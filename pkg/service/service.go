package service

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/minjs/golog"

	"os/user"

	"../comm"
	"../config"
	"../err"
	"../utils"
)

const (
	STRINGWC       = "*"
	INTWC          = -1
	CONNCHANLEN    = 1000
	PROCESSCHANLEN = 100
)

var (
	AgentService *agentService
	gcTicker     = time.Tick(60 * time.Second)
)

type ipPort struct {
	proto    int
	destIp   string
	destPort int
}

type pidCompName struct {
	pid     int
	cmpName string
	listen  string
}

type agentService struct {
	CmpList           []string
	CmpListLock       sync.Mutex
	ConnPidMap        map[ipPort]pidCompName
	ConnPidMapLock    sync.RWMutex
	CmpMap            map[int]string // key is pid, value is component name
	CmpMapLock        sync.Mutex
	Policy            config.WhiteListPolicy
	PolicyLock        sync.RWMutex
	PSEventChan       chan comm.ProcessInfo
	ConnEventChan     chan comm.ConnInfo
	PcaChan           chan comm.PulseCheckAckMsg
	alertsEnabled     bool
	alertsEnabledLock sync.Mutex
}

func NewAgentService(pcaChan chan comm.PulseCheckAckMsg) *agentService {
	AService := &agentService{
		CmpList:           []string{},
		CmpListLock:       sync.Mutex{},
		CmpMap:            make(map[int]string),
		CmpMapLock:        sync.Mutex{},
		Policy:            config.WhiteListPolicy{},
		PolicyLock:        sync.RWMutex{},
		PSEventChan:       make(chan comm.ProcessInfo, PROCESSCHANLEN),
		ConnEventChan:     make(chan comm.ConnInfo, CONNCHANLEN),
		PcaChan:           pcaChan,
		alertsEnabled:     true,
		alertsEnabledLock: sync.Mutex{},
		ConnPidMap:        make(map[ipPort]pidCompName),
		ConnPidMapLock:    sync.RWMutex{},
	}
	go AService.processEvent()
	go AService.gcCmpMap()
	return AService
}

func (as *agentService) gcCmpMap() {
	for {
		select {
		case <-gcTicker:
			log.Debugln("CmpMap gc start...")
			as.CmpMapLock.Lock()
			for pid, _ := range as.CmpMap {
				if _, err := os.Stat("/proc/" + strconv.Itoa(pid) + ""); os.IsNotExist(err) {
					log.Debugln("Process is not exist, removing form cmpMap", strconv.Itoa(pid))
					delete(as.CmpMap, pid)
				}
			}
			as.CmpMapLock.Unlock()
		}
	}
}

func (as *agentService) updateComponentList(componentList []string) {
	chg, adl, _ := listCompare(as.GetCmpList(), componentList)
	if chg && len(adl) != 0 && len(componentList) != 0 {
		// find component info and send to controller
		// update service map
		log.Debugln("New components from controller", adl)
		as.AddComponentList(adl)
		log.Debugln("Added components from controller", adl)
	}
	log.Debugln("New component list is", as.CmpList)
}

func (as *agentService) isAlertsEnabled() bool {
	as.alertsEnabledLock.Lock()
	defer as.alertsEnabledLock.Unlock()

	return as.alertsEnabled
}

func (as *agentService) disableAlerts() {
	as.alertsEnabledLock.Lock()
	defer as.alertsEnabledLock.Unlock()

	as.alertsEnabled = false
}

func (as *agentService) enableAlerts() {
	as.alertsEnabledLock.Lock()
	defer as.alertsEnabledLock.Unlock()

	as.alertsEnabled = true
}

func doesIpBelongToNetwork(cidr string, ip string) bool {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Debugln("Invalid CIDR.")
		return false
	}
	return network.Contains(net.ParseIP(ip))
}

func (as *agentService) AddComponentList(cmpList []string) {
	if len(cmpList) > 0 {
		as.CmpListLock.Lock()
		defer as.CmpListLock.Unlock()

		as.Add2CmpList(cmpList)
		log.Debugln("AddComponentList", cmpList)
		if pNodeMap, err := utils.GetComponents(cmpList); err == nil && len(pNodeMap) != 0 {
			for cn, node := range pNodeMap {
				as.AddNodeTree2ComponentMap(cn, node)
			}
			as.SendNewCompDisc(pNodeMap)
		} else {
			log.Errorln("GetComponents error", err)
		}

		log.Debugln("Added to ComponentList", cmpList)
	}
}

func (as *agentService) AddNodeTree2ComponentMap(cn string, n *utils.PSNode) {
	as.Add2CmpPidMap(n.Pid, cn)
	if n.Children == nil || len(n.Children) == 0 {
		return
	}
	for _, c := range n.Children {
		log.Debugln("add to component map for each child", c, cn)
		as.AddNodeTree2ComponentMap(cn, &c)
	}
}

func (as *agentService) SendNewCompDisc(m map[string]*utils.PSNode) {
	for cn, node := range m {

		ppid, err := utils.GetParentPid(int32(node.Pid))
		if err != nil {
			ppid = 0
		}

		//send component
		log.Debugln("Sending component and children to discover chanel", cn)
		as.Send2Disc(cn, "", node.Ps.Cmdline, int(ppid), node.Pid, node.Ps.Uid, node.Ps.Euid, node.Ps.Gid, node.Ps.Egid)
		log.Debugln("Sent component to discover chanel", cn)
		as.Send2DiscByNode(node, "")
		log.Debugln("Sent children to discover chanel", cn)
	}
}

func (as *agentService) Send2Disc(component, parent, child string, ppid, cpid, uid, euid, gid, egid int) {
	containerNetNs, containerPidNs, containerId, containerImage := "", "", "", ""
	containerPortProto, containerHostIp, containerCreateTime, containerStartTime := "", "", "", ""
	containerIp, containerPort, containerHostPort, containerRootPid := "", "", "", ""

	bl := strings.Fields(child)
	binary := bl[0]
	arguments := ""
	if len(bl) > 1 {
		arguments = strings.Join(bl[1:], " ")
	}

	// Get container info & add to processInfo
	container := utils.GetContainerTypeProcessIsRunningIn(strconv.Itoa(cpid))
	log.Debugln("pid: " + strconv.Itoa(cpid) + ", running in container type: " + container)

	if container != "" {
		containerNetNs = utils.GetNetworkNamespaceInodeForProcess(strconv.Itoa(cpid))
		containerPidNs = utils.GetPidNamespaceInodeForProcess(strconv.Itoa(cpid))

		if container == "docker" {
			containerId = utils.GetContainerIdWithPid(strconv.Itoa(cpid))
			containerRootPid = utils.GetPidForProcessInContainer(containerId)
			containerImage = utils.GetImageForContainer(containerId)
			containerIp = utils.GetIpAddressForContainer(containerId)
			containerPort = utils.GetPortForContainer(containerId)
			containerPortProto = utils.GetProtoForContainer(containerId)
			containerHostIp = utils.GetHostIpForContainer(containerId)
			containerHostPort = utils.GetHostPortForContainer(containerId)
			containerCreateTime = utils.GetCreationTimeForContainer(containerId)
			containerStartTime = utils.GetStartTimeForContainer(containerId)
		} else if container == "custom" {
			containerId = utils.GetNetworkNamespaceNameForPid(strconv.Itoa(cpid))
			containerIp = utils.GetContainerIpAddressForContainerFromPid(strconv.Itoa(cpid))
			containerPort = utils.GetOpenPortForProcessInsideNamespace(strconv.Itoa(cpid))
			containerPortProto = utils.GetOpenPortProtoForProcessInsideNamespace(strconv.Itoa(cpid))
			containerHostIp = utils.GetHostIpAddressForContainerFromPid(strconv.Itoa(cpid))
			containerHostPort = utils.GetHostPortForContainerizedProcess(strconv.Itoa(cpid))
		}
	}

	//get username and group name from uid and gid
	username := ""
	if user, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		username = user.Username
	}
	groupname := ""
	if group, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		groupname = group.Name
	}

	psEvent := comm.ProcessInfo{
		Component:           component,
		Parent:              parent,
		Child:               child,
		BinaryImage:         binary,
		Arguments:           arguments,
		Uid:                 uid,
		Euid:                euid,
		Gid:                 gid,
		Egid:                egid,
		Username:            username,
		Groupname:           groupname,
		Container:           container,
		ContainerRootPid:    containerRootPid,
		ContainerNetNs:      containerNetNs,
		ContainerPidNs:      containerPidNs,
		ContainerId:         containerId,
		ContainerImage:      containerImage,
		ContainerIp:         containerIp,
		ContainerPort:       containerPort,
		ContainerPortProto:  containerPortProto,
		ContainerHostIp:     containerHostIp,
		ContainerHostPort:   containerHostPort,
		ContainerCreateTime: containerCreateTime,
		ContainerStartTime:  containerStartTime,
		PsUniqKey: comm.PsUniqKey{
			Ppid: ppid,
			Pid:  cpid,
		},
	}
	log.Debugln("send to service psEvent chanel", psEvent)
	go as.SendPSEvent2Service(psEvent)
}

func (as *agentService) Send2DiscByNode(n *utils.PSNode, cn string) {
	xx := n
	if xx.Children != nil && len(xx.Children) > 0 {
		for _, c := range xx.Children {
			log.Debugln("Sending component children node recursively for each child")
			as.Send2Disc(cn, xx.Ps.Name, c.Ps.Cmdline, xx.Pid, c.Pid, c.Ps.Uid, c.Ps.Euid, c.Ps.Gid, c.Ps.Egid)
			as.Send2DiscByNode(&c, cn)
		}
	}
}

func (as *agentService) processEvent() {
	log.Debugln("Starting service routine... ")
	for {
		select {
		case psEvent := <-as.PSEventChan:
			log.Debugln("Processing ps event: ", psEvent)
			if psEvent.Component != "" {
				//fork event for component, indicating a component restart
				log.Debugln("fork event for component, indicating a component restart", psEvent)
				as.Add2CmpPidMap(psEvent.Pid, psEvent.Component)
			}
			as.LookupAndAdd2CmpMap(psEvent.Ppid, psEvent.Pid)
			if config.AgentMode == config.AgentModeDisc {
				//psEvent.Component = utils.CheckComponent(psEvent.Pid, as.GetCmpList())
				log.Debugln("service processEvent routine, get ps event and sending to comm discover chanel")
				comm.Send2PSDiscChan(comm.WSComm.Disc, psEvent)
			} else {
				// validation
				if psEvent.BinaryImage != "exitEvent" {
					if match, cid := as.ValidateProcess(psEvent.Parent, psEvent.BinaryImage, psEvent.Arguments, psEvent.Ppid, psEvent.Pid); !match {
						log.Infof("Validation failed for parent process %s, child process %s, arguments %s, ppid %d, pid %d", psEvent.Parent, psEvent.BinaryImage, psEvent.Arguments, psEvent.Ppid, psEvent.Pid)
						log.Debugln("isAlertsEnabled: ", as.isAlertsEnabled())
						if as.isAlertsEnabled() {
							comm.SendAlert(comm.WSComm, "process", psEvent, comm.ConnInfo{}, cid)
						}
					}
				}
			}
			log.Debugln("Processing ps event done: ", psEvent)
		case connEvent := <-as.ConnEventChan:
			log.Infoln("current channel lenth", len(as.ConnEventChan))
			go as.ProcessConnEvent(connEvent)
		case pulseCheckAck := <-as.PcaChan:
			log.Debugln("Processing pulsecheck ack", pulseCheckAck)
			as.processPCA(pulseCheckAck)
		}
	}
}

func (as *agentService) ProcessConnEvent(connEvent comm.ConnInfo) {
	if err := as.findMatchPid(&connEvent); err != nil {
		log.Debugln("Can not find match pid", connEvent)
	} else {
		log.Debugln("found match pid", connEvent)
		if config.AgentMode == config.AgentModeDisc {
			comm.Send2ConnDiscChan(comm.WSComm.Disc, connEvent)
		} else {
			// validation
			if match, cid := as.ValidateConn(connEvent.Pid, connEvent.SrcIP, connEvent.DestIP, connEvent.SrcPort, connEvent.DestPort, connEvent.Proto); !match {
				log.Infof("Validation failed for conn", connEvent)
				if as.isAlertsEnabled() {
					comm.SendAlert(comm.WSComm, "conn", comm.ProcessInfo{}, connEvent, cid)
				}
				if config.AgentMode == config.AgentModeEnforce {
					// put the container in separated network mode
					result := utils.SeparateContainerNetwork(connEvent.Pid)
					if !result {
						log.Error("detain network failed", connEvent.Pid)
					}
					notData := make(map[int]bool)
					notData[connEvent.Pid] = result
					comm.SendNotificationMsg(comm.WSComm, comm.ComponentDetainType, notData)
				}
			}
		}
	}
}

func (as *agentService) delayedEnableMonitor() {
	time.Sleep(120 * time.Second)
	EnableMonitor = true
}

func (as *agentService) processPCA(pcaMsg comm.PulseCheckAckMsg) error {
	switching, oldMode, err := SwitchMode(pcaMsg.AgentMode)
	if err != nil {
		return err
	}
	as.updateComponentList(pcaMsg.ComponentList)
	as.updatePolicy(pcaMsg.Policy)
	if switching {
		EnableMonitor = false
		if oldMode == config.AgentModeDisc &&
			(pcaMsg.AgentMode == config.AgentModeMonitor || pcaMsg.AgentMode == config.AgentModeEnforce) {
			log.Info("Switching to monitoring mode, sandboxing component & disabling alerts")
			log.Debugln("isAlertsEnabled: ", as.isAlertsEnabled())
			as.disableAlerts()
			log.Debugln("isAlertsEnabled: ", as.isAlertsEnabled())
			newPidsMap, _ := utils.SwitchBetweenNameSpace(as.CmpMap, true)
			as.enableAlerts()
			log.Debugln("isAlertsEnabled: ", as.isAlertsEnabled())
			log.Info("Sandboxed component & enabled alerts", newPidsMap)
			for _, component := range newPidsMap {
				as.RemoveFromCmpList(component)
			}
			for pid, component := range newPidsMap {
				as.UpdatePidAfterNameSpacing(pid, component, pcaMsg)
			}
		} else if pcaMsg.AgentMode == config.AgentModeDisc &&
			(oldMode == config.AgentModeMonitor || oldMode == config.AgentModeEnforce) {
			_, cmpList := utils.SwitchBetweenNameSpace(as.CmpMap, false)
			for _, component := range cmpList {
				as.RemoveFromCmpList(component)
			}
			as.AddComponentList(cmpList)
		}
		SaveComponentToFile()
		go as.delayedEnableMonitor()
	}
	return nil
}

func (as *agentService) UpdatePidAfterNameSpacing(pid int, component string, pcaMsg comm.PulseCheckAckMsg) {
	as.Add2CmpPidMap(pid, component)
	if policy, ok := pcaMsg.Policy.WhiteLists[component]; ok {
		cid := policy.CID
		as.SendNameSpaceInitialDisc(pid, cid, component)
	}
	if cpids, err := utils.GetChildrenPID(int32(pid)); err == nil && cpids != nil && len(cpids) != 0 {
		for _, cpid := range cpids {
			as.UpdatePidAfterNameSpacing(int(cpid), component, pcaMsg)
		}
	}
}

func (as *agentService) SendNameSpaceInitialDisc(pid int, cid, component string) {
	psEvent := as.CollectNameSpaceProcessInfo(pid, cid, component)
	log.Debugln("Sending initial process discovery message after moving to namespace")
	comm.Send2PSDiscChan(comm.WSComm.Disc, psEvent)
}

func (as *agentService) CollectNameSpaceProcessInfo(pid int, cid, component string) comm.ProcessInfo {
	containerNetNs, containerPidNs, containerId := "", "", ""
	containerPortProto, containerHostIp := "", ""
	containerIp, containerPort, containerHostPort := "", "", ""

	// Get container info & add to processInfo
	container := utils.GetContainerTypeProcessIsRunningIn(strconv.Itoa(pid))
	log.Debugln("pid: " + strconv.Itoa(pid) + ", running in container type: " + container)

	if container != "" {
		containerNetNs = utils.GetNetworkNamespaceInodeForProcess(strconv.Itoa(pid))
		containerPidNs = utils.GetPidNamespaceInodeForProcess(strconv.Itoa(pid))

		if container == "custom" {
			containerId = utils.GetNetworkNamespaceNameForPid(strconv.Itoa(pid))
			containerIp = utils.GetContainerIpAddressForContainerFromPid(strconv.Itoa(pid))
			containerPort = utils.GetOpenPortForProcessInsideNamespace(strconv.Itoa(pid))
			containerPortProto = utils.GetOpenPortProtoForProcessInsideNamespace(strconv.Itoa(pid))
			containerHostIp = utils.GetHostIpAddressForContainerFromPid(strconv.Itoa(pid))
			containerHostPort = utils.GetHostPortForContainerizedProcess(strconv.Itoa(pid))
		}
	}

	ppid, err := utils.GetParentPid(int32(pid))
	if err != nil {
		ppid = 0
	}

	parentName := ""
	childName := ""
	binary := ""
	arguments := ""
	uid := 0
	euid := 0
	gid := 0
	egid := 0
	userName := ""
	groupName := ""

	if pProc, err := utils.GetProcessInfo(int(ppid)); err == nil {
		parentName = pProc.Cmdline
	}
	if cProc, err := utils.GetProcessInfo(pid); err == nil {
		childName = cProc.Cmdline
		uid = cProc.Uid
		euid = cProc.Euid
		gid = cProc.Gid
		egid = cProc.Egid
		userName = cProc.Username
		groupName = cProc.Groupname
	}
	fields := strings.Fields(childName)
	if len(fields) > 1 {
		arguments = fields[1]
		binary = fields[0]
	} else if len(fields) > 0 {
		binary = fields[0]
	}

	return comm.ProcessInfo{
		Component:          component,
		CID:                cid,
		Parent:             parentName,
		Child:              childName,
		BinaryImage:        binary,
		Arguments:          arguments,
		Uid:                uid,
		Euid:               euid,
		Gid:                gid,
		Egid:               egid,
		Username:           userName,
		Groupname:          groupName,
		Type:               "componentUpdate",
		Container:          container,
		ContainerNetNs:     containerNetNs,
		ContainerPidNs:     containerPidNs,
		ContainerId:        containerId,
		ContainerIp:        containerIp,
		ContainerPort:      containerPort,
		ContainerPortProto: containerPortProto,
		ContainerHostIp:    containerHostIp,
		ContainerHostPort:  containerHostPort,
		PsUniqKey: comm.PsUniqKey{
			Ppid: int(ppid),
			Pid:  pid,
		},
	}
}

func (as *agentService) SendPSEvent2Service(psEvent comm.ProcessInfo) {
	as.PSEventChan <- psEvent
}

func (as *agentService) SendConnEvent2Service(connEvent comm.ConnInfo) {
	log.Debugln("Sending to connEvent channel: ", connEvent)
	as.ConnEventChan <- connEvent
	log.Debugln("Sent to connEvent channel: ", connEvent)
}

func (as *agentService) findMatchPid(event *comm.ConnInfo) error {
	var kind string
	if event.Proto == 6 {
		kind = "tcp"
	} else if event.Proto == 17 {
		kind = "udp"
	} else if event.Proto == 1 {
		event.Pid = event.SrcPort
		event.SrcPort = 0
		event.Listening = "false"
		return nil
	} else {
		log.Errorln("protocol is not tcp/udp/icmp", event.Proto)
		return nil
	}

	IpPortKey := ipPort{
		proto:    event.Proto,
		destIp:   event.DestIP,
		destPort: event.DestPort,
	}
	as.ConnPidMapLock.RLock()
	if inPidName, ok := as.ConnPidMap[IpPortKey]; ok {
		if validatePidWithName(inPidName.pid, inPidName.cmpName) {
			event.Pid = inPidName.pid
			event.Listening = inPidName.listen
			as.ConnPidMapLock.RUnlock()
			return nil
		}
	}
	as.ConnPidMapLock.RUnlock()

	CmpPidList := []int{}
	for pid := range as.CmpMap {
		CmpPidList = append(CmpPidList, pid)
	}

	if pid, listen, err := utils.GetConnPid(kind, CmpPidList, event.SrcIP, uint32(event.SrcPort), event.DestIP, uint32(event.DestPort), config.LocalIp, config.AgentMode); err != nil {
		return err
	} else {
		event.Pid = int(pid)

		if listen {
			event.Listening = "true"
		} else {
			event.Listening = "false"
		}

		IPKey := ipPort{
			proto:    event.Proto,
			destIp:   event.DestIP,
			destPort: event.DestPort,
		}
		cn, ce := findCmpName(int(pid))
		if ce == nil {
			pn := pidCompName{
				pid:     int(pid),
				cmpName: cn,
				listen:  event.Listening,
			}
			as.ConnPidMapLock.Lock()
			as.ConnPidMap[IPKey] = pn
			as.ConnPidMapLock.Unlock()
		} else {
			log.Errorln("can not find the process name from pid", pid, ce)
		}
	}
	return nil
}

func (as *agentService) UpdateCmpList(newList []string) {
	as.CmpList = newList
}

func (as *agentService) Add2CmpList(newList []string) {
	as.CmpList = append(as.CmpList, newList...)
}

func (as *agentService) RemoveFromCmpList(cmp string) {
	for i, v := range as.CmpList {
		if v == cmp {
			as.CmpList = append(as.CmpList[:i], as.CmpList[i+1:]...)
			return
		}
	}
}

func (as *agentService) GetCmpList() []string {
	return as.CmpList
}

func (as *agentService) updatePolicy(policy config.WhiteListPolicy) {
	as.PolicyLock.Lock()
	defer as.PolicyLock.Unlock()
	//if as.Policy.Version != policy.Version {
	as.Policy = policy
	//}
}

func (as *agentService) ValidateProcess(ppn, pn, arguments string, ppid, pid int) (bool, string) {
	// match component name
	if cn, found := as.LookupComponent(ppid); !found {
		// not found meaning pass
		return true, ""
	} else {
		return as.MatchProcessPolicy(cn, pn, arguments)
	}
}

func (as *agentService) ValidateConn(pid int, srcIP, destIP string, srcPort, destPort, proto int) (bool, string) {
	if cn, found := as.LookupComponent(pid); !found {
		log.Debugln("not belong to a component")
		return true, ""
	} else {
		return as.MatchConnPolicy(cn, srcIP, destIP, srcPort, destPort, proto)
	}
}

func (as *agentService) MatchProcessPolicy(cmpName, pn, arguments string) (bool, string) {
	as.PolicyLock.RLock()
	defer as.PolicyLock.RUnlock()

	cmpWL := as.Policy.WhiteLists[cmpName]
	procList := cmpWL.Process
	processJson, _ := json.Marshal(procList)
	log.Debugln("current process white list", cmpName, string(processJson))
	for _, proc := range procList {
		if (proc.BinaryImage == STRINGWC || processMatch(proc.BinaryImage, pn)) && (proc.Arguments == STRINGWC || processMatch(proc.Arguments, arguments)) {
			return true, ""
		}
	}
	return false, cmpWL.CID
}

func (as *agentService) MatchConnPolicy(cmpName string, srcIP, destIP string, srcPort, destPort, proto int) (bool, string) {
	as.PolicyLock.RLock()
	defer as.PolicyLock.RUnlock()

	cmpWL := as.Policy.WhiteLists[cmpName]
	connList := cmpWL.Conn
	log.Debugln("Matching conn policy", cmpName, srcIP, destIP, srcPort, destPort, proto)
	for _, conn := range connList {
		if (conn.SrcPort == INTWC || conn.SrcPort == srcPort) &&
			(conn.DestPort == INTWC || conn.DestPort == destPort) &&
			(conn.Proto == INTWC || conn.Proto == proto) &&
			(conn.SrcIP == STRINGWC || conn.SrcIP == srcIP || doesIpBelongToNetwork(srcIP, conn.SrcIP)) &&
			(conn.DestIP == STRINGWC || conn.DestIP == destIP || doesIpBelongToNetwork(destIP, conn.DestIP)) {
			log.Debugln("matched conn policy", conn.SrcIP, conn.DestIP, conn.SrcPort, conn.DestPort, conn.Proto)
			return true, ""
		}
	}
	return false, cmpWL.CID
}

func (as *agentService) LookupComponent(pid int) (string, bool) {
	as.CmpMapLock.Lock()
	defer as.CmpMapLock.Unlock()

	if cn, ok := as.CmpMap[pid]; ok {
		return cn, true
	}
	return "", false
}

func (as *agentService) LookupAndAdd2CmpMap(ppid, pid int) (string, bool) {
	as.CmpMapLock.Lock()
	defer as.CmpMapLock.Unlock()

	msi, _ := json.Marshal(as.CmpMap)
	log.Debugln("service -- current map", string(msi))
	if cn, ok := as.CmpMap[ppid]; ok {
		as.CmpMap[pid] = cn
		log.Infoln("Parent blong to component", ppid, pid, cn)
		return cn, true
	}
	return "", false
}

func (as *agentService) Add2CmpPidMap(cpid int, cmpname string) {
	as.CmpMapLock.Lock()
	defer as.CmpMapLock.Unlock()

	as.CmpMap[cpid] = cmpname
	log.Infoln("Add component to map", cpid, cmpname)
}

func (as *agentService) RemoveFromCmpPidMap(cpid int, cmpname string) {
	as.CmpMapLock.Lock()
	defer as.CmpMapLock.Unlock()

	delete(as.CmpMap, cpid)
	log.Infoln("Removed component from map", cpid, cmpname)
}

func processMatch(pa, pb string) bool {
	if strings.ToUpper(pa) == strings.ToUpper(pb) {
		return true
	}
	return false
}

func listCompare(lo []string, ln []string) (bool, []string, []string) {
	added := []string{}
	rem := []string{}
	for _, n := range ln {
		nc := true
		for _, o := range lo {
			if n == o {
				nc = false
				break
			}
		}
		if nc {
			added = append(added, n)
		}
	}

	for _, o := range lo {
		rc := true
		for _, n := range ln {
			if n == o {
				rc = false
				break
			}
		}
		if rc {
			rem = append(rem, o)
		}
	}
	if len(added) == 0 && len(rem) == 0 {
		return false, added, rem
	} else {
		return true, added, rem
	}
}

func SwitchMode(newMode string) (bool, string, error) {
	modeChanging := false
	if newMode != config.AgentModeDisc && newMode != config.AgentModeMonitor && newMode != config.AgentModeEnforce {
		log.Errorln("the agent mode in pulse-check-ack from controller is wrong", newMode)
		return modeChanging, config.AgentMode, err.ErrWrongMode
	}
	oldMode := config.AgentMode
	if newMode != config.AgentMode {
		config.AgentMode = newMode
		modeChanging = true
	}
	return modeChanging, oldMode, nil
}

func validatePidWithName(pid int, name string) bool {
	filename := "/proc/" + strconv.Itoa(pid) + "/cmdline"
	if lines, err := utils.ReadFile(filename); err != nil || len(lines) < 1 {
		return false
	} else {
		return name == lines[0]
	}
}

func findCmpName(pid int) (string, error) {
	filename := "/proc/" + strconv.Itoa(pid) + "/cmdline"
	if lines, err := utils.ReadFile(filename); err != nil {
		return "", err
	} else {
		return lines[0], nil
	}
}
