package pswatch

//bigfoot
//Author - Min

import (
	"../comm"
	"../pswatch/psnotify"
	"../service"
	"../utils"
	log "github.com/minjs/golog"
	"os"
	"strconv"
	"strings"
)

type Pps struct {
	ppid int
	pstr string
}


type PsWatcher struct {
	psWatcher  *psnotify.Watcher
	pids       []int
	watchEvent uint32
	ParentMap  map[int]Pps
}

func NewPsWatcher(pids []int, watchEvent uint32) (*PsWatcher, error) {
	watcher, err := psnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &PsWatcher{
		psWatcher:  watcher,
		pids:       pids,
		watchEvent: watchEvent,
		ParentMap:  make(map[int]Pps),
	}, nil
}

func (p *PsWatcher) Close() {
	p.psWatcher.Close()
}

func (p *PsWatcher) Watch() error {
	for _, pid := range p.pids {
		err := p.psWatcher.Watch(pid, p.watchEvent)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *PsWatcher) Receive() {
	for {
		select {
		case ev := <-p.psWatcher.Fork:
			p.PasePsEvent(ev)
		case ev := <-p.psWatcher.Exec:
			p.PasePsEvent(ev)
		case ev := <-p.psWatcher.Exit:
			p.PasePsEvent(ev)
		case err := <-p.psWatcher.Error:
			log.Infoln("error:", err)
		}
	}
}

func (p *PsWatcher) PasePsEvent(event interface{}) {
	switch event := event.(type) {
	case *psnotify.ProcEventFork:
		log.Debugln("fork event: ", event.ParentPid, event.ChildPid)
		pstr, _ := findPsName(event.ParentPid)
		if pstr == "" {
			log.Errorln("Parent pid has no name", event.ParentPid)
			return
		}
		//cstr, _ := findPsName(event.ChildPid)
		proc, err := utils.GetProcessInfo(event.ChildPid)
		if err != nil {
			p.ParentMap[event.ChildPid] = Pps{
				ppid: event.ParentPid,
				pstr: pstr,
			}
			return
		}

		cstr := proc.Cmdline
		//do not process empty child, bash from bash
		if cstr != "" && cstr != pstr && cstr != "bash" {
			go sendProcessEvent(pstr, cstr, event.ParentPid, event.ChildPid, proc)
		} else {
			p.ParentMap[event.ChildPid] = Pps{
				ppid: event.ParentPid,
				pstr: pstr,
			}
		}
		log.Debugln("fork event with process name: ", event.ParentPid, event.ChildPid, pstr, cstr)
	case *psnotify.ProcEventExec:
		//cstr, _ := findPsName(event.Pid)
		proc, err := utils.GetProcessInfo(event.Pid)
		if err != nil {
			//log.Infoln("Can not find the /proc/", event.Pid)
			return
		}
		cstr := proc.Cmdline
		if cstr != "" {
			if pps, ok := p.ParentMap[event.Pid]; ok {
				go sendProcessEvent(pps.pstr, cstr, pps.ppid, event.Pid, proc)
			} else {
				log.Debugln("Can not find parent for process", cstr)
			}
		}
		log.Debugln("exec event: ", cstr)
	case *psnotify.ProcEventExit:
		pps := p.ParentMap[event.Pid]
		go sendProcessEvent(pps.pstr, "exitEvent", pps.ppid, event.Pid, &utils.Process{})
		delete(p.ParentMap, event.Pid)
		log.Debugln("exit event: ", event.Pid)
	default:
		log.Errorln("Invalid event type")
	}
}

func findPsName(pid int) (string, error) {
	pidstr := strconv.Itoa(pid)
	linkname := "/proc/" + pidstr + "/exe"
	return os.Readlink(linkname)
}

func sendProcessEvent(parent string, child string, ppid, cpid int, proc *utils.Process) error {
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

		if container == utils.DOCKER_CONTAINER {
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
		}
	}

	psEvent := comm.ProcessInfo{
		Component:           utils.CheckComponent(cpid, service.AgentService.GetCmpList(), child),
		Parent:              parent,
		Child:               child,
		BinaryImage:         binary,
		Arguments:           arguments,
		Uid:                 proc.Uid,
		Euid:                proc.Euid,
		Gid:                 proc.Gid,
		Egid:                proc.Egid,
		Username:            proc.Username,
		Groupname:           proc.Groupname,
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
	log.Debugln("sending process event to service channel")
	service.AgentService.SendPSEvent2Service(psEvent)
	//comm.Send2PSDiscChan(comm.WSComm.Disc, psEvent)
	return nil
}
