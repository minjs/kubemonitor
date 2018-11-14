package comm

//bigfoot
//Author - Min

import (
	"encoding/json"
	"../config"
	"../utils"
	log "github.com/minjs/golog"
	"sync"
	"time"
)

type ProcessInfo struct {
	Parent              string `json:"parent"`
	Child               string `json:"child"`
	Component           string `json:"component"`
	BinaryImage         string `json:"binaryImage"`
	Arguments           string `json:"arguments"`
	Container           string `json:"container"`
	ContainerRootPid    string `json:"containerRootPid"`
	ContainerNetNs      string `json:"containerNetNs"`
	ContainerPidNs      string `json:"containerPidNs"`
	ContainerId         string `json:"containerId"`
	ContainerImage      string `json:"containerImage"`
	ContainerIp         string `json:"containerIp"`
	ContainerPort       string `json:"containerPort"`
	ContainerPortProto  string `json:"containerPortProto"`
	ContainerHostIp     string `json:"containerHostIp"`
	ContainerHostPort   string `json:"containerHostPort"`
	ContainerCreateTime string `json:"containerCreateTime"`
	ContainerStartTime  string `json:"containerStartTime"`
	Uid                 int    `json:"uid"`
	Euid                int    `json:"euid"`
	Gid                 int    `json:"gid"`
	Egid                int    `json:"egid"`
	Username            string `json:"username"`
	Groupname           string `json:"groupname"`
	CID                 string `json:"Cid"`
	Type                string `json:"Type"`
	PsUniqKey
}

func (p ProcessInfo) String() string {
	js, _ := json.Marshal(p)
	return string(js)
}

type ConnInfo struct {
	Pid       int    `json:"pid"`
	Listening string `json:"listening"`
	ConnUniqKey
}

func (c ConnInfo) String() string {
	js, _ := json.Marshal(c)
	return string(js)
}

type ConnUniqKey struct {
	Proto    int    `json:"proto"`
	SrcIP    string `json:"srcIP"`
	SrcPort  int    `json:"srcPort"`
	DestIP   string `json:"destIP"`
	DestPort int    `json:"destPort"`
}

type PsUniqKey struct {
	Ppid int `json:"ppid"`
	Pid  int `json:"pid"`
}

type DiscoveryMessage struct {
	MID       string        `json:"mid"`
	Timestamp int64         `json:"timestamp"`
	Process   []ProcessInfo `json:"process"`
	Conn      []ConnInfo    `json:"conn"`
}

type DiscoveryMessageRequest struct {
	MessageHeader
	DiscoveryMessage `json:"payload"`
}

type Discovery struct {
	psListLock    sync.Mutex
	psEventList   []ProcessInfo
	connEventList []ConnInfo
	connListLock  sync.Mutex
	connMapLock   sync.Mutex
	ConnEventMap  map[ConnUniqKey]ConnInfo
	PSDiscChan    chan ProcessInfo
	ConnDiscChan  chan ConnInfo
}

func NewDiscovery() *Discovery {
	ar := &Discovery{
		psEventList:   []ProcessInfo{},
		ConnEventMap:  make(map[ConnUniqKey]ConnInfo),
		connEventList: []ConnInfo{},
		PSDiscChan:    make(chan ProcessInfo, DISCCHANLEN),
		ConnDiscChan:  make(chan ConnInfo, DISCCHANLEN),
	}
	WSComm.RegisterMsgReceiver(MessageTypeDiscoveryAck, ar)

	go ar.discEventRevRoutine()
	go ar.discEventSendRoutine()
	return ar
}

func (d *Discovery) MsgReceive(ackMsg []byte) error {
	log.Infoln("Got discovery ack msg", string(ackMsg))
	return nil
}

func Send2PSDiscChan(d *Discovery, event ProcessInfo) {
	if d == nil {
		log.Errorln("Please setup discovery module before setup watch watch")
		return
	}
	d.PSDiscChan <- event
}

func Send2ConnDiscChan(d *Discovery, event ConnInfo) {
	d.ConnDiscChan <- event
}

func (d *Discovery) discEventRevRoutine() {
	for {
		select {
		case psEvent := <-d.PSDiscChan:
			d.insertPSEvent(psEvent)

		case connEvent := <-d.ConnDiscChan:
			if d.connEventProcessPipeLine(&connEvent) {
				d.insertConnEvent(connEvent)
			}
		}
	}
}

func (d *Discovery) discEventSendRoutine() {
	discTicker := time.Tick(10 * time.Second)
	for {
		select {
		case <-discTicker:
			d.sendEvent2Controller()
		}
	}
}

func (d *Discovery) insertPSEvent(event ProcessInfo) {
	d.psListLock.Lock()
	defer d.psListLock.Unlock()
	d.psEventList = append(d.psEventList, event)
}

func (d *Discovery) connEventProcessPipeLine(event *ConnInfo) bool {
	return true
}

func (d *Discovery) insertConnEvent(event ConnInfo) {
	d.connListLock.Lock()
	defer d.connListLock.Unlock()
	d.connEventList = append(d.connEventList, event)
}

func (d *Discovery) sendEvent2Controller() {
	// collect ps events
	d.psListLock.Lock()
	psEvents := d.psEventList
	//set psevent list empty
	d.psEventList = []ProcessInfo{}
	d.psListLock.Unlock()

	// collect conn events
	d.connListLock.Lock()
	connEvents := d.connEventList
	d.connEventList = []ConnInfo{}
	d.connListLock.Unlock()

	if len(psEvents) > 0 || len(connEvents) > 0 {
		SendDiscoveryMessage(WSComm, psEvents, dedupConnEvent(connEvents))
	}
}

func (d *Discovery) RootComponentDiscovery() {

}

func dedupPsEvent(psEventList []ProcessInfo) []ProcessInfo {
	psMap := make(map[PsUniqKey]bool)
	procList := []ProcessInfo{}
	for _, process := range psEventList {
		if _, ok := psMap[process.PsUniqKey]; !ok {
			procList = append(procList, process)
			psMap[process.PsUniqKey] = true
		}
	}
	return procList
}

func dedupConnEvent(connEventList []ConnInfo) []ConnInfo {
	connMap := make(map[ConnUniqKey]bool)
	connList := []ConnInfo{}
	for _, conn := range connEventList {
		if _, ok := connMap[conn.ConnUniqKey]; !ok {
			connList = append(connList, conn)
			connMap[conn.ConnUniqKey] = true
		}
	}
	return connList
}

func SendDiscoveryMessage(ws *CommWS, process []ProcessInfo, connInfo []ConnInfo) {
	discoverMessage := &DiscoveryMessageRequest{
		MessageHeader: MessageHeader{
			MessageType: MessageTypeDiscovery,
		},
		DiscoveryMessage: DiscoveryMessage{
			MID:       config.MachineID,
			Timestamp: utils.GetTimeStamp(),
			Process:   process,
			Conn:      connInfo,
		},
	}
	dm, _ := json.Marshal(discoverMessage)
	log.Debugln("Sending discovery message", string(dm))
	ws.Send(discoverMessage)
}
