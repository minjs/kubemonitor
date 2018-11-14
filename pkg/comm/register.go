package comm

import (
	"encoding/json"

	log "github.com/minjs/golog"

	"github.com/Zero-Systems/agent/pkg/config"
	"github.com/Zero-Systems/agent/pkg/err"
	"github.com/Zero-Systems/agent/pkg/utils"
	goNet "github.com/shirou/gopsutil/net"
	"strings"
)

var (
	IntfName = "eth0"
)

type RegisterMessagePayload struct {
	Hostname   string `json:"hostName"`
	IPAddress  string `json:"ipAddress"`
	MacAddress string `json:"macAddress"`
	CommoNaame string `json:"commonName"`
}

type RegisterMessage struct {
	MessageHeader
	RegisterMessagePayload `json:"payload"`
}

type RegisterAckMessagePayload struct {
	MID    string                 `json:"mid"`
	Config map[string]interface{} `json:"config"`
}

type RegisterAckMessage struct {
	MessageHeader
	RegisterAckMessagePayload
}

type AgentRegister struct {
}

func NewAgentRegister() *AgentRegister {
	ar := &AgentRegister{}
	WSComm.RegisterMsgReceiver(MessageTypeRegisterAck, ar)
	return ar
}

func (r *AgentRegister) MsgReceive(ackMsg []byte) error {
	var regAck RegisterAckMessage
	if err := json.Unmarshal(ackMsg, &regAck); err != nil {
		log.Errorln("Json unmarshal error", string(ackMsg), err)
		return err
	}
	if regAck.MessageType != MessageTypeRegisterAck {
		log.Errorln("Get wrong type message", regAck.MessageType)
		return err.ErrWrongType
	}
	config.MachineID = regAck.MID
	config := regAck.Config
	if ipci, ok := config[PulseCheckIntvKey].(float64); ok {
		PulseCheckInterval = int(ipci)
	}

	log.Debugln("Got machine id and config ", regAck.MID, PulseCheckInterval)
	//write MachineID to a file

	return nil
}

func (r *AgentRegister) AgentRegister(ws *CommWS) {
	var hostname string
	ipAddr := "UNKNOWN"
	macAddr := "UNKNOWN"
	if lines, err := utils.ExecCmd("hostname"); err != nil || len(lines) < 1 {
		log.Errorln("Could not run hostname cmd")
		return
	} else {
		hostname = lines[0]
	}

	if intfs, err := goNet.Interfaces(); err != nil {
		log.Errorln("get interface error", err)
		return
	} else {
		for _, intf := range intfs {
			if intf.Name == IntfName {
				ips := strings.Split(intf.Addrs[0].Addr, "/")
				ipAddr = ips[0]
				macAddr = intf.HardwareAddr
				break
			}
		}
	}

	config.LocalIp = ipAddr

	sendRegister(ws, hostname, ipAddr, macAddr, "Zero-systems")
}

func sendRegister(ws *CommWS, hostname string, ipaddress string, macaddress string, commonname string) {
	registerMessage := &RegisterMessage{
		MessageHeader: MessageHeader{
			MessageType: MessageTypeRegister,
		},
		RegisterMessagePayload: RegisterMessagePayload{
			Hostname:   hostname,
			IPAddress:  ipaddress,
			MacAddress: macaddress,
			CommoNaame: commonname,
		},
	}
	dm, _ := json.Marshal(registerMessage)
	log.Debugln("Sending register message", string(dm))
	ws.Send(registerMessage)
}
