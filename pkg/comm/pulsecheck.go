package comm

import (
	"encoding/json"
	"../config"
	"../utils"
	log "github.com/minjs/golog"
	"time"
)

type PulseCheckRequest struct {
	MessageHeader
	PulseCheckPayload `json:"payload"`
}

type PulseCheckPayload struct {
	MID           string `json:"mid"`
	Timestamp     int64  `json:"timestamp"`
	AgentUpTime   int64  `json:"agentUptime"`
	MachineUpTime string `json:"machineUptime"`
}

type PulseCheck struct {
	PulseCheckAckChan chan PulseCheckAckMsg
}

type PulseCheckAckMsg struct {
	MessageHeader
	ComponentList []string               `json:"componentList"`
	AgentMode     string                 `json:"secureMode"`
	ProtocolV     string                 `json:"protocolVersion"`
	Policy        config.WhiteListPolicy `json:"policy"`
}

func NewPulseCheck() *PulseCheck {
	ar := &PulseCheck{}
	WSComm.RegisterMsgReceiver(MessageTypePulseCheckAck, ar)
	ar.PulseCheckAckChan = make(chan PulseCheckAckMsg)
	return ar
}

func (r *PulseCheck) MsgReceive(ackMsg []byte) error {
	log.Debugln("Got pulse check ack msg", string(ackMsg))
	var pca PulseCheckAckMsg
	if err := json.Unmarshal(ackMsg, &pca); err != nil {
		log.Errorln("pulse check ack message unmarshal error", err, string(ackMsg))
		return err
	}

	r.PulseCheckAckChan <- pca
	return nil
}

func SendPulseCheck(ws *CommWS) {
	pulseCheckMessage := &PulseCheckRequest{
		MessageHeader: MessageHeader{
			MessageType: MessageTypePulseCheck,
		},
		PulseCheckPayload: PulseCheckPayload{
			MID:           config.MachineID,
			Timestamp:     utils.GetTimeStamp(),
			AgentUpTime:   int64(time.Since(AgentStartTime) / time.Second),
			MachineUpTime: utils.GetMachineUpTime(),
		},
	}

	dm, _ := json.Marshal(pulseCheckMessage)
	log.Debugln("Sending pulse check message", string(dm))
	ws.Send(pulseCheckMessage)
}

func (r *PulseCheck) AgentPulseCheck(ws *CommWS) {
	pcTicker := time.Tick(time.Duration(PulseCheckInterval) * time.Millisecond)

	for {
		select {
		case <-pcTicker:
			SendPulseCheck(ws)
		}
	}
}
