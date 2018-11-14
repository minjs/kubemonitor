package comm

import (
	"encoding/json"

	log "github.com/minjs/golog"

	"github.com/Zero-Systems/agent/pkg/config"
)

type AlertMessage struct {
	MessageHeader
	AlertMessagePayload `json:"payload"`
}

type AlertMessagePayload struct {
	AlertType  string      `json:"alertType"`
	MID        string      `json:"mid"`
	CID        string      `json:"cid"`
	PsInfo     ProcessInfo `json:"psInfo"`
	ConnInfo   ConnInfo    `json:"connInfo"`
	SecureMode string      `json:"secureMode"`
}

func SendAlert(ws *CommWS, alertType string, processInfo ProcessInfo, connInfo ConnInfo, cid string) {
	alertMsg := &AlertMessage{
		MessageHeader: MessageHeader{
			MessageType: MessageAlert,
		},
		AlertMessagePayload: AlertMessagePayload{
			MID:        config.MachineID,
			CID:        cid,
			AlertType:  alertType,
			PsInfo:     processInfo,
			ConnInfo:   connInfo,
			SecureMode: config.AgentMode,
		},
	}
	dm, _ := json.Marshal(alertMsg)
	log.Debugln("Sending alert message", string(dm))
	ws.Send(alertMsg)
}
