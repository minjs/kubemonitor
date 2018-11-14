package comm

import (
	"encoding/json"
	"github.com/Zero-Systems/agent/pkg/config"
	"github.com/Zero-Systems/agent/pkg/utils"
	log "github.com/minjs/golog"
)

type NotificationMsg struct {
	MessageHeader
	Payload NotificationPayload `json:"payload"`
}

type NotificationPayload struct {
	MID              string      `json:"mid"`
	Timestamp        int64       `json:"timestamp"`
	NotificationType string      `json:"type"`
	NotificationData interface{} `json:"data"`
}

func SendNotificationMsg(ws *CommWS, nType string, nMsg interface{}) {
	notificationMessage := &NotificationMsg{
		MessageHeader: MessageHeader{
			MessageType: MessageTypeNotification,
		},
		Payload: NotificationPayload{
			MID:              config.MachineID,
			Timestamp:        utils.GetTimeStamp(),
			NotificationType: nType,
			NotificationData: nMsg,
		},
	}

	dm, _ := json.Marshal(notificationMessage)
	log.Debugln("Sending notification message", string(dm))
	ws.Send(notificationMessage)
}
