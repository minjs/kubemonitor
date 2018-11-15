package comm

import (
	"encoding/json"
	"github.com/minjs/kubemonitor/pkg/comm/wsclient"
	log "github.com/minjs/golog"
	"time"
)

type MessageHeader struct {
	MessageType string `json:"messageType"`
}

type revMesg struct {
	MessageHeader
}

type MsgReceiver interface {
	MsgReceive(msg []byte) error
}

const (
	RECEIVERCHANLEN          = 1000
	DISCCHANLEN              = 100
	MessageAlert             = "alert"
	MessageTypePulseCheck    = "pulse-check"
	MessageTypeRegister      = "register"
	MessageTypeDiscovery     = "discovery"
	MessageTypeRegisterAck   = "register-ack"
	MessageTypePulseCheckAck = "pulse-check-ack"
	MessageTypeDiscoveryAck  = "discovery-ack"
	PulseCheckIntvKey        = "pulseCheckInterval"
	MessageTypePushCommand   = "pushCommand"
	MessageTypeNotification  = "agent-notification"
	ComponentReDisc          = "compReDisc"

	//notification
	ComponentDetainType = "ComponentDetainStatus"
)

var (
	PulseCheckInterval = 5000
	AgentStartTime     time.Time
)

var WSComm *CommWS

type CommWS struct {
	Server        string
	TLS           bool
	ServerCA      string
	ClientAuth    bool
	ClientCert    string
	ClientKey     string
	IsSelfSigned  bool
	Disc          *Discovery
	WebSocketConn *wsclient.WSConn
	SenderChan    chan interface{}
	ReceiverChan  chan []byte
	StopChan      chan int
	ErrChan       chan int
	MsgMap        map[string]MsgReceiver
}

func NewCommWS(server string, tlsEnable bool, serverCA string, clientAuth bool, clientCert string, clientKey string, isSelfSigned bool) *CommWS {
	return &CommWS{
		Server:       server,
		TLS:          tlsEnable,
		ServerCA:     serverCA,
		ClientAuth:   clientAuth,
		ClientCert:   clientCert,
		ClientKey:    clientKey,
		IsSelfSigned: isSelfSigned,
	}
}

func (c *CommWS) Setup() {
	c.SenderChan = make(chan interface{})
	c.ReceiverChan = make(chan []byte, RECEIVERCHANLEN)
	c.StopChan = make(chan int)
	c.ErrChan = make(chan int)
	c.MsgMap = make(map[string]MsgReceiver)

	c.SetupConn()

	go c.Receive()
	go c.ErrHandler()
}

func (c *CommWS) SetupConn() {
	c.WebSocketConn = wsclient.NewWSConn()
	log.Infoln("Setup comm")
	for {
		if err := c.WebSocketConn.Open(c.Server, c.TLS, c.ServerCA, c.ClientAuth, c.ClientCert, c.ClientKey, c.IsSelfSigned); err == nil {
			break
		} else {
			log.Infoln("Open connection to web socket server failed, retrying...")
			time.Sleep(5 * time.Second)
		}
	}
	go c.WebSocketConn.SendRoutine(c.SenderChan, c.StopChan, c.ErrChan)
	go c.WebSocketConn.ReceiveRoutine(c.ReceiverChan, c.ErrChan)
}

func (c *CommWS) ErrHandler() {
	for {
		<-c.ErrChan
		c.SetupConn()
	}
}

func (c *CommWS) RegisterMsgReceiver(msgType string, receiver MsgReceiver) {
	c.MsgMap[msgType] = receiver
}

func (c *CommWS) CleanUp() {
	// send stop message to stop chanel
	c.StopChan <- 0
	c.WebSocketConn.Close()
}

func (c *CommWS) Send(v interface{}) {
	c.SenderChan <- v
}

func (c *CommWS) MsgReceive(ackMsg []byte) error {
	log.Infoln(string(ackMsg))
	return nil
}

func (c *CommWS) Receive() {
	for {
		select {
		case recMsg := <-c.ReceiverChan:
			var msg revMesg
			if err := json.Unmarshal(recMsg, &msg); err != nil {
				log.Errorln("Json unmarshal error", string(recMsg), err)
			} else {
				if recv, ok := c.MsgMap[msg.MessageHeader.MessageType]; ok {
					log.Debugln("get message type", msg.MessageHeader.MessageType)
					go recv.MsgReceive(recMsg)

				} else {
					log.Debugln("The handler for this message type is not registered, go to default handler")
					c.MsgReceive(recMsg)
				}
			}
		}
	}
}
