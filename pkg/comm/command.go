package comm

import (
	"encoding/json"

	log "github.com/minjs/golog"

	"github.com/minjs/kubemonitor/pkg/config"
	"github.com/minjs/kubemonitor/pkg/err"
	"github.com/minjs/kubemonitor/pkg/utils"
)

type CommandPayload struct {
	MID          string                 `json:"mid"`
	Command      string                 `json:"command"`
	ParameterMap map[string]interface{} `json:"parameters"`
}

type PushCommandMessage struct {
	MessageHeader
	CommandPayload
}

type cmdProcInterface interface {
	cmdProcess(parameters map[string]interface{})
}

type Commands struct {
	cmdMap map[string]cmdProcInterface
}

type DetainCmd struct {
}

var PushCommands *Commands

const (
	DetainCommand = "detainCommand"
)

func PushCommandRegister() *Commands {
	cr := &Commands{
		cmdMap: make(map[string]cmdProcInterface),
	}
	WSComm.RegisterMsgReceiver(MessageTypePushCommand, cr)
	detainCMD := newDetainCmd()
	RegisterDetainCmd(cr, detainCMD)
	return cr
}

func (c *Commands) MsgReceive(ackMsg []byte) error {
	var command PushCommandMessage
	if err := json.Unmarshal(ackMsg, &command); err != nil {
		log.Errorln("Json unmarshal error", string(ackMsg), err)
		return err
	}
	if command.MessageType != MessageTypePushCommand {
		log.Errorln("Get wrong type message", command.MessageType)
		return err.ErrWrongType
	}
	log.Info("Got push command from controller, ", command.CommandPayload.MID, command.CommandPayload.Command)

	if command.CommandPayload.MID != config.MachineID {
		log.Info("The command is for another machine", command.CommandPayload.MID)
		return nil
	}

	return c.ProcessCommand(command.CommandPayload.Command, command.CommandPayload.ParameterMap)
}

func (c *Commands) ProcessCommand(cmd string, parameters map[string]interface{}) error {
	if cmdfunc, ok := c.cmdMap[cmd]; ok {
		cmdfunc.cmdProcess(parameters)
		return nil
	}
	log.Error("Cmd is not exist", cmd)
	return err.ErrCmdNotExist
}

func RegisterCmdProcess(c *Commands, cmd string, process cmdProcInterface) {
	c.cmdMap[cmd] = process
}

func newDetainCmd() *DetainCmd {
	return &DetainCmd{}
}

func (d *DetainCmd) cmdProcess(parameters map[string]interface{}) {
	//find pidlist
	if config.AgentMode != config.AgentModeMonitor {
		log.Info("try to detain in non monitor mode", config.AgentMode)
		return
	}
	log.Info("parameters is ", parameters)
	if pidList, ok := parameters["pidList"]; ok {
		if pids, ok := pidList.([]interface{}); ok {
			for _, pid := range pids {
				log.Info("detaining container for pid", pid)
				res := utils.SeparateContainerNetwork(int(pid.(float64)))
				if !res {
					log.Error("detain network failed", pid)
				}
				notData := make(map[int]bool)
				notData[int(pid.(float64))] = res
				SendNotificationMsg(WSComm, ComponentDetainType, notData)
			}
		} else {
			log.Error("pidList has wrong type, not []int")
		}
	} else {
		log.Error("pidList does not exist in detainCommand parameters", parameters)
	}
}

func RegisterDetainCmd(c *Commands, d *DetainCmd) {
	RegisterCmdProcess(c, DetainCommand, d)
}
