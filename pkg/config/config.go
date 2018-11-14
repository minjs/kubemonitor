package config

const (
	AgentModeDisc    = "discovery"
	AgentModeMonitor = "monitor"
	AgentModeEnforce = "enforce"
)

var (
	AgentMode     = ""
	MachineID     = ""
	machineIdFile = "/etc/agent/mid"
	LocalIp       = ""
)
