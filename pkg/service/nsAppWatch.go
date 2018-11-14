package service

import (
	"encoding/json"
	"io/ioutil"
	"time"

	"github.com/Zero-Systems/agent/pkg/config"
	"github.com/Zero-Systems/agent/pkg/utils"

	log "github.com/minjs/golog"
)

var (
	CompMonitorFile = "/opt/zsAgent/monitoring.json"
	EnableMonitor   = true
)

type compMonitor struct {
	AgentMode string
	CmpMap    map[int]string
	Policy    config.WhiteListPolicy
}

func MonitoringModeWatch() {
	MonitorInterval := 2000
	pcTicker := time.Tick(time.Duration(MonitorInterval) * time.Millisecond)
	for {
		select {
		case <-pcTicker:
			if EnableMonitor && (config.AgentMode == config.AgentModeMonitor || config.AgentMode == config.AgentModeEnforce) {
				//write component map to a file
				SaveComponentToFile()
				checkComponentRunning()
			}
		}
	}
}

func checkComponentRunning() {
	compOkMap := make(map[string]bool)
	for pid, component := range AgentService.CmpMap {
		if ppid, err := utils.GetParentPid(int32(pid)); err == nil {
			if _, exists := AgentService.CmpMap[int(ppid)]; exists {
				continue
			}
		}
		if utils.CheckIfProcessExists(pid) {
			compOkMap[component] = true
		} else {
			if _, ok := compOkMap[component]; !ok {
				compOkMap[component] = false
			}
		}
	}

	for comp,ok := range compOkMap {
		if !ok {
			if restarted_pid, err := utils.RestartComponentInNS(comp); err == nil {
				log.Info("Restarted component in ns", comp)
				AgentService.Add2CmpPidMap(restarted_pid, comp)
				if policy, ok := AgentService.Policy.WhiteLists[comp]; ok {
					cid := policy.CID
					AgentService.SendNameSpaceInitialDisc(restarted_pid, cid, comp)
				} else {
					log.Error("Component is not in whitelist", AgentService.Policy.WhiteLists, comp)
				}
			} else {
				log.Error("Restart component failed in ns", err)
			}
		}
	}
}

func SaveComponentToFile() {
	saveJson, _ := json.Marshal(compMonitor{
		AgentMode: config.AgentMode,
		CmpMap:    AgentService.CmpMap,
		Policy:    AgentService.Policy,

	})
	if err := ioutil.WriteFile(CompMonitorFile, saveJson, 0644); err != nil {
		log.Error("Write to monitor file error", err)
	}
}

func MonitorEnforceRecover() {
	compMon := compMonitor{
		AgentMode: "",
		CmpMap:    make(map[int]string),
	}
	if cm, err := ioutil.ReadFile(CompMonitorFile); err == nil {
		if erru := json.Unmarshal(cm, &compMon); erru == nil {
			config.AgentMode = compMon.AgentMode
			for k, v := range compMon.CmpMap {
				AgentService.CmpMap[k] = v
			}
			AgentService.Policy = compMon.Policy
		} else {
			log.Error("json unmarshal error", erru)
		}
	} else {
		log.Error("Read compMonitorFile error", err)
	}
}
