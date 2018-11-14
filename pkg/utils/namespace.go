package utils

import (
	"os/exec"
	"strconv"

	"bufio"
	"errors"
	log "github.com/minjs/golog"
	"syscall"
)

func SwitchBetweenNameSpace(CmpMap map[int]string, toNS bool) (map[int]string, []string) {
	newPidsMap := make(map[int]string)
	movedCmps := []string{}

	for pid, component := range CmpMap {
		if CheckIfProcessExists(pid) {
			pidstr := strconv.Itoa(pid)
			if ppid, err := GetParentPid(int32(pid)); err == nil {
				if _, exists := CmpMap[int(ppid)]; exists {
					continue
				}
			}
			if !CheckIfProcessIsContainerized(pidstr) && toNS {
				log.Infoln("Moving process with pid " + pidstr + " & component " + component + " to it's separate namespace.")
				cmd := exec.Command("/usr/bin/zero_agent/ns.sh", "-p", pidstr, "-c", component)

				cmd.SysProcAttr = &syscall.SysProcAttr{
					Setpgid: true,
					Pgid:    0,
				}

				stdout, err := cmd.StdoutPipe()
				if err != nil {
					log.Errorln("Not able to setup stdout pipe for the command, err: ")
					log.Errorln(err)
					return newPidsMap, nil
				}
				if err := cmd.Start(); err != nil {
					log.Errorln("Error executing the command, err:")
					log.Errorln(err)
					return newPidsMap, nil
				}
				in := bufio.NewScanner(stdout)
				output := ""
				for in.Scan() {
					output += in.Text()
				}

				log.Infoln("Moved process with pid " + pidstr + " & component " + component + " to it's separate namespace with pid " + string(output))
				if output != "" {
					i64, err := strconv.ParseInt(output, 10, 64)
					if err != nil {
						continue
					}
					newPidsMap[int(i64)] = component
				}
			} else if !toNS && CheckIfProcessIsContainerized(pidstr) {
				log.Infoln("Moving component " + component + " to out of namespace.")
				cmd := exec.Command("/usr/bin/zero_agent/ns.sh", "-d", component)
				_, err := cmd.StdoutPipe()
				if err != nil {
					log.Errorln("Error for open stdout", err)
					return nil, movedCmps
				}
				if err := cmd.Run(); err != nil {
					log.Errorln("Error executing the command, err:", err)
					return nil, movedCmps
				} else {
					movedCmps = append(movedCmps, component)
				}
			}
		}
	}
	if toNS {
		return newPidsMap, nil
	} else {
		log.Info("Moved the components out of namespace", movedCmps)
		return nil, movedCmps
	}
}

func RestartComponentInNS(component string) (int, error) {
	cmd := exec.Command("/usr/bin/zero_agent/ns.sh", "-S", component)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorln("Not able to setup stdout pipe for the command, err: ")
		log.Errorln(err)
		return 0, err
	}
	if err := cmd.Run(); err != nil {
		log.Errorln("Error executing the command, err:")
		log.Errorln(err)
		return 0, err
	}
	in := bufio.NewScanner(stdout)
	output := ""
	for in.Scan() {
		output += in.Text()
	}
	if output != "" {
		i64, err := strconv.ParseInt(output, 10, 64)
		if err != nil {
			return 0, err
		}
		return int(i64), nil
	} else {
		return 0, errors.New("no output")
	}
}
