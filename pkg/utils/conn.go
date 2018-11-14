package utils

import (
	"time"

	log "github.com/minjs/golog"
	goNet "github.com/shirou/gopsutil/net"

	serr "github.com/Zero-Systems/agent/pkg/err"
	"io"
	"os"
	"strconv"
)

func ElapseTimeFromStartForFunction(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Debugln("Timer for "+name+" took: ", elapsed)
}

func determinePidFromSourceIpOfCustomContiner(srcIp string) int32 {
	namespaceId := GetProcessIdInNetworkNamespaceWithIp(srcIp)
	log.Debugln("Determining pid using srcip "+srcIp+" of custom container, namespaceId: ", namespaceId)
	if namespaceId != "" {
		cpid, err := strconv.ParseInt(namespaceId, 10, 32)
		if err != nil {
			return 0
		}
		return int32(cpid)
	}

	return 0
}

func isConnectionForDockerContainerPid(pid int, srcip string, destPort uint32, kind string) (bool, bool) {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "isConnectionForDockerContainerPid")

	log.Debugln("isConnectionForDockerContainerPid pid, srcip, destPort, kind = ",
		strconv.Itoa(pid), srcip, strconv.Itoa(int(destPort)), kind)

	containerId := GetContainerIdWithPid(strconv.Itoa(pid))
	log.Debugln("isConnectionForDockerContainerPid containerId: ", containerId)

	port, proto := GetPortProtoForContainer(containerId)
	log.Debugln("isConnectionForDockerContainerPid port, proto : ", port, proto)

	if port == strconv.Itoa(int(destPort)) && proto == kind {
		return true, false
	}

	if containerId != "" {
		containerIp := GetIpAddressForContainer(containerId)
		log.Debugln("isConnectionForDockerContainerPid containerIp: ", containerIp)

		if containerIp == srcip {
			return false, true
		}
	}

	return false, false
}

func determinePidUsingPreroutingIptableRule(destPort uint32, kind string) int32 {
	log.Debugln("Determining pid using prerouting rule")
	pidUsingDport := GetProcessIdInNamespaceForDport(strconv.Itoa(int(destPort)), kind)
	log.Debugln("pidUsingDport: ", pidUsingDport)

	if pidUsingDport != "" {
		cpid, err := strconv.ParseInt(pidUsingDport, 10, 32)
		if err != nil || pidUsingDport == "" {
			return 0
		} else {
			return int32(cpid)
		}
	}

	return 0
}

func GetConnPid(kind string, pidList []int, srcIp string, srcPort uint32, destIp string, destPort uint32, localIp string, mode string) (int32, bool, error) {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "GetConnPid")

	for _, pid := range pidList {
		log.Debugln("Getting connstats for pid: ", pid)
		if connStats, err := goNet.ConnectionsPid(kind, int32(pid)); err != nil {
			log.Error("Error getting connstats for pid: ", pid)
			continue
		} else {
			containerType := GetContainerTypeProcessIsRunningIn(strconv.Itoa(int(pid)))
			log.Info("Got connstats for pid: ", pid, " containerType: " + containerType)

			if containerType == "" {
				log.Info("Determining connection for non containerized process")
				for _, connStat := range connStats {
					log.Info("ConnStat: ", connStat.String(), destIp, destPort)
					if kind == "tcp" {
						if (destIp == connStat.Laddr.IP || connStat.Laddr.IP == "::" || connStat.Laddr.IP == "0.0.0.0") && destPort == connStat.Laddr.Port && connStat.Pid != 0 {
							log.Info("Found tcp match pid with destip = laddr ip", connStat.Pid)
							return connStat.Pid, true, nil
						}
						if srcIp == connStat.Laddr.IP && srcPort == connStat.Laddr.Port {
							log.Info("Found tcp match pid with srcip = laddr ip", connStat.Pid)
							return connStat.Pid, false, nil
						}
					} else {
						if destPort == connStat.Laddr.Port {
							if destIp == localIp {
								log.Debugln("Found non tcp match pid with destport = laddrport, destip = laddrip", connStat.Pid)
								return connStat.Pid, true, nil
							} else {
								log.Debugln("Found non tcp match pid with destport = laddrport, destip != laddrip", connStat.Pid)
								return connStat.Pid, false, nil
							}
						}
						if srcPort == connStat.Laddr.Port {
							log.Debugln("Found non tcp match pid with srcport = laddrport", connStat.Pid)
							return connStat.Pid, false, nil
						}
					}
				}
			} else if containerType == "docker" {
				log.Debugln("Determining connection for docker container process")
				isDestPort, isSrcIp := isConnectionForDockerContainerPid(pid, srcIp, destPort, kind)
				if isDestPort == true {
					log.Debugln("Dest port/proto matched for docker container process")
					return int32(pid), true, nil
				} else if isSrcIp == true {
					log.Debugln("Source ip matched for docker container process")
					return int32(pid), false, nil
				}
			} else if containerType == "custom" {
				log.Debugln("Determining connection for custom container process")
				containerPID := determinePidUsingPreroutingIptableRule(destPort, kind)
				if containerPID != 0 {
					return containerPID, true, nil
				}

				containerPID = determinePidFromSourceIpOfCustomContiner(srcIp)
				log.Debugln("Return root pid of container if srcip is container ip", containerPID)
				if containerPID != 0 {
					return containerPID, false, nil
				}
			}
		}
	}
	log.Warnln("Does not find the Pid for the conn", srcIp, srcPort, destIp, destPort)
	return 0, false, serr.ErrNotFoundPid

}

func processes() ([]int, error) {
	d, err := os.Open("/proc")
	if err != nil {
		return nil, err
	}
	defer d.Close()

	results := []int{}
	for {
		fis, err := d.Readdir(10)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		for _, fi := range fis {
			// We only care about directories, since all pids are dirs
			if !fi.IsDir() {
				continue
			}
			name := fi.Name()
			if name[0] < '0' || name[0] > '9' {
				continue
			}
			pid, err := strconv.ParseInt(name, 10, 0)
			if err != nil {
				continue
			}
			results = append(results, int(pid))
		}
	}
	return results, nil
}
