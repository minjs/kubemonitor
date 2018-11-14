// bigfoot
// author - min@

package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	log "github.com/minjs/golog"
)

func getListOfDockerContainers() string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getListOfDockerContainers")

	output, error := exec.Command("docker", "ps", "-q").Output()
	if error != nil {
		return ""
	}
	return string(output)
}

func getDockerInspectForFormat(containerId string, format string) string {
	if containerId == "" || format == "" {
		return ""
	}
	output, error := exec.Command("docker", "inspect", "--format='{{json ."+format+"}}", containerId).Output()
	if error != nil {
		return ""
	}
	return strings.Replace(string(output), "'", "", -1)
}

func getDockerInspectOutputForFormatString(containerId string, format string) string {
	if containerId == "" || format == "" {
		return ""
	}
	output, error := exec.Command("docker", "inspect", "--format="+format, containerId).Output()
	if error != nil {
		return ""
	}
	return strings.TrimSuffix(string(output), "\n")
}

func getFieldFromDockerInspectForFormat(containerId string, format string, field string) string {
	var data map[string]interface{}
	inspectOutput := getDockerInspectForFormat(containerId, format)

	if inspectOutput != "" {
		err := json.Unmarshal([]byte(inspectOutput), &data)
		if err != nil {
			return ""
		}
		if field != "" {
			return fmt.Sprintf("%v", data[field])
		} else {
			return fmt.Sprintf("%v", data)
		}
	} else {
		return ""
	}
}

func GetPidForProcessInContainer(containerId string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "GetPidForProcessInContainer")

	return getFieldFromDockerInspectForFormat(containerId, "State", "Pid")
}

func GetIpAddressForContainer(containerId string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "GetIpAddressForContainer")

	return getFieldFromDockerInspectForFormat(containerId, "NetworkSettings", "IPAddress")
}

func getPortsNetworkSettingForContainer(containerId string, field string) string {
	return getFieldFromDockerInspectForFormat(containerId, "NetworkSettings.Ports", field)
}

func parseDockerProxyProcessParameters(processID string) (string, string, string, string, string) {
	var proto, hostIp, hostPort, containerIp, containerPort string = "", "", "", "", ""

	filePath := "/proc/" + processID + "/cmdline"
	buffer, error := ioutil.ReadFile(filePath)
	if error != nil {
		return "", "", "", "", ""
	}
	params := strings.Split(string(buffer), "-")
	for index := range params {
		if strings.Contains(params[index], "proto") {
			proto = strings.TrimPrefix(params[index], "proto")
		} else if strings.Contains(params[index], "host") {
			if strings.Contains(params[index+1], "ip") {
				hostIp = strings.TrimPrefix(params[index+1], "ip")
			} else if strings.Contains(params[index+1], "port") {
				hostPort = strings.TrimPrefix(params[index+1], "port")
			}
		} else if strings.Contains(params[index], "container") {
			if strings.Contains(params[index+1], "ip") {
				containerIp = strings.TrimPrefix(params[index+1], "ip")
			} else if strings.Contains(params[index+1], "port") {
				containerPort = strings.TrimPrefix(params[index+1], "port")
			}
		}
	}

	return proto, hostIp, hostPort, containerIp, containerPort
}

func checkProxyProcessIdIsForContinerId(proxyProcessID string, containerID string) bool {
	dockerContainerIp := GetIpAddressForContainer(containerID)

	_, _, _, containerIp, _ := parseDockerProxyProcessParameters(proxyProcessID)

	return strings.Contains(containerIp, dockerContainerIp)
}

func getContainerIdFromProxyProcessId(proxyProcessID string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getContainerIdFromProxyProcessId")

	scanner := bufio.NewScanner(strings.NewReader(getListOfDockerContainers()))
	for scanner.Scan() {
		containerID := scanner.Text()
		if checkProxyProcessIdIsForContinerId(proxyProcessID, containerID) {
			return containerID
		}
	}
	return ""
}

func getListOfDockerIpChainRulesFromCommand() string {
	output, error := exec.Command("iptables", "-t", "nat", "-S", "DOCKER").Output()
	if error != nil {
		return ""
	}
	return string(output)
}

func parseDockerIptableDnatPortForwardingRule(rule string) (string, string, string) {
	var proto, dport, toIp string = "", "", ""

	if strings.Contains(rule, "dport") && strings.Contains(rule, "to-destination") {
		params := strings.Split(rule, " ")
		for index := range params {
			if strings.Contains(params[index], "-p") {
				proto = params[index+1]
			} else if strings.Contains(params[index], "-dport") {
				dport = params[index+1]
			} else if strings.Contains(params[index], "--to-destination") {
				toIp = strings.Split(params[index+1], ":")[0]
			}
		}
	}

	return proto, dport, toIp
}

func getIpTableRuleContainingDestinationPort(dport string, kind string) string {
	scanner := bufio.NewScanner(strings.NewReader(getListOfDockerIpChainRulesFromCommand()))
	for scanner.Scan() {
		rule := scanner.Text()
		proto, iptableDPort, _ := parseDockerIptableDnatPortForwardingRule(rule)
		if proto == kind && iptableDPort == dport {
			return rule
		}
	}

	return ""
}

func checkContainerIdToDestinationforIp(containerID string, Ip string) bool {
	dockerContainerIp := GetIpAddressForContainer(containerID)
	if dockerContainerIp == Ip {
		return true
	}

	return false
}

func getContainerIdFromDport(dport string, kind string) string {
	rule := getIpTableRuleContainingDestinationPort(dport, kind)
	if rule != "" {
		_, _, toIp := parseDockerIptableDnatPortForwardingRule(rule)

		scanner := bufio.NewScanner(strings.NewReader(getListOfDockerContainers()))
		for scanner.Scan() {
			containerID := scanner.Text()
			if checkContainerIdToDestinationforIp(containerID, toIp) {
				return containerID
			}
		}
	}
	return ""
}

func getProcessIdInContainerForDport(dport string, kind string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getProcessIdInContainerForDport")

	return GetPidForProcessInContainer(getContainerIdFromDport(dport, kind))
}

func getContainerIdWithIp(ipAddress string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getContainerIdWithIp")

	scanner := bufio.NewScanner(strings.NewReader(getListOfDockerContainers()))
	for scanner.Scan() {
		containerID := scanner.Text()
		if GetIpAddressForContainer(containerID) == ipAddress {
			return containerID
		}
	}
	return ""
}

func getProcessIdInContainerWithIp(ipAddress string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getProcessIdInContainerWithIp")

	containerID := getContainerIdWithIp(ipAddress)
	if containerID != "" {
		return GetPidForProcessInContainer(containerID)
	}
	return ""
}

func checkIfProcessInContainer(containerId string, pid string) bool {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "checkIfProcessInContainer")

	rootPid := GetPidForProcessInContainer(containerId)
	if GetNamespaceInodeForProcess(pid, "pid") == GetNamespaceInodeForProcess(rootPid, "pid") &&
		GetNamespaceInodeForProcess(pid, "net") == GetNamespaceInodeForProcess(rootPid, "net") {
		return true
	}
	return false
}

func GetContainerIdWithPid(pid string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "GetContainerIdWithPid")

	scanner := bufio.NewScanner(strings.NewReader(getListOfDockerContainers()))
	for scanner.Scan() {
		containerID := scanner.Text()
		if checkIfProcessInContainer(containerID, pid) {
			return containerID
		}
	}
	return ""
}

func getPortProtoForContainer(containerId string) string {
	return getDockerInspectOutputForFormatString(containerId,
		"{{range $p, $conf := .NetworkSettings.Ports}}{{$p}}{{end}}")
}

func GetPortProtoForContainer(containerId string) (string, string) {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "GetPortProtoForContainer")

	portProto := getPortProtoForContainer(containerId)
	if portProto != "" {
		return strings.Split(portProto, "/")[0], strings.Split(portProto, "/")[1]
	}
	return "", ""
}

func GetPortForContainer(containerId string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "GetPortForContainer")

	portProto := getPortProtoForContainer(containerId)
	if portProto != "" {
		return strings.Split(portProto, "/")[0]
	}
	return ""
}

func GetProtoForContainer(containerId string) string {
	portProto := getPortProtoForContainer(containerId)
	if portProto != "" {
		return strings.Split(portProto, "/")[1]
	}
	return ""
}

func getContainerNetwork(containerID string) string {
	return getDockerInspectOutputForFormatString(containerID,
		"{{range $p, $conf := .NetworkSettings.Networks}}{{$p}}{{end}}")
}

func DisconnectNetwork(containerID string) {
	networkName := getContainerNetwork(containerID)
	if networkName == "" {
		networkName = "bridge"
	}
	cmd := "docker network disconnect -f " + networkName + " " + containerID
	ExecCmd(cmd)
}

func GetHostIpForContainer(containerId string) string {
	return getDockerInspectOutputForFormatString(containerId,
		"{{range $p, $conf := .NetworkSettings.Ports}}{{(index $conf 0).HostIp}}{{end}}")
}

func GetHostPortForContainer(containerId string) string {
	return getDockerInspectOutputForFormatString(containerId,
		"{{range $p, $conf := .NetworkSettings.Ports}}{{(index $conf 0).HostPort}}{{end}}")
}

func GetImageForContainer(containerId string) string {
	return getDockerInspectOutputForFormatString(containerId,
		"{{.Config.Image}}")
}

func GetCreationTimeForContainer(containerId string) string {
	return getDockerInspectOutputForFormatString(containerId,
		"{{.Created}}")
}

func GetStartTimeForContainer(containerId string) string {
	return getDockerInspectOutputForFormatString(containerId,
		"{{.State.StartedAt}}")
}

func runCommandOnSystem(command string) string {
	output, error := exec.Command("/bin/sh", "-c", command).Output()
	if error != nil {
		return ""
	}

	return string(output)
}

func execCommandInNetworkNamespace(namespace string, command string) string {

	output, error := exec.Command("/bin/sh", "-c", "ip netns exec "+namespace+" "+command).Output()
	if error != nil {
		return ""
	}

	return string(output)
}

func getNetworkNamespaceNameIdMap() map[string]string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getNetworkNamespaceNameIdMap")

	idNameMap := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(runCommandOnSystem("ip netns")))

	for scanner.Scan() {
		line := scanner.Text()
		split := strings.Split(line, " ")
		if len(split) > 1 && strings.Contains(split[2], ")") {
			idNameMap[split[0]] = strings.Split(split[2], ")")[0]
		}
	}

	return idNameMap
}

func getNetworkNamespaceIdInterfaceMap() map[string]string {
	idIfMap := map[string]string{}

	ifaces, err := net.Interfaces()
	if err != nil {
		return idIfMap
	}

	for _, intf := range ifaces {
		scanner := bufio.NewScanner(strings.NewReader(runCommandOnSystem("ip link list " + intf.Name)))

		for scanner.Scan() {
			line := scanner.Text()
			split := strings.Split(line, " ")
			for index := range split {
				if strings.Contains(split[index], "link-netnsid") {
					id := split[index+1]
					idIfMap[id] = intf.Name
				}
			}
		}
	}

	return idIfMap
}

func getNetworkInterfaceNameIpMap() map[string]string {
	intNameIpMap := map[string]string{}

	ifaces, err := net.Interfaces()
	if err != nil {
		return intNameIpMap
	}

	for _, intf := range ifaces {
		addrs, err := intf.Addrs()
		if err != nil {
			continue
		}

		// addrs list example: [10.200.2.1/24 fe80::f8b4:a6ff:feaf:49ce/64]
		if len(addrs) > 0 && strings.Contains(addrs[0].String(), "/") {
			intNameIpMap[intf.Name] = strings.Split(addrs[0].String(), "/")[0]
		}
	}

	return intNameIpMap
}

func getNetworkInterfaceOfNamespace(namespace string) string {

	scanner := bufio.NewScanner(strings.NewReader(execCommandInNetworkNamespace(namespace, "ip link")))

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "mtu") && strings.Contains(line, "qlen") {
			if !strings.Contains(line, "lo:") {
				split := strings.Split(line, " ")
				if len(split) > 1 && strings.Contains(split[1], "@") {
					return strings.Split(split[1], "@")[0]
				}
			}
		}
	}

	return ""
}

func getNetworkIpForNamespace(namespace string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getNetworkIpForNamespace")

	intf := getNetworkInterfaceOfNamespace(namespace)

	scanner := bufio.NewScanner(strings.NewReader(execCommandInNetworkNamespace(namespace, "ip addr show "+intf)))

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "inet") {
			split := strings.Split(line, " ")
			for index := range split {
				if strings.Contains(split[index], "inet") {
					return strings.Split(split[index+1], "/")[0]
				}
			}
		}
	}
	return ""
}

func GetNetworkNamespaceNameForPid(pid string) string {
	return strings.TrimSpace(runCommandOnSystem("ip netns identify " + pid))
}

func GetHostIpAddressForContainerFromPid(pid string) string {
	netns := GetNetworkNamespaceNameForPid(pid)
	intNameIpMap := getNetworkInterfaceNameIpMap()
	netnsNameIdMap := getNetworkNamespaceNameIdMap()
	netnsIdIntMap := getNetworkNamespaceIdInterfaceMap()

	if id, ok := netnsNameIdMap[netns]; ok {
		if intf, ok := netnsIdIntMap[id]; ok {
			if ip, ok := intNameIpMap[intf]; ok {
				return ip
			}
		}
	}

	return ""
}

func getHostNetworkInterfaceNameFromPidInNamespace(pid string) string {
	netns := GetNetworkNamespaceNameForPid(pid)
	log.Debugln("getHostNetworkInterfaceNameFromPidInNamespace, netns: " + netns)
	netnsIdIntMap := getNetworkNamespaceIdInterfaceMap()
	netnsNameIdMap := getNetworkNamespaceNameIdMap()

	if id, ok := netnsNameIdMap[netns]; ok {
		log.Debugln("getHostNetworkInterfaceNameFromPidInNamespace, id: " + id)
		if intf, ok := netnsIdIntMap[id]; ok {
			log.Debugln("getHostNetworkInterfaceNameFromPidInNamespace, intf: " + intf)
			return intf
		}
	}

	return ""
}

func DisconnectHostNetworkFromPidInNamespace(pid string) {
	intf := getHostNetworkInterfaceNameFromPidInNamespace(pid)

	if intf != "" {
		log.Debugln("Deleting host network from Pid in custom container" + intf)
		runCommandOnSystem("ip link del dev " + intf)
	}
}

func GetContainerIpAddressForContainerFromPid(pid string) string {
	return getNetworkIpForNamespace(GetNetworkNamespaceNameForPid(pid))
}

func GetOpenPortForProcessInsideNamespace(pid string) string {
	namespace := GetNetworkNamespaceNameForPid(pid)
	scanner := bufio.NewScanner(strings.NewReader(execCommandInNetworkNamespace(namespace, "ss -l -p -n")))

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, pid) {
			split := regexp.MustCompile("[^\\s]+").FindAllString(line, -1)
			if len(split) > 3 && strings.Contains(split[4], ":") {
				return strings.Split(split[4], ":")[1]
			}
		}
	}

	return ""
}

func GetOpenPortProtoForProcessInsideNamespace(pid string) string {
	namespace := GetNetworkNamespaceNameForPid(pid)
	scanner := bufio.NewScanner(strings.NewReader(execCommandInNetworkNamespace(namespace, "ss -l -p -n")))

	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, pid) {
			split := regexp.MustCompile("[^\\s]+").FindAllString(line, -1)
			return split[0]
		}
	}

	return ""
}

func GetHostPortForContainerizedProcess(pid string) string {
	containerIp := GetContainerIpAddressForContainerFromPid(pid)
	containerPort := GetOpenPortForProcessInsideNamespace(pid)
	containerPortProto := GetOpenPortProtoForProcessInsideNamespace(pid)

	iptableRules := runCommandOnSystem("iptables -t nat -S")
	containerDest := containerIp + ":" + containerPort

	if strings.Contains(iptableRules, "PREROUTING") && strings.Contains(iptableRules, "dport") &&
		strings.Contains(iptableRules, "to-destination") && strings.Contains(iptableRules, containerDest) &&
		strings.Contains(iptableRules, containerPortProto) {
		params := strings.Split(iptableRules, " ")
		for index := range params {
			if strings.Contains(params[index], "-dport") {
				return params[index+1]
			}
		}
	}

	return ""
}

func getNetworkNamespaceFromIp(ip string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getNetworkNamespaceFromIp")

	namespaceNameIdMap := getNetworkNamespaceNameIdMap()

	for namespace := range namespaceNameIdMap {
		if getNetworkIpForNamespace(namespace) == ip {
			return namespace
		}
	}

	return ""
}

func getPidMatchingSupportedComponentInNamespace(namespace string) string {
	scanner := bufio.NewScanner(strings.NewReader(runCommandOnSystem("ip netns pid " + namespace)))

	for scanner.Scan() {
		pid := scanner.Text()

		if CheckForSupportedProcess(pid, "") != "" {
			return pid
		}
	}

	return ""
}

func getListOfPreroutingIpTableRulesFromCommand() string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getListOfPreroutingIpTableRulesFromCommand")

	output, error := exec.Command("iptables", "-t", "nat", "-S", "PREROUTING").Output()
	if error != nil {
		return ""
	}
	return string(output)
}

func parsePreroutingIptablePortForwardingRule(rule string) (string, string, string) {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "parsePreroutingIptablePortForwardingRule")

	var proto, dport, toIp string = "", "", ""

	if strings.Contains(rule, "dport") && strings.Contains(rule, "to-destination") {
		params := strings.Split(rule, " ")
		for index := range params {
			if strings.Contains(params[index], "-p") {
				proto = params[index+1]
			} else if strings.Contains(params[index], "-dport") {
				dport = params[index+1]
			} else if strings.Contains(params[index], "--to-destination") {
				toIp = strings.Split(params[index+1], ":")[0]
			}
		}
	}

	return proto, dport, toIp
}

func getPreroutingIpTableRuleContainingDestinationPort(dport string, kind string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getPreroutingIpTableRuleContainingDestinationPort")

	scanner := bufio.NewScanner(strings.NewReader(getListOfPreroutingIpTableRulesFromCommand()))
	for scanner.Scan() {
		rule := scanner.Text()
		proto, iptableDPort, _ := parsePreroutingIptablePortForwardingRule(rule)
		if proto == kind && iptableDPort == dport {
			return rule
		}
	}

	return ""
}

func getNetworkNamespaceNameFromDport(dport string, kind string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "getNetworkNamespaceNameFromDport")

	rule := getPreroutingIpTableRuleContainingDestinationPort(dport, kind)
	log.Debugln("Rule in getNetworkNamespaceNameFromDport: ", rule)
	if rule != "" {
		_, _, toIp := parsePreroutingIptablePortForwardingRule(rule)
		if toIp != "" {
			return getNetworkNamespaceFromIp(toIp)
		}
	}
	return ""
}

func GetProcessIdInNamespaceForDport(dport string, kind string) string {
	ns := getNetworkNamespaceNameFromDport(dport, kind)
	return getPidMatchingSupportedComponentInNamespace(ns)
}

func GetProcessIdInNetworkNamespaceWithIp(ipAddress string) string {
	namespaceId := getNetworkNamespaceFromIp(ipAddress)
	if namespaceId != "" {
		return getPidMatchingSupportedComponentInNamespace(namespaceId)
	}
	return ""
}

func SeparateContainerNetwork(pid int) bool {
	result := false
	pidStr := strconv.Itoa(pid)
	containerType := GetContainerTypeProcessIsRunningIn(pidStr)
	if containerType == "docker" {
		log.Debugln("Disconnecting host network from Pid in docker container" + pidStr)
		containerID := GetContainerIdWithPid(pidStr)
		DisconnectNetwork(containerID)
	} else if containerType == "custom" {
		log.Debugln("Disconnecting host network from Pid in custom container" + pidStr)
		DisconnectHostNetworkFromPidInNamespace(pidStr)
	}

	return result
}
