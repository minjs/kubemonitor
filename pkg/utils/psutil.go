// ZeroSystems
// author - vinay@

package utils

import (
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

/**
Checks if provided process ID is one of the Jboss processes, based on provided buffer.
Returns:
    JBOSS_PROCESS_CONTROLLER if it is Jboss process controller process.
    JBOSS_HOST_CONTROLLER if it is Jboss host controller process.
    JBOSS_SERVER if it is Jboss server proces.
    EMPTY or "" string if it does not belong to Jboss processes.
*/
func checkForJbossProcess(processID string, buffer string) string {
	//var buffer bytes.Buffer

	//grepProcessID(&buffer, processID)

	if strings.Contains(buffer, "jboss") {
		if strings.Contains(buffer, "Djboss.domain.default.config") {
			if strings.Contains(buffer, "D[Process Controller]") {
				return "JBOSS_PROCESS_CONTROLLER"
			}

			if strings.Contains(buffer, "Djboss.home.dir") {
				if strings.Contains(buffer, "D[Host Controller]") {
					if strings.Contains(buffer, "D[Server:") {
						return "JBOSS_SERVER"
					}
					return "JBOSS_HOST_CONTROLLER"
				}
			}
		} else if strings.Contains(buffer, "org.jboss.as.standalone") && strings.Contains(buffer, "Djboss.home.dir") {
			return "JBOSS_SERVER"
		}
	}

	return ""
}

/**
Checks if provided process ID is one of the nginx processes, based on provided buffer.
Returns:
    NGINX_MASTER_PROCESS if it is Nginx master process.
    NGINX_WORKER_PROCESS if it is Nginx worker process.
    EMPTY or "" string if it does not belong to Nginx processes.
*/
func checkForNginxProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "nginx") {
		if strings.Contains(buffer, "nginx: master process") {
			return "NGINX_MASTER_PROCESS"
		} else if strings.Contains(buffer, "nginx: worker process") {
			return "NGINX_WORKER_PROCESS"
		}
	}

	return ""
}

/**
Checks if provided process ID is tomcat server process, based on provided buffer.
Returns:
    TOMCAT_SERVER_PROCESS if it's tomcat server process.
    EMPTY or "" string if it's not a Tomcat server process.
*/
func checkForTomcatProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "catalina") {
		if strings.Contains(buffer, "catalina.home") && strings.Contains(buffer, "catalina.base") &&
			strings.Contains(buffer, "tomcat-juli.jar") {
			return "TOMCAT_SERVER_PROCESS"
		}
	}

	return ""
}

/**
Checks if provided process ID is Mysql server process, based on provided buffer.
Returns:
    MYSQL_SERVER_PROCESS if it's Mysql server process.
    EMPTY or "" string if it's not a Mysql server process.
*/
func checkForMysqlProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "mysql") {
		if GetContainerTypeProcessIsRunningIn(processID) == "docker" && strings.Contains(buffer, "mysqld") {
			return "MYSQL_SERVER_PROCESS"
		}

		if strings.Contains(buffer, "basedir") && strings.Contains(buffer, "datadir") &&
			strings.Contains(buffer, "plugin-dir") && strings.Contains(buffer, "socket") {
			return "MYSQL_SERVER_PROCESS"
		} else if strings.Contains(buffer, "mysqld") && strings.Contains(buffer, "pid-file") {
			return "MYSQL_SERVER_PROCESS"
		}
	}

	return ""
}

/**
Checks if provided process ID is Apache server process, based on provided buffer.
Returns:
	APACHE_SERVER_PROCESS if it's Apache server process.
	EMPTY or "" string if it's not a Apache server process.
*/
func checkForApacheProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "httpd") && !strings.Contains(buffer, "-V") {
		if GetContainerTypeProcessIsRunningIn(processID) == "docker" {
			return "APACHE_SERVER_PROCESS"
		}

		httpdPath := strings.Split(buffer, "httpd")[0]

		output, error := exec.Command("/bin/sh", "-c", httpdPath+"httpd -V").Output()
		if error != nil {
			return ""
		}
		if strings.Contains(string(output), "HTTPD_ROOT") && strings.Contains(string(output), "SERVER_CONFIG_FILE") &&
			strings.Contains(string(output), "DEFAULT_PIDLOG") && strings.Contains(string(output), "DEFAULT_ERRORLOG") {
			return "APACHE_SERVER_PROCESS"
		} else if strings.Contains(buffer, "bitnami") && strings.Contains(buffer, "httpd.bin") &&
			strings.Contains(buffer, "httpd.conf") {
			return "APACHE_SERVER_PROCESS"
		}
	}

	return ""
}

/**
Checks if provided process ID is one of Oracle processes, based on provided buffer.
Returns:
	ORACLE_NETLISTENER_PROCESS if it's Oracle net listener process.
	ORACLE_ENTERPRISE_MANAGER_PROCESS if it's Oracle enterprise manager process.
	ORACLE_DATABASE_SERVER_PROCESS if it's Oracle DB server process.
	ORACLE_MANAGEMENT_AGENT_PROCESS if it's Oracle management agent process.
	ORACLE_BACKGROUND_PROCES if it's Oracle background process.
	EMPTY or "" string if it's not a Apache server process.
*/
func checkForOracleProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "oracle") {
		if strings.Contains(buffer, "tnslsnr") && strings.Contains(buffer, "inherit") {
			return "ORACLE_NETLISTENER_PROCESS"
		}

		if strings.Contains(buffer, "emdb.nohup") {
			return "ORACLE_ENTERPRISE_MANAGER_PROCESS"
		}

		if strings.Contains(buffer, "oracle.home") && strings.Contains(buffer, "java.protocol.handler.pkgs") &&
			strings.Contains(buffer, "server") {
			return "ORACLE_DATABASE_SERVER_PROCESS"
		}

		if strings.Contains(buffer, "emagent") {
			return "ORACLE_MANAGEMENT_AGENT_PROCESS"
		}
	}

	if strings.HasPrefix(buffer, "ora_") {
		return "ORACLE_BACKGROUND_PROCES"
	}

	return ""
}

/**
Checks if provided process ID is Kibana process, based on provided buffer.
Returns:
    KIBANA_PROCESS if it's Kibana process.
    EMPTY or "" string if it's not a Kibana process.
*/
func checkForKibanaProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "kibana") {
		if strings.Contains(buffer, "node/bin/node") {
			return "KIBANA_PROCESS"
		}
	}

	return ""
}

/**
Checks if provided process ID is Logstash process, based on provided buffer.
Returns:
    LOGSTASH_PROCESS if it's Logstash process.
    EMPTY or "" string if it's not a Logstash process.
*/
func checkForLogstashProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "logstash") {
		if strings.Contains(buffer, "jffi.boot.library.path") && strings.Contains(buffer, "bootclasspath") &&
			strings.Contains(buffer, "org.jruby.Main") && strings.Contains(buffer, "java.awt.headless") {
			return "LOGSTASH_PROCESS"
		}
	}

	return ""
}

/**
Checks if provided process ID is Elasticsearch process, based on provided buffer.
Returns:
    ELASTICSEARCH_PROCESS if it's Elasticsearch process.
    EMPTY or "" string if it's not a Elasticsearch process.
*/
func checkForElasticsearchProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "elasticsearch") {
		if strings.Contains(buffer, "path.home") && strings.Contains(buffer, "org.elasticsearch.bootstrap.Elasticsearch") {
			return "ELASTICSEARCH_PROCESS"
		}
	}

	return ""
}

/**
Checks if provided process ID is MongoDB process, based on provided buffer.
Returns:
	MONGODB_PROCESS if it's mongodb process.
	EMPTY or "" string if it's not a mongodb process.
*/
func checkForMongodbProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "mongod") && !strings.Contains(buffer, "--version") &&
		!strings.Contains(buffer, ";") {
		if GetContainerTypeProcessIsRunningIn(processID) == "docker" {
			return "MONGODB_PROCESS"
		}

		mongodPath := strings.Split(buffer, "mongod")[0]

		output, error := exec.Command("/bin/sh", "-c", mongodPath+"mongod --version").Output()
		if error != nil {
			return ""
		}
		if strings.Contains(string(output), "db version") && strings.Contains(string(output), "git version") {
			return "MONGODB_PROCESS"
		}
	}

	return ""
}

/**
Checks if process ID is docker-proxy process, based on provided buffer.
Returns:
	DOCKER_PROXY_PROCESS if it's docker proxy process.
	EMPTY or "" string if it's not a mongodb process.
*/
func checkForDockerProxyProcess(processID string, buffer string) string {
	if strings.Contains(buffer, "docker-proxy") && strings.Contains(buffer, "-proto") &&
		strings.Contains(buffer, "-host-ip") && strings.Contains(buffer, "-container-ip") {
		return "DOCKER_PROXY_PROCESS"
	}
	return ""
}

/**
Checks if provided process ID is supported by ZS Agent.
*/
func CheckForSupportedProcess(processID string, processPath string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "CheckForSupportedProcess")

	var buffer []byte
	var err error
	if processPath == "" {
		filePath := "/proc/" + processID + "/cmdline"
		buffer, err = ioutil.ReadFile(filePath)
		if err != nil {
			return ""
		}
	} else {
		buffer = []byte(processPath)
	}

	jbossProcess := checkForJbossProcess(processID, string(buffer))
	if jbossProcess != "" {
		return jbossProcess
	}

	nginxProcess := checkForNginxProcess(processID, string(buffer))
	if nginxProcess != "" {
		return nginxProcess
	}

	tomcatProcess := checkForTomcatProcess(processID, string(buffer))
	if tomcatProcess != "" {
		return tomcatProcess
	}

	mysqlProcess := checkForMysqlProcess(processID, string(buffer))
	if mysqlProcess != "" {
		return mysqlProcess
	}

	apacheProcess := checkForApacheProcess(processID, string(buffer))
	if apacheProcess != "" {
		return apacheProcess
	}

	oracleProcess := checkForOracleProcess(processID, string(buffer))
	if oracleProcess != "" {
		return oracleProcess
	}

	kibanaProcess := checkForKibanaProcess(processID, string(buffer))
	if kibanaProcess != "" {
		return kibanaProcess
	}

	logstashProcess := checkForLogstashProcess(processID, string(buffer))
	if logstashProcess != "" {
		return logstashProcess
	}

	elastisearchProcess := checkForElasticsearchProcess(processID, string(buffer))
	if elastisearchProcess != "" {
		return elastisearchProcess
	}

	mongodbProcess := checkForMongodbProcess(processID, string(buffer))
	if mongodbProcess != "" {
		return mongodbProcess
	}

	dockerProxyProcess := checkForDockerProxyProcess(processID, string(buffer))
	if dockerProxyProcess != "" {
		return dockerProxyProcess
	}

	return ""
}

/*
Gets namespace inode for process (ID) for passed namespace type (nsType).
Allowed nsTypes: ipc, mnt, net, pid, user or uts.
*/
func GetNamespaceInodeForProcess(processID string, nsType string) string {
	linkFile := "/proc/" + processID + "/ns/" + nsType

	if os.Geteuid() != 0 {
		return ""
	}

	output, error := os.Readlink(linkFile)
	if error != nil {
		return ""
	} else {
		return output
	}
}

func GetNetworkNamespaceInodeForProcess(processID string) string {
	return GetNamespaceInodeForProcess(processID, "net")
}

func GetPidNamespaceInodeForProcess(processID string) string {
	return GetNamespaceInodeForProcess(processID, "pid")
}

/*
Checks if process belongs to root namespace.
*/
func CheckIfRootNamespace(processID string, nsType string) bool {
	rootNs := GetNamespaceInodeForProcess("1", nsType)
	processNs := GetNamespaceInodeForProcess(processID, nsType)

	return rootNs == processNs
}

/*
Checks if process is containerized. For ZS agent we assume process is containerized
if at least separate net & pid namespaces are used.
*/
func CheckIfProcessIsContainerized(processID string) bool {
	if !CheckIfRootNamespace(processID, "net") && !CheckIfRootNamespace(processID, "pid") {
		return true
	}
	return false
}

/*
Gets parent process ID for the process.
*/
func GetParentProcessId(processID string) string {
	output, error := exec.Command("ps", "-p", processID, "-o", "ppid=").Output()
	if error != nil {
		return ""
	} else {
		return strings.TrimSpace(string(output))
	}
}

/*
Checks for the string's existence in process tree
*/
func CheckStringInProcessTree(processID string, searchString string) bool {
	for {
		if processID == "1" || processID == "" {
			return false
		}

		filePath := "/proc/" + processID + "/cmdline"
		buffer, error := ioutil.ReadFile(filePath)
		if error != nil {
			return false
		}

		if strings.Contains(string(buffer), searchString) {
			return true
		}

		i64, err := strconv.ParseInt(processID, 10, 32)
		if err != nil {
			return false
		}
		pi32, err := GetParentPid(int32(i64))
		if err != nil {
			return false
		}

		processID = strconv.Itoa(int(pi32))
	}
}

/*
Returns container type process is running in.
Types returned:
docker - If process is running inside docker container.
custom - If process is running inside custom container, created with namespaces.
empty string - If process is not running inside container.
*/
func GetContainerTypeProcessIsRunningIn(processID string) string {
	start := time.Now()
	defer ElapseTimeFromStartForFunction(start, "GetContainerTypeProcessIsRunningIn")

	i64, err := strconv.ParseInt(processID, 10, 64)
	if err != nil {
		return ""
	}

	if CheckIfProcessExists(int(i64)) {
		if CheckIfProcessIsContainerized(processID) {
			if CheckStringInProcessTree(processID, "docker-containerd") {
				return "docker"
			} else if CheckStringInProcessTree(processID, "lxc-start") {
				return "lxc"
			} else {
				return "custom"
			}
		}
	}

	return ""
}

func CheckIfProcessExists(pid int) bool {
	exists := true
	process, err := os.FindProcess(int(pid))
	if err != nil {
		exists = false
	} else {
		err := process.Signal(syscall.Signal(0))
		if err != nil && !strings.Contains(err.Error(), "operation not permitted") {
			exists = false
		}
	}

	return exists
}
