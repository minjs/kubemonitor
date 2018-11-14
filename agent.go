package main

//Author - Min

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	//"runtime"

	"./pkg/comm"
	"./pkg/connwatch"
	"./pkg/pswatch"
	"./pkg/pswatch/psnotify"
	"./pkg/service"

	"flag"
	"./pkg/config"
	log "github.com/minjs/golog"
	"time"
)

func setupLog(logfile string, std bool, format string, logLevel string) {
	level := log.InfoLevel
	if logLevel == "WarnLevel" {
		level = log.WarnLevel
	} else if logLevel == "DebugLevel" {
		level = log.DebugLevel
	}
	log.SetLogLevel(level)
	log.SetFormatter(format)
	log.SetOutputAndRotate(log.LogRotate{
		Filename:  logfile,
		MaxSize:   100,
		MaxBackup: 10,
		MaxAge:    100,
		DupToStd:  std,
	})
}

func main() {
	var logfile string
	comm.AgentStartTime = time.Now()

	version := flag.Bool("version", false, "agent version")
	tlsEnable := flag.Bool("tls", false, "enable tls")
	clientCertEnable := flag.Bool("clientCert", false, "enable client auth")
	clientCertFile := flag.String("cert", "someCertFile", "A PEM eoncoded certificate file.")
	clientKeyFile := flag.String("key", "someKeyFile", "A PEM encoded private key file.")
	isSelfSigned := flag.Bool("isSelfSigned", false, "Boolean value representing if the Controller is using a Self Signed Certificate")
	lf := flag.String("log", "", "agent log file")
	server := flag.String("controller", "", "Controller Web Sockets Interface url. e.g ws://controller.somedomain/wsi OR wss://controller.somedomain/wsi")
	intf := flag.String("int", "", "watching interface")

	serverCertFile := flag.String("serverCrt", "", "servert ca")
	logLevel := flag.String("logLevel", "InfoLevel", "LogLevel (Ex: WarnLevel, DebugLevel Default: InfoLevel)")

	flag.Parse()

	if *version {
		fmt.Println(Version)
		return
	}

	if *server == "" {
		flag.PrintDefaults()
		return
	}

	if *lf == "" {
		logfile = "/var/log/zsAgent.log"
	}

	setupLog(logfile, true, "text", *logLevel)

	comm.IntfName = *intf

	log.Infoln("Starting zero-system agent")

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	//receive the os signal
	go func() {
		sig := <-sigs
		fmt.Println(sig)
		done <- true
	}()

	comm.WSComm = comm.NewCommWS(*server, *tlsEnable, *serverCertFile, *clientCertEnable,
		*clientCertFile, *clientKeyFile, *isSelfSigned)
	comm.WSComm.Setup()
	defer comm.WSComm.CleanUp()

	//register agent to controller
	reg := comm.NewAgentRegister()
	for config.MachineID == "" {
		select {
		case <-done:
			return
		default:
			reg.AgentRegister(comm.WSComm)
			time.Sleep(10 * time.Second)
		}
	}

	comm.WSComm.Disc = comm.NewDiscovery()

	// default to discover mode
	config.AgentMode = config.AgentModeDisc

	pulseCheck := comm.NewPulseCheck()
	comm.SendPulseCheck(comm.WSComm)

	service.AgentService = service.NewAgentService(pulseCheck.PulseCheckAckChan)
	service.MonitorEnforceRecover()

	initCompList := []string{"Nginx", "JBoss", "MySQL", "Tomcat", "Apache", "ElasticSearch", "Logstash", "Kibana", "MongoDB", "Oracle"}
	log.Infoln("Add initial component list and discovery message")
	service.AgentService.AddComponentList(initCompList)

	time.Sleep(5 * time.Second)

	log.Infoln("Start process watch")

	watcher, err := pswatch.NewPsWatcher([]int{0}, psnotify.PROC_EVENT_FORK|psnotify.PROC_EVENT_EXEC|psnotify.PROC_EVENT_EXIT)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	defer watcher.Close()

	// Process events
	go watcher.Receive()

	err = watcher.Watch()
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	log.Infoln("Start conn watch")

	cw := connwatch.NewConnWatch()
	cw.SetupWatch()
	defer cw.Close()

	go cw.Watch()

	time.Sleep(5 * time.Second)

	go pulseCheck.AgentPulseCheck(comm.WSComm)
	go service.MonitoringModeWatch()

	comm.PushCommands = comm.PushCommandRegister()

	<-done
	log.Infoln("exiting")
}
