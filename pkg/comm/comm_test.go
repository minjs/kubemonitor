package comm

import (
	"fmt"
	"testing"
	"time"
)

func TestSendRegister(t *testing.T) {
	var server = "controller-ba52ec29.controller.c0a4c3e7.svc.dockerapp.io:3000"

	ws := NewCommWS(server)
	ws.Setup()
	defer ws.CleanUp()
	done := make(chan bool, 1)

	go sendPulse(ws)

	<-done
	fmt.Println("finish testing")
}

func sendPulse(ws *CommWS) {
	for {
		time.Sleep(10 * time.Second)
		SendPulseCheck(ws)
	}
}
