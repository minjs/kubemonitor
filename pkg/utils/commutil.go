// ZeroSystems
// author - vinay@

package utils

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"time"
)

type PulseCheckRequest struct {
	MessageType string `json:"messageType"`
}

type RegisterMessagePayload struct {
	Hostname   string `json:"hostName"`
	IPAddress  string `json:"ipAddress"`
	MacAddress string `json:"macAddress"`
	CommoNaame string `json:"commonName"`
}

type RegisterMessageRequest struct {
	MessageType            string `json:"messageType"`
	RegisterMessagePayload `json:"payload"`
}

/**
 * Creates connection with controller.
 * Caller is responsible to check conn is not nil & for closing the connection.
 */
func DialController(controllerHost string) *websocket.Conn {
	var dialer *websocket.Dialer
	controllerURL := "ws://" + controllerHost
	conn, _, err := dialer.Dial(controllerURL, nil)
	if err != nil {
		fmt.Println(err)
		return nil

	}
	return conn
}

/**
 * Sends register message to controller.
 */
func SendPulseCheck(conn *websocket.Conn) {
	pulseCheckMessage := &PulseCheckRequest{
		MessageType: "pulse-check",
	}

	bytes, err := json.Marshal(pulseCheckMessage)
	if err != nil {
		fmt.Println("Failed to serialize pulse check message....")
		fmt.Println(err)
		return
	}
	fmt.Println("Sending pulse check message....")
	fmt.Println(string(bytes))
	conn.WriteMessage(websocket.TextMessage, []byte(bytes))
}

/**
 * Sends register message to controller with provided parameters.
 */
func SendRegister(conn *websocket.Conn, hostname string, ipaddress string, macaddress string, commonname string) {
	registerMessage := &RegisterMessageRequest{
		MessageType: "register",
		RegisterMessagePayload: RegisterMessagePayload{
			Hostname:   hostname,
			IPAddress:  ipaddress,
			MacAddress: macaddress,
			CommoNaame: commonname,
		},
	}

	bytes, err := json.Marshal(registerMessage)
	if err != nil {
		fmt.Println("Failed to serialize register message....")
		fmt.Println(err)
		return
	}
	fmt.Println("Sending register message....")
	fmt.Println(string(bytes))
	conn.WriteMessage(websocket.TextMessage, []byte(bytes))
}

/**
 * Receives message from websocket & stores in provided buffered channel.
 * This should be called once as go routine to receive contorller messages asynchronously.
 */
func ReceiveMessages(conn *websocket.Conn, receivedMessages chan string) {
	fmt.Println("Receiving messages....")
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("read:", err)
			return
		}
		if len(receivedMessages) < cap(receivedMessages) {
			receivedMessages <- string(message)
		} else {
			fmt.Println("Channel full, not storing any new message received from controller.")
		}

	}
}

/**
 * Processes all messages stored in provided buffered channel.
 * This method should be called periodically to process messages.
 */
func processReceivedMessages(receivedMessages chan string) {
	for len(receivedMessages) > 0 {
		fmt.Println("received: ", <-receivedMessages)
	}
}

/**
 * Processes received messages periodically with periodicity of provided interval (in nano seconds).
 */
func ProcessReceivedMessagesPeriodically(receiveMessages chan string, interval int64) {
	for {
		processReceivedMessages(receiveMessages)
		time.Sleep(time.Duration(interval))
	}
}

/**
 * Starts receving & processing messages at predefined interval (100 ms)
 */
func ReceiveAndProcessMessages(conn *websocket.Conn, receivedMessages chan string) {
	var intervalToProcessReceivedMessages int64 = 100000000 // 100 ms

	go ReceiveMessages(conn, receivedMessages)
	ProcessReceivedMessagesPeriodically(receivedMessages, intervalToProcessReceivedMessages)
}

/**
// Tested with below code
func main() {
    var conn *websocket.Conn
    controllerHost := "controller-ba52ec29.controller.c0a4c3e7.svc.dockerapp.io:3000"

    conn = DialController(controllerHost)
    defer conn.Close()

    //
    chansize := 100
    receivedMessages := make(chan string, chansize)

    if conn != nil {
        go ReceiveMessages(conn, receivedMessages)
        SendPulseCheck(conn)
        SendRegister(conn, "tester.zs.com", "10.10.10.10", "aa:aa:aa:aa:aa:aa", "testerCN.zs.com")
        ProcessReceivedMessagesPeriodically(receivedMessages, 0)
        //ReceiveAndProcessMessages(conn, receivedMessages)
    }
}*/
