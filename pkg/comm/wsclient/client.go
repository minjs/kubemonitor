package wsclient

import (
	"github.com/gorilla/websocket"
	"io/ioutil"
	"net/url"

	"crypto/tls"
	"crypto/x509"
	log "github.com/minjs/golog"
)

type WSConn struct {
	conn *websocket.Conn
}

func NewWSConn() *WSConn {
	return &WSConn{
		conn: nil,
	}
}

func (wsConn *WSConn) Open(addr string, tlsEnable bool, serverCert string, clientAuth bool, clientCert, clientKey string, isSelfSigned bool) error {
	u, parseErr := url.Parse(addr)
	if parseErr != nil {
		log.Error("url parse: ", parseErr)
	}
	u.Scheme = "ws" // force ws scheme

	if tlsEnable {
		u.Scheme = "wss"
		cert, err := ioutil.ReadFile(serverCert)
		if err != nil {
			log.Fatalf("Couldn't load file", serverCert, err)
			return err
		}
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(cert)
		if clientAuth {
			cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
			if err != nil {
				log.Fatalf("Couldn't load client key and cert file", clientCert, clientKey, err)
				return err
			}
			websocket.DefaultDialer.TLSClientConfig = &tls.Config{
				Certificates:       []tls.Certificate{cert},
				RootCAs:            certPool,
				InsecureSkipVerify: isSelfSigned,
			}

		} else {
			websocket.DefaultDialer.TLSClientConfig = &tls.Config{
				RootCAs: certPool,
			}
		}
	}

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)

	if err != nil {
		log.Error("dial:", err)
		return err
	}
	wsConn.conn = c
	return nil
}

func (wsConn *WSConn) Close() {
	wsConn.conn.Close()
}

func (wsConn *WSConn) Send(v interface{}) error {
	return wsConn.conn.WriteJSON(v)
}

func (wsConn *WSConn) Receive() (messageType int, p []byte, err error) {
	return wsConn.conn.ReadMessage()
}

func (wsConn *WSConn) SendRoutine(senderChan chan interface{}, stopChan chan int, errChan chan int) {
	log.Infoln("Start send routine", senderChan)

	for {
		select {
		case sendMsg := <-senderChan:
			if err := wsConn.Send(sendMsg); err != nil {
				errChan <- 1
				return
			}
		case <-stopChan:
			log.Infoln("Receive stop message")
			return
		}
	}
}

func (wsConn *WSConn) ReceiveRoutine(receiverChan chan []byte, errChan chan int) {
	log.Infoln("Start receive routine")
	for {
		if msgType, bytes, err := wsConn.Receive(); err != nil {
			log.Errorln("WebSocket read error", err)
			errChan <- 1
			return
		} else {
			if msgType != websocket.TextMessage {
				log.Errorln("WebSocket read wrong message type", msgType)
			} else {
				//send it to receiver channel
				receiverChan <- bytes
			}
		}
	}
}
