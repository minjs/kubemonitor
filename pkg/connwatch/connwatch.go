package connwatch

//bigfoot
//Author - Min

/*
#include <stdlib.h>
#include <linux/netlink.h>

#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
*/
import "C"

import (
	"../comm"
	serr "../err"
	"../service"
	mnl "github.com/chamaken/cgolmnl"
	inet "github.com/chamaken/cgolmnl/inet"
	log "github.com/minjs/golog"
	"net"
	"syscall"
)

const SizeofNfgenmsg = C.sizeof_struct_nfgenmsg
const BufferSizeFactor = 1

type connInfo struct {
	proto   int
	srcIp   string
	dstIp   string
	srcPort int
	dstPort int
}

func parse_ip_cb(attr *mnl.Nlattr, data interface{}) (int, syscall.Errno) {
	tb := data.(map[uint16]*mnl.Nlattr)
	attr_type := attr.GetType()

	if err := attr.TypeValid(C.CTA_IP_MAX); err != nil {
		return mnl.MNL_CB_OK, 0
	}

	switch attr_type {
	case C.CTA_IP_V4_SRC:
		fallthrough
	case C.CTA_IP_V4_DST:
		if err := attr.Validate(mnl.MNL_TYPE_U32); err != nil {
			log.Errorln("mnl_attr_validate: %s\n", err)
			return mnl.MNL_CB_ERROR, err.(syscall.Errno)
		}
	}
	tb[attr_type] = attr
	return mnl.MNL_CB_OK, 0
}

func print_ip(nest *mnl.Nlattr) {
	tb := make(map[uint16]*mnl.Nlattr)

	nest.ParseNested(parse_ip_cb, tb)
	if tb[C.CTA_IP_V4_SRC] != nil {
		log.Infof("src=%s ", net.IP(tb[C.CTA_IP_V4_SRC].PayloadBytes()))
	}
	if tb[C.CTA_IP_V4_DST] != nil {
		log.Infof("dst=%s ", net.IP(tb[C.CTA_IP_V4_DST].PayloadBytes()))
	}
}

func parse_proto_cb(attr *mnl.Nlattr, data interface{}) (int, syscall.Errno) {
	tb := data.(map[uint16]*mnl.Nlattr)
	attr_type := attr.GetType()

	if err := attr.TypeValid(C.CTA_PROTO_MAX); err != nil {
		return mnl.MNL_CB_OK, 0
	}

	switch attr_type {
	case C.CTA_PROTO_NUM:
		fallthrough
	case C.CTA_PROTO_ICMP_TYPE:
		fallthrough
	case C.CTA_PROTO_ICMP_CODE:
		if err := attr.Validate(mnl.MNL_TYPE_U8); err != nil {
			log.Errorln("mnl_attr_validate: ", err)
			return mnl.MNL_CB_ERROR, err.(syscall.Errno)
		}
	case C.CTA_PROTO_SRC_PORT:
		fallthrough
	case C.CTA_PROTO_DST_PORT:
		fallthrough
	case C.CTA_PROTO_ICMP_ID:
		if err := attr.Validate(mnl.MNL_TYPE_U16); err != nil {
			log.Errorln("mnl_attr_validate: ", err)
			return mnl.MNL_CB_ERROR, err.(syscall.Errno)
		}
	}
	tb[attr_type] = attr
	return mnl.MNL_CB_OK, 0
}

func print_proto(nest *mnl.Nlattr) {
	tb := make(map[uint16]*mnl.Nlattr)

	nest.ParseNested(parse_proto_cb, tb)
	if tb[C.CTA_PROTO_NUM] != nil {
		log.Infof("proto=%d ", tb[C.CTA_PROTO_NUM].U8())
	}
	if tb[C.CTA_PROTO_SRC_PORT] != nil {
		log.Infof("sport=%d ", inet.Ntohs(tb[C.CTA_PROTO_SRC_PORT].U16()))
	}
	if tb[C.CTA_PROTO_DST_PORT] != nil {
		log.Infof("dport=%d ", inet.Ntohs(tb[C.CTA_PROTO_DST_PORT].U16()))
	}
	if tb[C.CTA_PROTO_ICMP_ID] != nil {
		log.Infof("id=%d ", inet.Ntohs(tb[C.CTA_PROTO_ICMP_ID].U16()))
	}
	if tb[C.CTA_PROTO_ICMP_TYPE] != nil {
		log.Infof("type=%d ", tb[C.CTA_PROTO_ICMP_TYPE].U8())
	}
	if tb[C.CTA_PROTO_ICMP_CODE] != nil {
		log.Infof("code=%d ", tb[C.CTA_PROTO_ICMP_CODE].U8())
	}
}

func parse_tuple_cb(attr *mnl.Nlattr, data interface{}) (int, syscall.Errno) {
	tb := data.(map[uint16]*mnl.Nlattr)
	attr_type := attr.GetType()

	if err := attr.TypeValid(C.CTA_TUPLE_MAX); err != nil {
		return mnl.MNL_CB_OK, 0
	}

	switch attr_type {
	case C.CTA_TUPLE_IP:
		if err := attr.Validate(mnl.MNL_TYPE_NESTED); err != nil {
			log.Errorln("mnl_attr_validate: ", err)
			return mnl.MNL_CB_ERROR, err.(syscall.Errno)
		}
	case C.CTA_TUPLE_PROTO:
		if err := attr.Validate(mnl.MNL_TYPE_NESTED); err != nil {
			log.Errorln("mnl_attr_validate: ", err)
			return mnl.MNL_CB_ERROR, err.(syscall.Errno)
		}
	}
	tb[attr_type] = attr
	return mnl.MNL_CB_OK, 0
}

func print_tuple(nest *mnl.Nlattr) {
	tb := make(map[uint16]*mnl.Nlattr)

	nest.ParseNested(parse_tuple_cb, tb)
	if tb[C.CTA_TUPLE_IP] != nil {
		print_ip(tb[C.CTA_TUPLE_IP])
	}
	if tb[C.CTA_TUPLE_PROTO] != nil {
		print_proto(tb[C.CTA_TUPLE_PROTO])
	}
}

func data_attr_cb(attr *mnl.Nlattr, data interface{}) (int, syscall.Errno) {
	tb := data.(map[uint16]*mnl.Nlattr)
	attr_type := attr.GetType()

	if err := attr.TypeValid(C.CTA_MAX); err != nil {
		return mnl.MNL_CB_OK, 0
	}

	switch attr_type {
	case C.CTA_TUPLE_ORIG:
		if err := attr.Validate(mnl.MNL_TYPE_NESTED); err != nil {
			log.Errorln("mnl_attr_validate:", err)
			return mnl.MNL_CB_ERROR, err.(syscall.Errno)
		}
	case C.CTA_TIMEOUT:
		fallthrough
	case C.CTA_MARK:
		fallthrough
	case C.CTA_SECMARK:
		if err := attr.Validate(mnl.MNL_TYPE_U32); err != nil {
			log.Errorln("mnl_attr_validate:", err)
			return mnl.MNL_CB_ERROR, err.(syscall.Errno)
		}
	}
	tb[attr_type] = attr
	return mnl.MNL_CB_OK, 0
}

func data_cb(nlh *mnl.Nlmsghdr, data interface{}) (int, syscall.Errno) {
	tb := make(map[uint16]*mnl.Nlattr)
	// nfg := (*Nfgenmsg)(nlh.Payload())

	switch nlh.Type & 0xFF {
	case C.IPCTNL_MSG_CT_NEW:
		if nlh.Flags&(C.NLM_F_CREATE|C.NLM_F_EXCL) != 0 {
			//log.Infof("%9s ", "[NEW] ")
		} else {
			return mnl.MNL_CB_OK, 0
		}
	case C.IPCTNL_MSG_CT_DELETE:
		return mnl.MNL_CB_OK, 0
	}

	nlh.Parse(SizeofNfgenmsg, data_attr_cb, tb)
	if tb[C.CTA_TUPLE_ORIG] != nil {
		//print_tuple(tb[C.CTA_TUPLE_ORIG])
		processTuple(tb[C.CTA_TUPLE_ORIG])
	}
	if tb[C.CTA_MARK] != nil {
		log.Infof("mark=%d ", inet.Ntohl(tb[C.CTA_MARK].U32()))
	}
	if tb[C.CTA_SECMARK] != nil {
		log.Infof("secmark=%d ", inet.Ntohl(tb[C.CTA_SECMARK].U32()))
	}
	return mnl.MNL_CB_OK, 0
}

func processTuple(nest *mnl.Nlattr) {
	conn := connInfo{}
	tb := make(map[uint16]*mnl.Nlattr)
	nest.ParseNested(parse_tuple_cb, tb)
	if tb[C.CTA_TUPLE_IP] != nil {
		tbip := make(map[uint16]*mnl.Nlattr)
		ip := tb[C.CTA_TUPLE_IP]
		ip.ParseNested(parse_ip_cb, tbip)
		if tbip[C.CTA_IP_V4_SRC] != nil {
			conn.srcIp = net.IP(tbip[C.CTA_IP_V4_SRC].PayloadBytes()).String()
		}
		if tbip[C.CTA_IP_V4_DST] != nil {
			conn.dstIp = net.IP(tbip[C.CTA_IP_V4_DST].PayloadBytes()).String()
		}
	}
	if tb[C.CTA_TUPLE_PROTO] != nil {
		nestProto := tb[C.CTA_TUPLE_PROTO]
		tbproto := make(map[uint16]*mnl.Nlattr)

		nestProto.ParseNested(parse_proto_cb, tbproto)
		if tbproto[C.CTA_PROTO_NUM] != nil {
			conn.proto = int(tbproto[C.CTA_PROTO_NUM].U8())
		}
		if tbproto[C.CTA_PROTO_SRC_PORT] != nil {
			conn.srcPort = int(inet.Ntohs(tbproto[C.CTA_PROTO_SRC_PORT].U16()))
		}
		if tbproto[C.CTA_PROTO_DST_PORT] != nil {
			conn.dstPort = int(inet.Ntohs(tbproto[C.CTA_PROTO_DST_PORT].U16()))
		}
		if conn.proto == 1 && tbproto[C.CTA_PROTO_ICMP_ID] != nil {
			conn.srcPort = int(inet.Ntohs(tbproto[C.CTA_PROTO_ICMP_ID].U16()))
		}
		if tbproto[C.CTA_PROTO_ICMP_TYPE] != nil {
			log.Infof("type=%d ", tbproto[C.CTA_PROTO_ICMP_TYPE].U8())
		}
		if tbproto[C.CTA_PROTO_ICMP_CODE] != nil {
			log.Infof("code=%d ", tbproto[C.CTA_PROTO_ICMP_CODE].U8())
		}
	}
	log.Debugln("conn watch: conn event", conn)
	sendConnEvent(conn)
}

func sendConnEvent(conn connInfo) {
	connEvent := comm.ConnInfo{
		ConnUniqKey: comm.ConnUniqKey{
			Proto:    conn.proto,
			SrcIP:    conn.srcIp,
			SrcPort:  conn.srcPort,
			DestIP:   conn.dstIp,
			DestPort: conn.dstPort,
		},
	}
	log.Debugln("sending conn event to service channel", connEvent)
	service.AgentService.SendConnEvent2Service(connEvent)
	//comm.Send2ConnDiscChan(comm.WSComm.Disc, connEvent)
}

type ConnWatch struct {
	nl *mnl.Socket
}

func NewConnWatch() *ConnWatch {
	return &ConnWatch{}
}

func (c *ConnWatch) SetupWatch() error {
	var err error
	c.nl, err = mnl.NewSocket(C.NETLINK_NETFILTER)
	if err != nil {
		log.Errorln("mnl_socket_open: ", err)
		return serr.ErrCreateSocket
	}
	if err := c.nl.Bind(C.NF_NETLINK_CONNTRACK_NEW|
		C.NF_NETLINK_CONNTRACK_UPDATE|
		C.NF_NETLINK_CONNTRACK_DESTROY,
		mnl.MNL_SOCKET_AUTOPID); err != nil {
		log.Errorln("mnl_socket_bind: ", err)
		return serr.ErrSocketBind
	}
	return nil
}

func (c *ConnWatch) Watch() {
	buf := make([]byte, mnl.MNL_SOCKET_BUFFER_SIZE*BufferSizeFactor)
	ret := mnl.MNL_CB_OK
	for ret >= mnl.MNL_CB_STOP {
		nrcv, err := c.nl.Recvfrom(buf)
		if err != nil {
			log.Errorln("mnl_socket_recvfrom: ", err)
		} else {
			if int64(nrcv) > int64(mnl.MNL_SOCKET_BUFFER_SIZE) {
				log.Warn("receive date bigger than created buffer size", nrcv, mnl.MNL_SOCKET_BUFFER_SIZE)
				continue
			}
			ret, err = mnl.CbRun(buf[:nrcv], 0, 0, data_cb, nil)
		}
	}

	if ret < mnl.MNL_CB_STOP {
		log.Infoln("mnl_cb_run")
		return
	}
}

func (c *ConnWatch) Close() {
	c.nl.Close()
}
