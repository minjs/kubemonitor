// Created by cgo -godefs - DO NOT EDIT
// cgo -godefs -- -I./include types_linux.go

package cgolmnl

type (
	Size_t    uint64
	Pid_t     int32
	Ssize_t   int64
	Socklen_t uint32
)

type nlmsghdr struct {
	Len   uint32
	Type  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
}

const SizeofNlmsghdr = 0x10

const SizeofNlmsgerr = 0x14

type Nlmsgerr struct {
	Error int32
	Msg   nlmsghdr
}

const SizeofNlPktinfo = 0x4

type NlPktinfo struct {
	Group uint32
}

const SizeofNlattr = 0x4

type nlattr struct {
	Len  uint16
	Type uint16
}
