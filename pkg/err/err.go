package err

//Zero-Systems.io
//Author - Min

import "errors"

var (
	ErrCreateSocket = errors.New("create socker error")
	ErrSocketBind   = errors.New("socker bind error")
	ErrNotFoundPid  = errors.New("can not find the pid for the conn")
	ErrWrongMode    = errors.New("wrong agent mode")
	ErrWrongType    = errors.New("Wrong message type")
	ErrCmdNotExist  = errors.New("command does not exist")
)
