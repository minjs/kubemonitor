package config

//Zero-Systems.io
//Author - Min

type WhiteList struct {
	CID     string      `json:"cid"`
	Process []ProcessWL `json:"processes"`
	Conn    []ConnWL    `json:"conn"`
}

type WhiteListPolicy struct {
	Version    string               `json:"version"`
	WhiteLists map[string]WhiteList `json:"whitelist"`
}

type ProcessWL struct {
	BinaryImage string `json:"binaryImage"`
	Arguments   string `json:"arguments"`
}

type ConnWL struct {
	SrcIP    string `json:"srcIP"`
	DestIP   string `json:"destIP"`
	SrcPort  int    `json:"srcPort"`
	DestPort int    `json:"destPort"`
	Proto    int    `json:"proto"`
	Listen   string `json:"listening"`
}
