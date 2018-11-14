package utils

import (
	"strconv"
	"strings"

	log "github.com/minjs/golog"
	goProc "github.com/shirou/gopsutil/process"
	"os/user"
)

type Process struct {
	Name      string
	Exe       string
	Cmdline   string
	Uid       int
	Euid      int
	Gid       int
	Egid      int
	Username  string
	Groupname string
}
type PSNode struct {
	Pid      int
	Ps       *Process
	Children []PSNode
}

func GetProcessInfo(pid int) (*Process, error) {
	if proc, err := goProc.NewProcess(int32(pid)); err != nil {
		log.Debugln("Get proc/Pid error from Pid", pid, err)
		return nil, err
	} else {
		var name, exe, cmdline, username, groupname string
		var uids, gids []int32
		var err error

		name, err = proc.Name()
		if err != nil {
			log.Debugln("Get Name for Pid error", pid, err)
			name = ""
		}
		exe, err = proc.Exe()
		if err != nil {
			log.Debugln("Get Exe for Pid error", pid, err)
			exe = ""
		}
		cmdline, err = proc.Cmdline()
		if err != nil {
			log.Debugln("Get Cmdline for Pid error", pid, err)
			cmdline = ""
		}
		uids, err = proc.Uids()
		if err != nil {
			log.Debugln("Get uids for Pid error", pid, err)
			uids = []int32{-1, -1}
		}
		gids, err = proc.Gids()
		if err != nil {
			log.Debugln("Get gids for Pid error", pid, err)
			gids = []int32{-1, -1}
		}
		User, erru := user.LookupId(strconv.Itoa(int(uids[0])))
		if erru != nil {
			log.Debugln("Get username error for", pid, erru)
			username = ""
		} else {
			username = User.Username
		}
		gr, err1 := user.LookupGroupId(strconv.Itoa(int(gids[0])))
		if err1 != nil {
			log.Debugln("Get groupname error for", pid, err1)
			groupname = ""
		} else {
			groupname = gr.Name
		}
		/*
			username, err = proc.Username()
			if err != nil {
				username = ""
			}
			gr, err1 := user.LookupGroup(username)
			if err1 != nil {
				log.Errorln("Get groupname error for", pid, err)
				groupname = ""
			} else {
				groupname = gr.Name
			}
		*/
		return &Process{
			Name:      name,
			Exe:       exe,
			Cmdline:   cmdline,
			Uid:       int(uids[0]),
			Euid:      int(uids[1]),
			Gid:       int(gids[0]),
			Egid:      int(gids[1]),
			Username:  username,
			Groupname: groupname,
		}, nil
	}
}

func GetComponents(comps []string) (map[string]*PSNode, error) {
	if pids, err := goProc.Pids(); err != nil {
		log.Errorln("Get all pids error", err)
		return nil, err
	} else {
		cmap := make(map[string]*PSNode)
		for _, pid := range pids {
			if cn := CheckComponent(int(pid), comps, ""); cn != "" {
				// check its parent process, if it is same component, by pass the current one
				pc := GetParentComponent(pid, comps)
				if cn != pc {
					rootNode := new(PSNode)
					cmap[cn] = rootNode
					constructPNodeTree(pid, rootNode)
				}
			}
		}
		log.Debugln("get process tree", cmap)
		return cmap, nil
	}
}

func GetParentComponent(pid int32, cl []string) string {
	if cp, err := goProc.NewProcess(pid); err == nil {
		if ppid, err := cp.Ppid(); err == nil {
			return CheckComponent(int(ppid), cl, "")
		}
	}
	return ""
}

func GetParentPid(pid int32) (int32, error) {
	if cp, err := goProc.NewProcess(pid); err == nil {
		return cp.Ppid()
	} else {
		return 0, err
	}
}

func GetChildrenPID(pid int32) ([]int32, error) {
	if cp, err := goProc.NewProcess(pid); err != nil {
		return nil, err
	} else {
		cPids := []int32{}
		if children, err := cp.Children(); err != nil {
			return nil, err
		} else {
			for _, c := range children {
				cPids = append(cPids, c.Pid)
			}
			return cPids, nil
		}
	}
}

func constructPNodeTree(pid int32, root *PSNode) {
	root.Pid = int(pid)
	root.Children = []PSNode{}
	p, e := GetProcessInfo(int(pid))
	if e != nil {
		return
	}
	root.Ps = p
	log.Debugln("constructPNodeTree", root.Pid, root.Ps, root.Children)
	if cp, err := goProc.NewProcess(pid); err == nil {
		if cps, err := cp.Children(); err == nil {
			cl := []PSNode{}
			for _, cp := range cps {
				log.Debugln("loop through each child ")
				c := new(PSNode)
				constructPNodeTree(cp.Pid, c)
				cl = append(cl, *c)
			}
			root.Children = cl
		}
	}
	log.Debugln("constructPNodeTree done", root.Pid, root.Ps, root.Children)
}

func CheckComponent(pid int, cl []string, ppath string) string {
	pidstr := strconv.Itoa(pid)
	log.Debugln("check component, ", pid)
	cn := CheckForSupportedProcess(pidstr, ppath)

	//cp, _ := goProc.NewProcess(int32(pid))
	//cn, _ := cp.Cmdline()

	if len(cl) == 0 {
		return ""
	} else if cn != "" {
		for _, n := range cl {
			if strings.Contains(strings.ToUpper(cn), strings.ToUpper(n)) {
				return n
			}
		}
	}
	return ""
}
