package utils

//bigfoot
//Author - Min

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"

	log "github.com/minjs/golog"
	"time"
)

func ReadFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLines(file)
}

func readLines(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func ExecCmd(cmd string) ([]string, error) {
	parts := strings.Fields(cmd)
	head := parts[0]
	var parameters []string
	if len(parts) > 1 {
		parameters = parts[1:]
	} else {
		parameters = []string{}
	}
	execmd := exec.Command(head, parameters...)
	output, err := execmd.CombinedOutput()
	return strings.Split(string(output), "\n"), err
}

func ReadConfig(configFile string, dilemaType string, filterKey []string) (map[string]string, error) {
	contentMap := make(map[string]string)

	if lines, err := ReadFile(configFile); err != nil {
		log.Errorln("Read file error", configFile, err)
		return nil, err
	} else {
		for _, line := range lines {
			var words []string
			if dilemaType == " " {
				words = strings.Fields(line)
			} else {
				words = strings.Split(line, dilemaType)
			}
			if len(words) >= 2 {
				k := strings.TrimSpace(words[0])
				v := strings.TrimSpace(words[0])
				v = strings.TrimLeft(v, string('"'))
				v = strings.TrimRight(v, string('"'))
				if len(filterKey) == 0 || stringInList(k, filterKey) {
					contentMap[k] = v
				}
			}
		}
		return contentMap, nil
	}

}

func stringInList(dst string, list []string) bool {
	for _, c := range list {
		if dst == c {
			return true
		}
	}
	return false
}

func GetTimeStamp() int64 {
	tms := int64(time.Microsecond)
	ts := (time.Now().UTC().UnixNano()) / tms
	return ts
}

func GetMachineUpTime() string {
	file := "/proc/uptime"
	if lines, err := ReadFile(file); err != nil || len(lines) < 1 {
		log.Error("Read uptime error", err)
		return "unknown"
	} else {
		words := strings.Fields(lines[0])
		return words[0]
	}

}
