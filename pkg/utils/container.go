// bigfoot
// author - min@

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

/**
 * Creates new container (in new namespaces) & launches the provided executable in new container.
 * It also configurs container:
 * 	- Set UID/GID mapping to emulate root access.
 *
 * Function parameters:
 * containerId - ID create new container.
 * environmentVariables - Environment variables to set in the container.
 * executable - Full path for executable to launch in the container.
 * arguments - To be passed to provided executable.
 */
func startProcessInNewContainer(containerID int, environmentVariables []string, executable string, arguments []string) {
	cmd := exec.Cmd{
		Path: executable,
		Args: arguments,
	}

	cmd.Env = environmentVariables

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWNET |
			syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: containerID,
				HostID:      os.Getuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: containerID,
				HostID:      os.Getgid(),
				Size:        1,
			},
		},
	}

	if err := cmd.Run(); err != nil {
		fmt.Printf("Error running the %s command - %s\n", executable, err)
		os.Exit(1)
	}
}
