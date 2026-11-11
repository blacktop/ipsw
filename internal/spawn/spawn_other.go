//go:build !(darwin && cgo)

package spawn

import (
	"errors"
	"os/exec"
	"syscall"
)

// run uses os/exec where posix_spawn is not implemented.
func (c *Cmd) run() error {
	cmd := exec.Command(c.Path, c.Args[1:]...)
	cmd.Args = c.Args
	cmd.Stdin, cmd.Stdout, cmd.Stderr = c.Stdin, c.Stdout, c.Stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return err
	}
	status := &ExitError{Code: exitErr.ExitCode()}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		status.Code, status.Signal = -1, ws.Signal()
	}
	return status
}
