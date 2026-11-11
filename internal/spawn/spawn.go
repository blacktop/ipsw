// Package spawn starts child processes without fork(2).
//
// os/exec forks on macOS. A fork marks every dirty page of the parent
// copy-on-write, and XNU then ignores MADV_FREE_REUSABLE on those pages, so
// memory Go frees afterwards is never returned to the system: a process that
// forks while its heap is large keeps that memory for the rest of its life.
// ipsw diff runs helper tools hundreds of times from inside its largest
// stages. posix_spawn(2) creates the child without duplicating the parent's
// address space, so the heap stays releasable.
//
// Cmd covers the subset of exec.Cmd those tools need. Hosts without a
// posix_spawn implementation here fall back to os/exec.
package spawn

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"syscall"
)

// Cmd describes a child process. Fields mirror exec.Cmd: a nil Stdin reads
// from the null device and nil Stdout and Stderr discard output. The child
// inherits the parent's environment.
type Cmd struct {
	// Path is the program to run. Command resolves it with exec.LookPath.
	Path string
	// Args is the full argument list, including the program name as Args[0].
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// ExitError reports a child that ran but did not exit successfully.
type ExitError struct {
	// Code is the exit status, or -1 when a signal ended the process.
	Code   int
	Signal syscall.Signal
	// Stderr holds the child's standard error when Output captured it.
	Stderr []byte
}

func (e *ExitError) Error() string {
	if e.Code < 0 {
		return "signal: " + e.Signal.String()
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

// ExitCode returns the exit status, or -1 when a signal ended the process.
func (e *ExitError) ExitCode() int { return e.Code }

// Command returns a Cmd for name with the given arguments. name is looked up
// in PATH like exec.Command does; a failed lookup surfaces from Run.
func Command(name string, args ...string) *Cmd {
	cmd := &Cmd{Path: name, Args: append([]string{name}, args...)}
	if path, err := exec.LookPath(name); err == nil {
		cmd.Path = path
	}
	return cmd
}

// Run starts the child and waits for it. A non-zero exit returns *ExitError.
func (c *Cmd) Run() error { return c.run() }

// Output runs the child and returns its standard output. When Stderr is nil
// the standard error is captured into the returned *ExitError instead.
func (c *Cmd) Output() ([]byte, error) {
	if c.Stdout != nil {
		return nil, fmt.Errorf("spawn: Stdout already set")
	}
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	captureStderr := c.Stderr == nil
	if captureStderr {
		c.Stderr = &stderr
	}
	err := c.Run()
	if captureStderr {
		if exitErr, ok := err.(*ExitError); ok {
			exitErr.Stderr = stderr.Bytes()
		}
	}
	return stdout.Bytes(), err
}

// CombinedOutput runs the child and returns its standard output and standard
// error interleaved as the child wrote them.
func (c *Cmd) CombinedOutput() ([]byte, error) {
	if c.Stdout != nil || c.Stderr != nil {
		return nil, fmt.Errorf("spawn: Stdout or Stderr already set")
	}
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	err := c.Run()
	return out.Bytes(), err
}
