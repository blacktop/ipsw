//go:build darwin || linux

package cmd

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestInterruptContext re-execs the test binary as a helper that installs
// interruptContext and then ignores it, proving the first SIGINT cancels the
// context and the second one kills the process (default disposition restored).
func TestInterruptContext(t *testing.T) {
	if os.Getenv("IPSW_TEST_SIGNAL_HELPER") == "1" {
		helperInterruptContext()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run", "TestInterruptContext")
	cmd.Env = append(os.Environ(), "IPSW_TEST_SIGNAL_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()

	lines := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	waitLine := func(want string) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					t.Fatalf("helper exited before printing %q", want)
				}
				if line == want {
					return
				}
			case <-deadline:
				t.Fatalf("timed out waiting for helper to print %q", want)
			}
		}
	}

	waitLine("ready")
	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	// first interrupt: context cancels, helper keeps running (ignores it)
	waitLine("cancelled")

	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	// second interrupt: default disposition restored, process must die
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if err == nil {
			t.Fatal("helper exited 0, want death by SIGINT")
		} else if ok := errorsAs(err, &exitErr); !ok || exitErr.Sys().(syscall.WaitStatus).Signal() != syscall.SIGINT {
			t.Fatalf("helper exit = %v, want death by SIGINT", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper survived the second SIGINT: default disposition was not restored")
	}
}

// helperInterruptContext simulates a command that ignores its context.
func helperInterruptContext() {
	ctx, cancel := interruptContext()
	defer cancel()
	fmt.Println("ready")
	<-ctx.Done()
	fmt.Println("cancelled")
	// deliberately non-responsive: only a second signal can end us
	select {}
}

func errorsAs(err error, target *(*exec.ExitError)) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}
