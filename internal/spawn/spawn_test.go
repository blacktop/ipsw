package spawn

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func requireShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("requires /bin/sh")
	}
}

func TestOutputCapturesStdoutAndStderrOnFailure(t *testing.T) {
	requireShell(t)
	out, err := Command("/bin/sh", "-c", "echo out; echo err >&2; exit 3").Output()
	if string(out) != "out\n" {
		t.Errorf("stdout = %q, want %q", out, "out\n")
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 || string(exitErr.Stderr) != "err\n" || err.Error() != "exit status 3" {
		t.Fatalf("err = %#v (%v), want exit status 3 with stderr captured", err, err)
	}
}

func TestCombinedOutputKeepsOrder(t *testing.T) {
	requireShell(t)
	out, err := Command("/bin/sh", "-c", "echo a; echo b >&2; echo c").CombinedOutput()
	if err != nil || string(out) != "a\nb\nc\n" {
		t.Fatalf("CombinedOutput() = %q, %v", out, err)
	}
}

func TestStdinIsPipedInFull(t *testing.T) {
	requireShell(t)
	input := make([]byte, 4<<20)
	if _, err := rand.Read(input); err != nil {
		t.Fatal(err)
	}
	cmd := Command("/bin/cat")
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.Output()
	if err != nil || !bytes.Equal(out, input) {
		t.Fatalf("cat returned %d bytes, err %v; want %d bytes", len(out), err, len(input))
	}
}

func TestChildExitingBeforeReadingStdinIsNotAnError(t *testing.T) {
	requireShell(t)
	cmd := Command("/bin/sh", "-c", "exit 0")
	cmd.Stdin = bytes.NewReader(make([]byte, 8<<20))
	if err := cmd.Run(); err != nil {
		t.Fatalf("Run() = %v, want nil", err)
	}
}

func TestFileStreamsAreHandedToTheChild(t *testing.T) {
	requireShell(t)
	path := filepath.Join(t.TempDir(), "out")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := Command("/bin/sh", "-c", "echo to-file; echo and-err >&2")
	cmd.Stdout, cmd.Stderr = f, f
	runErr := cmd.Run()
	f.Close()
	data, err := os.ReadFile(path)
	if runErr != nil || err != nil || string(data) != "to-file\nand-err\n" {
		t.Fatalf("file holds %q (run %v, read %v)", data, runErr, err)
	}
}

func TestMissingProgramFailsToStart(t *testing.T) {
	err := Command(filepath.Join(t.TempDir(), "missing")).Run()
	var exitErr *ExitError
	if err == nil || errors.As(err, &exitErr) {
		t.Fatalf("Run() = %v, want a start failure", err)
	}
}

func TestSignalIsReported(t *testing.T) {
	requireShell(t)
	err := Command("/bin/sh", "-c", "kill -9 $$").Run()
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != -1 || exitErr.Signal != syscall.SIGKILL || err.Error() != "signal: killed" {
		t.Fatalf("Run() = %v, want signal: killed", err)
	}
}

func TestChildInheritsOnlyStandardStreams(t *testing.T) {
	requireShell(t)
	// Hold an extra descriptor open in the parent; the child must see exactly
	// what an os/exec child sees (its own shell and ls descriptors, no more).
	extra, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	want, err := exec.Command("/bin/sh", "-c", "ls /dev/fd").Output()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Command("/bin/sh", "-c", "ls /dev/fd").Output()
	if err != nil || string(got) != string(want) {
		t.Fatalf("child descriptors = %q, want %q (err %v)", got, want, err)
	}
}

func TestCommandResolvesPath(t *testing.T) {
	requireShell(t)
	cmd := Command("sh", "-c", "exit 0")
	if !filepath.IsAbs(cmd.Path) || cmd.Args[0] != "sh" {
		t.Fatalf("Command() = Path %q Args %v", cmd.Path, cmd.Args)
	}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
}
