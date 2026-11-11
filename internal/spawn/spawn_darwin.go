//go:build darwin && cgo

package spawn

/*
#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>

// ipsw_spawn starts path with argv and envp, giving the child fd0, fd1 and
// fd2 as its standard streams and nothing else (POSIX_SPAWN_CLOEXEC_DEFAULT),
// default signal handling and an empty signal mask. Returns 0 or an errno.
static int ipsw_spawn(const char *path, char *const argv[], char *const envp[],
                      int fd0, int fd1, int fd2, pid_t *pid) {
	posix_spawn_file_actions_t actions;
	posix_spawnattr_t attr;
	sigset_t none, all;
	int rc;

	if ((rc = posix_spawn_file_actions_init(&actions)) != 0) {
		return rc;
	}
	if ((rc = posix_spawnattr_init(&attr)) != 0) {
		posix_spawn_file_actions_destroy(&actions);
		return rc;
	}
	sigemptyset(&none);
	sigfillset(&all);
	if ((rc = posix_spawnattr_setsigmask(&attr, &none)) == 0 &&
	    (rc = posix_spawnattr_setsigdefault(&attr, &all)) == 0 &&
	    (rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)) == 0 &&
	    (rc = posix_spawn_file_actions_adddup2(&actions, fd0, 0)) == 0 &&
	    (rc = posix_spawn_file_actions_adddup2(&actions, fd1, 1)) == 0 &&
	    (rc = posix_spawn_file_actions_adddup2(&actions, fd2, 2)) == 0) {
		rc = posix_spawn(pid, path, &actions, &attr, argv, envp);
	}
	posix_spawnattr_destroy(&attr);
	posix_spawn_file_actions_destroy(&actions);
	return rc;
}
*/
import "C"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

// run starts the child with posix_spawn. Streams backed by *os.File are
// handed to the child directly; anything else goes through a pipe serviced by
// a goroutine, as exec.Cmd does.
func (c *Cmd) run() error {
	var streams streamSet
	defer streams.closeParent()

	stdin, err := streams.reader(c.Stdin)
	if err != nil {
		return err
	}
	stdout, err := streams.writer(c.Stdout)
	if err != nil {
		return err
	}
	stderr := stdout
	if c.Stderr != c.Stdout {
		if stderr, err = streams.writer(c.Stderr); err != nil {
			return err
		}
	}

	pid, err := start(c.Path, c.Args, os.Environ(), stdin, stdout, stderr)
	streams.closeChild()
	if err != nil {
		return err
	}
	streams.serve()

	var status syscall.WaitStatus
	for {
		if _, err = syscall.Wait4(pid, &status, 0, nil); !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	copyErr := streams.wait()
	if err != nil {
		return fmt.Errorf("spawn: wait4 %s: %w", c.Path, err)
	}
	switch {
	case status.Signaled():
		return &ExitError{Code: -1, Signal: status.Signal()}
	case status.ExitStatus() != 0:
		return &ExitError{Code: status.ExitStatus()}
	}
	return copyErr
}

// start calls posix_spawn and returns the child's pid.
func start(path string, args, env []string, stdin, stdout, stderr int) (int, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	argv := cStrings(args)
	defer freeCStrings(argv)
	envp := cStrings(env)
	defer freeCStrings(envp)

	var pid C.pid_t
	if rc := C.ipsw_spawn(cpath, &argv[0], &envp[0], C.int(stdin), C.int(stdout), C.int(stderr), &pid); rc != 0 {
		return 0, &os.PathError{Op: "posix_spawn", Path: path, Err: syscall.Errno(rc)}
	}
	return int(pid), nil
}

// cStrings builds a NULL-terminated C string array.
func cStrings(values []string) []*C.char {
	out := make([]*C.char, len(values)+1)
	for i, v := range values {
		out[i] = C.CString(v)
	}
	return out
}

func freeCStrings(values []*C.char) {
	for _, v := range values {
		if v != nil {
			C.free(unsafe.Pointer(v))
		}
	}
}

// streamSet owns the descriptors handed to the child and the goroutines that
// pump non-file streams through pipes.
type streamSet struct {
	child  []*os.File // handed to the child; closed in the parent after spawn
	parent []*os.File // parent ends of pipes and null devices
	pumps  []func() error
	errs   []error
	wg     sync.WaitGroup
	mu     sync.Mutex
}

// reader returns the fd the child reads r from.
func (s *streamSet) reader(r io.Reader) (int, error) {
	if r == nil {
		return s.null(os.O_RDONLY)
	}
	if f, ok := r.(*os.File); ok {
		return int(f.Fd()), nil
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	s.child = append(s.child, pr)
	s.parent = append(s.parent, pw)
	s.pumps = append(s.pumps, func() error {
		_, err := io.Copy(pw, r)
		if closeErr := pw.Close(); err == nil {
			err = closeErr
		}
		// A child that exits before draining its input is not a copy failure.
		if errors.Is(err, syscall.EPIPE) {
			return nil
		}
		return err
	})
	return int(pr.Fd()), nil
}

// writer returns the fd the child writes w through.
func (s *streamSet) writer(w io.Writer) (int, error) {
	if w == nil {
		return s.null(os.O_WRONLY)
	}
	if f, ok := w.(*os.File); ok {
		return int(f.Fd()), nil
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	s.child = append(s.child, pw)
	s.parent = append(s.parent, pr)
	s.pumps = append(s.pumps, func() error {
		_, err := io.Copy(w, pr)
		return err
	})
	return int(pw.Fd()), nil
}

func (s *streamSet) null(flag int) (int, error) {
	f, err := os.OpenFile(os.DevNull, flag, 0)
	if err != nil {
		return 0, err
	}
	s.child = append(s.child, f)
	return int(f.Fd()), nil
}

func (s *streamSet) serve() {
	for _, pump := range s.pumps {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if err := pump(); err != nil {
				s.mu.Lock()
				s.errs = append(s.errs, err)
				s.mu.Unlock()
			}
		}()
	}
}

// closeChild releases the child's ends once the child owns them.
func (s *streamSet) closeChild() {
	for _, f := range s.child {
		f.Close()
	}
	s.child = nil
}

// wait waits for the pumps to finish; the child's exit closes its pipe ends.
func (s *streamSet) wait() error {
	s.wg.Wait()
	return errors.Join(s.errs...)
}

func (s *streamSet) closeParent() {
	s.closeChild()
	for _, f := range s.parent {
		f.Close()
	}
	s.parent = nil
}
