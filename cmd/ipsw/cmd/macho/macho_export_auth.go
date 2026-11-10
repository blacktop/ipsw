//go:build darwin || linux

package macho

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/blacktop/ipsw/pkg/fairplay"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

const (
	exportAuthorizationHelper  = "_export-auth-helper"
	exportAuthorizationTimeout = 2 * time.Minute
)

var errAuthorizationTooLarge = errors.New("authorization snapshot exceeded its size limit")

func init() {
	command := &cobra.Command{
		Use:   "export-auth",
		Short: "Export existing local authorization for offline IPA decryption",
		Long:  "Export existing local authorization on macOS. Run as your normal user; a short-lived helper requests sudo approval for the protected read. The authorization is saved to ~/.config/ipsw/fairplay/authorization.fpauth unless --output names another private directory. No account login or download is performed.",
		Example: heredoc.Doc(`
			# Export to ~/.config/ipsw/fairplay/authorization.fpauth as your normal macOS user;
			# the helper requests sudo approval
			❯ ipsw macho export-auth

			# Export to ./private-auth/authorization.fpauth instead
			❯ ipsw macho export-auth --output ./private-auth`),
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE:         runExportAuthorization,
	}
	command.Flags().StringP("output", "o", "",
		"Private output directory for authorization.fpauth (default ~/.config/ipsw/fairplay)")
	MachoCmd.AddCommand(command)
	MachoCmd.AddCommand(&cobra.Command{
		Use:           exportAuthorizationHelper,
		Hidden:        true,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runExportAuthorizationHelper,
	})
}

func runExportAuthorization(cmd *cobra.Command, _ []string) error {
	if os.Geteuid() == 0 {
		return errors.New("run export-auth as your normal user; it requests sudo approval for its helper")
	}
	if runtime.GOOS != "darwin" {
		return fairplay.ErrOfflineUnsupported
	}
	if err := fairplay.OfflineAvailable(); err != nil {
		return err
	}
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	if !cmd.Flags().Changed("output") {
		if output, err = defaultAuthorizationDirectory(); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(output), 0700); err != nil {
			return errors.New("could not create the ipsw config directory")
		}
	}
	if output == "" {
		return errors.New("--output must be nonempty")
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("could not locate the authorization helper")
	}
	// sudo uses the terminal device for approval. Its stdout remains a pipe,
	// and no password or authorization material is read from the terminal here.
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("authorization export requires an interactive terminal for sudo approval")
	}
	defer terminal.Close()
	// Reject an unusable destination before requesting sudo approval.
	directory, created, err := openAuthorizationDirectory(output)
	if err != nil {
		return err
	}
	defer directory.Close()
	ctx, cancel := context.WithTimeout(cmd.Context(), exportAuthorizationTimeout)
	defer cancel()
	helper := exec.CommandContext(ctx, "/usr/bin/sudo", "--", executable,
		"--config-quiet", "macho", exportAuthorizationHelper)
	helper.Stdin = terminal
	// SIGKILL would leave the terminal without echo if sudo is still prompting;
	// SIGTERM lets sudo restore it, and WaitDelay escalates if sudo lingers.
	helper.Cancel = func() error { return helper.Process.Signal(unix.SIGTERM) }
	payload, err := collectAuthorization(ctx, helper, cancel)
	if err != nil {
		if created {
			// Rmdir removes the directory only while it is still empty.
			_ = unix.Rmdir(directory.Name())
		}
		return err
	}
	defer clear(payload)
	if err := writeAuthorization(directory, payload); err != nil {
		return err
	}
	cmd.Println("Authorization saved to", filepath.Join(directory.Name(), authorizationFilename))
	return nil
}

func runExportAuthorizationHelper(cmd *cobra.Command, _ []string) error {
	if runtime.GOOS != "darwin" {
		return fairplay.ErrOfflineUnsupported
	}
	if os.Geteuid() != 0 {
		return fairplay.ErrOfflinePermission
	}
	output, err := os.Stdout.Stat()
	if err != nil || output.Mode()&os.ModeNamedPipe == 0 {
		return errors.New("authorization helper requires a stdout pipe")
	}
	if err := cmd.Context().Err(); err != nil {
		return err
	}
	// Once approved, sudo runs as full root and the unprivileged parent can no
	// longer signal it, so this privileged process bounds its own lifetime.
	deadline := time.AfterFunc(exportAuthorizationTimeout, func() { os.Exit(1) })
	defer deadline.Stop()
	payload, err := fairplay.CaptureAuthorization()
	if err != nil {
		return err
	}
	defer clear(payload)
	n, err := cmd.OutOrStdout().Write(payload)
	if err != nil || n != len(payload) {
		return errors.New("could not transfer authorization snapshot")
	}
	return nil
}

type authorizationWriter struct {
	data     []byte
	written  int
	exceeded bool
	cancel   context.CancelFunc
}

func (w *authorizationWriter) Write(data []byte) (int, error) {
	remaining := len(w.data) - w.written
	if len(data) > remaining {
		w.exceeded = true
		w.cancel()
		return 0, errAuthorizationTooLarge
	}
	n := copy(w.data[w.written:], data)
	w.written += n
	return n, nil
}

func collectAuthorization(ctx context.Context, command *exec.Cmd, cancel context.CancelFunc) ([]byte, error) {
	output := &authorizationWriter{data: make([]byte, fairplay.AuthorizationMaxBytes), cancel: cancel}
	command.Stdout = output
	// Never relay helper diagnostics: neither a panic nor a failed child may
	// print authorization material. sudo's approval uses /dev/tty directly.
	command.Stderr = io.Discard
	command.WaitDelay = 3 * time.Second
	err := command.Run() // Run observes Wait, including every child failure.
	if err != nil || output.exceeded {
		clear(output.data)
		if output.exceeded {
			return nil, errAuthorizationTooLarge
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, errors.New("authorization export timed out")
		}
		if ctx.Err() != nil {
			return nil, errors.New("authorization export was canceled")
		}
		return nil, errors.New("authorization export helper failed")
	}
	payload := output.data[:output.written:output.written]
	if !fairplay.ValidAuthorization(payload) {
		clear(output.data)
		return nil, errors.New("authorization helper returned an invalid snapshot")
	}
	return payload, nil
}

// openAuthorizationDirectory creates or opens the private output directory and
// reports whether it created it. The returned handle pins the validated
// directory, so the later write cannot land anywhere else.
func openAuthorizationDirectory(output string) (*os.File, bool, error) {
	output = filepath.Clean(output)
	mkdirErr := os.Mkdir(output, 0700)
	if mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
		return nil, false, errors.New("could not create the authorization directory")
	}
	fd, err := unix.Open(output, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, false, errors.New("could not open the authorization directory")
	}
	directory := os.NewFile(uintptr(fd), output)
	if err := checkAuthorizationDirectory(fd); err != nil {
		_ = directory.Close()
		return nil, false, err
	}
	return directory, mkdirErr == nil, nil
}

func checkAuthorizationDirectory(fd int) error {
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return errors.New("could not inspect the authorization directory")
	}
	if uint64(info.Uid) != uint64(os.Geteuid()) || info.Mode&07777 != 0700 {
		return errors.New("authorization directory must be owned by the current user with mode 0700")
	}
	if unix.Fstatat(fd, authorizationFilename, &info, unix.AT_SYMLINK_NOFOLLOW) == nil {
		return errors.New("authorization.fpauth already exists; existing files are never overwritten")
	}
	return nil
}

func writeAuthorization(directory *os.File, payload []byte) error {
	return writeAuthorizationWith(directory, payload, (*os.File).Write)
}

func writeAuthorizationWith(
	directory *os.File, payload []byte, write func(*os.File, []byte) (int, error),
) error {
	if !fairplay.ValidAuthorization(payload) {
		return errors.New("invalid authorization snapshot")
	}
	fd := int(directory.Fd())
	fileFD, err := unix.Openat(fd, authorizationFilename,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("could not create authorization.fpauth; existing files are never overwritten")
	}
	file := os.NewFile(uintptr(fileFD), authorizationFilename)
	var created unix.Stat_t
	if err := unix.Fstat(fileFD, &created); err != nil {
		_ = file.Close()
		return errors.New("could not inspect the created authorization file")
	}
	published := false
	defer func() {
		if published {
			return
		}
		var current unix.Stat_t
		if unix.Fstatat(fd, authorizationFilename, &current, unix.AT_SYMLINK_NOFOLLOW) == nil &&
			current.Mode&unix.S_IFMT == unix.S_IFREG &&
			current.Dev == created.Dev && current.Ino == created.Ino {
			_ = unix.Unlinkat(fd, authorizationFilename, 0)
		}
		_ = file.Close()
	}()
	if err := file.Chmod(0600); err != nil {
		return errors.New("could not set authorization file permissions")
	}
	if n, err := write(file, payload); err != nil || n != len(payload) {
		return errors.New("could not write the authorization file")
	}
	if err := file.Sync(); err != nil {
		return errors.New("could not sync the authorization file")
	}
	if err := file.Close(); err != nil {
		return errors.New("could not close the authorization file")
	}
	published = true
	if err := directory.Sync(); err != nil {
		return errors.New("authorization was saved, but directory durability could not be confirmed")
	}
	return nil
}
