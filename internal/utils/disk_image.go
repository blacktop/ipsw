package utils

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strings"
)

// darwinImageBackend is a tool that can attach a disk image on macOS.
type darwinImageBackend struct {
	tool         string
	args         []string
	mountFlag    string
	passwordFlag string
	// stdinPassword reports whether the tool advertises reading a passphrase
	// from stdin. A diskutil whose help does not mention one is not trusted
	// with a password; probeDarwinImageBackend sets it from the help text.
	stdinPassword bool
}

// diskutilBackend always uses single-hyphen flags: diskutil on macOS 13
// through 15 rejects double-hyphen flags, and newer builds accept both.
// See https://github.com/blacktop/ipsw/issues/1321.
var diskutilBackend = darwinImageBackend{
	tool:         "/usr/sbin/diskutil",
	args:         []string{"image", "attach"},
	mountFlag:    "-mountPoint",
	passwordFlag: "-stdinpassphrase",
}

var hdiutilBackend = darwinImageBackend{
	tool:          "/usr/bin/hdiutil",
	args:          []string{"attach", "-noverify"},
	mountFlag:     "-mountpoint",
	passwordFlag:  "-stdinpass",
	stdinPassword: true,
}

// attachDarwinImage probes capability before attaching. hdiutil is used when
// the image verb is unavailable or diskutil cannot preserve the password.
// Retrying a failed attachment with a different tool could hide permission
// errors or attach an image twice.
func attachDarwinImage(
	image, mountPoint string, password io.Reader, run func(*exec.Cmd) ([]byte, error),
) error {
	backend, err := probeDarwinImageBackend(run)
	if err != nil {
		return err
	}

	if password != nil {
		data, err := io.ReadAll(password)
		if err != nil {
			return fmt.Errorf("failed to read disk image password: %w", err)
		}
		// diskutil reads a line from stdin; hdiutil preserves embedded/trailing
		// line breaks. Select before attaching so the password is not changed.
		if bytes.ContainsAny(data, "\r\n") || !backend.stdinPassword {
			backend = hdiutilBackend
		}
		password = bytes.NewReader(data)
	}

	var flags []string
	if mountPoint != "" {
		flags = append(flags, backend.mountFlag, mountPoint)
	}
	if password != nil {
		flags = append(flags, backend.passwordFlag)
	}
	cmd := exec.Command(backend.tool, slices.Concat(backend.args, flags, []string{image})...)
	cmd.Stdin = password
	out, err := run(cmd)
	if err != nil {
		if strings.Contains(string(out), "Resource busy") {
			return fmt.Errorf("%w: %s", ErrMountResourceBusy, out)
		}
		return fmt.Errorf("%s attach failed: %w: %s", backend.tool, err, out)
	}
	return nil
}

// probeDarwinImageBackend selects diskutil's image verb when it exists and
// advertises a mount point flag, and hdiutil otherwise. The probe uses -help
// because older diskutil builds reject --help. Help that names the flag is
// trusted even when the probe exits non-zero, since older builds may print
// usage with a failure status.
func probeDarwinImageBackend(run func(*exec.Cmd) ([]byte, error)) (darwinImageBackend, error) {
	out, err := run(exec.Command("/usr/sbin/diskutil", "image", "attach", "-help"))
	help := string(out)
	switch {
	case strings.Contains(help, `did not recognize verb "image"`):
		return hdiutilBackend, nil
	case strings.Contains(help, "-mountPoint"):
		backend := diskutilBackend
		backend.stdinPassword = strings.Contains(help, "stdinpass")
		return backend, nil
	case err != nil:
		return darwinImageBackend{}, fmt.Errorf(
			"failed to check diskutil image attach support: %w: %s", err, out)
	default:
		return darwinImageBackend{}, fmt.Errorf(
			"diskutil image attach help did not advertise -mountPoint: %s", out)
	}
}
