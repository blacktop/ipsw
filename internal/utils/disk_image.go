package utils

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// attachDarwinImage probes capability before attaching. The legacy backend is
// used when the image verb is unavailable or cannot preserve the password.
// Retrying a failed attachment with a different tool could hide permission
// errors or attach an image twice.
func attachDarwinImage(image, mountPoint string, password io.Reader, run func(*exec.Cmd) ([]byte, error)) error {
	out, err := run(exec.Command("/usr/sbin/diskutil", "image", "attach", "--help"))
	legacy := strings.Contains(string(out), `did not recognize verb "image"`)
	if !legacy {
		if err != nil {
			return fmt.Errorf("failed to check diskutil image attach support: %w: %s", err, out)
		}
		if !strings.Contains(string(out), "--mountPoint") {
			return fmt.Errorf("diskutil image attach help did not advertise --mountPoint: %s", out)
		}
	}

	if password != nil {
		data, err := io.ReadAll(password)
		if err != nil {
			return fmt.Errorf("failed to read disk image password: %w", err)
		}
		// diskutil reads a line from stdin; hdiutil preserves embedded/trailing
		// line breaks. Select before attaching so the password is not changed.
		legacy = legacy || bytes.ContainsAny(data, "\r\n")
		password = bytes.NewReader(data)
	}

	tool := "/usr/sbin/diskutil"
	args := []string{"image", "attach"}
	mountFlag, passwordFlag := "--mountPoint", "--stdinpassphrase"
	if legacy {
		tool = "/usr/bin/hdiutil"
		args = []string{"attach", "-noverify"}
		mountFlag, passwordFlag = "-mountpoint", "-stdinpass"
	}
	if mountPoint != "" {
		args = append(args, mountFlag, mountPoint)
	}
	if password != nil {
		args = append(args, passwordFlag)
	}
	cmd := exec.Command(tool, append(args, image)...)
	cmd.Stdin = password
	out, err = run(cmd)
	if err != nil {
		if strings.Contains(string(out), "Resource busy") {
			return fmt.Errorf("%w: %s", ErrMountResourceBusy, out)
		}
		return fmt.Errorf("%s attach failed: %w: %s", tool, err, out)
	}
	return nil
}
