package utils

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
)

// Cp copies a file from src to dest
func Cp(src, dst string) error {
	from, err := os.Open(src)
	if err != nil {
		return err
	}
	defer from.Close()

	to, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer to.Close()

	_, err = io.Copy(to, from)

	return err
}

// Mount mounts a DMG with hdiutil
func Mount(image, mountPoint string) (string, error) {
	if runtime.GOOS == "darwin" {
		var attachRe = regexp.MustCompile(`/dev/disk[\d]+`)
		cmd := exec.Command("hdiutil", "attach", "-noverify", "-mountpoint", mountPoint, image)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, out)
		}

		return string(attachRe.Find(out)), nil
	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("apfs-fuse", image, mountPoint)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %s", err, out)
		}
		return mountPoint, nil
	}

	return "", nil
}

// Unmount unmounts a DMG with hdiutil
func Unmount(deviceNode string) error {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("hdiutil", "detach", deviceNode)

		err := cmd.Run()
		if err != nil {
			return err
		}

		return nil

	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("umount", deviceNode)

		err := cmd.Run()
		if err != nil {
			return err
		}

		return nil
	}
	return nil
}
