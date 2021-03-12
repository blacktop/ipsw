package utils

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

// CodeSign codesigns a given binary
func CodeSign(filePath, signature string) error {
	if runtime.GOOS == "darwin" {
		filePath = filepath.Clean(filePath)
		cmd := exec.Command("codesign -s - -f", "-s", signature, "-f", filePath)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		return nil
	}

	return fmt.Errorf("only supported on macOS")
}

// CodeSignWithEntitlements codesigns a given binary with given entitlements
func CodeSignWithEntitlements(filePath, entitlementsPath, signature string) error {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("codesign", "--entitlements", entitlementsPath, "-s", signature, "-f", filepath.Clean(filePath))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		return nil
	}

	return fmt.Errorf("only supported on macOS")
}

// CodeSignAdHoc codesigns a given binary with ad-hoc signature
func CodeSignAdHoc(filePath string) error {
	return CodeSign(filePath, "-")
}

// Mount mounts a DMG with hdiutil
func Mount(image, mountPoint string) error {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("hdiutil", "attach", "-noverify", "-mountpoint", mountPoint, image)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}

		return nil
	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("apfs-fuse", image, mountPoint)

		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}

	return nil
}

// Unmount unmounts a DMG with hdiutil
func Unmount(mountPoint string) error {
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("hdiutil", "detach", mountPoint)

		err := cmd.Run()
		if err != nil {
			return err
		}

		return nil

	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("umount", mountPoint)

		err := cmd.Run()
		if err != nil {
			return err
		}

		return nil
	}
	return nil
}
