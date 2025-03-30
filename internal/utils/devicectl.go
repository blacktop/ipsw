package utils

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/ddi"
)

const devicectlPath = "/Library/Developer/PrivateFrameworks/CoreDevice.framework/Resources/bin/devicectl"

func PreferredDDI() (*ddi.PreferredDDI, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "list", "preferredDDI", "--quiet", "--json-output", "-")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get preferred DDI: %v", err)
	}
	var info ddi.PreferredDDI
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal preferred DDI: %v", err)
	}
	return &info, nil
}

func UpdateDDIsFromXCode() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "manage", "ddis", "update", "--no-include-coredevice", "--include-xcode", "--clean")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to update DDIs: %v", err)
	}
	return string(out), nil
}

func UpdateDDIs(sourceDir string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "manage", "ddis", "update", "--no-include-coredevice", "--no-include-xcode", "--source-dir", sourceDir, "--clean")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to update DDIs: %v", err)
	}
	return string(out), nil
}

func BackupDDIs(outputDir string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("only supported on macOS")
	}

	ddiDir := "/Library/Developer/CoreDevice/CandidateDDIs"
	if _, err := os.Stat(ddiDir); os.IsNotExist(err) {
		return "", fmt.Errorf("DDI directory does not exist: %s", ddiDir)
	}
	versionFile := filepath.Join(ddiDir, "iOS/version.plist")
	data, err := os.ReadFile(versionFile)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %v", versionFile, err)
	}
	var version ddi.Version
	if _, err := plist.Unmarshal(data, &version); err != nil {
		return "", fmt.Errorf("failed to unmarshal plist: %v", err)
	}

	zipFile := filepath.Join(outputDir, fmt.Sprintf("ddis_%s.zip", version.ProductBuildVersion))
	zf, err := os.Create(zipFile)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %v", err)
	}
	defer zf.Close()

	zw := zip.NewWriter(zf)
	defer zw.Close()

	if err := filepath.WalkDir(ddiDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Get the relative path of the file/directory within hostDDIDir
		relPath, err := filepath.Rel(ddiDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %s: %w", path, err)
		}

		// Get file info for header
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("failed to get file info for %s: %w", path, err)
		}

		// Create a zip file header
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return fmt.Errorf("failed to create zip header for %s: %w", path, err)
		}

		header.Name = filepath.ToSlash(relPath) // Use slash separators for zip standard

		if d.IsDir() {
			header.Name += "/" // Mark it as a directory
		} else {
			// Set compression method (optional)
			header.Method = zip.Deflate
		}

		// Create the entry in the zip file
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return fmt.Errorf("failed to create zip entry for %s: %w", relPath, err)
		}

		// If it's a file, copy its contents
		if !d.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return fmt.Errorf("failed to open file %s: %w", path, err)
			}
			defer file.Close()

			_, err = io.Copy(writer, file)
			if err != nil {
				return fmt.Errorf("failed to copy file contents for %s: %w", path, err)
			}
		}

		return nil
	}); err != nil {
		os.Remove(zipFile) // Clean up incomplete zip file on error
		return "", fmt.Errorf("failed to walk directory %s: %w", ddiDir, err)
	}

	return zipFile, nil
}

func CleanDDIs() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "manage", "ddis", "clean")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to clean DDIs: %v", err)
	}
	return string(out), nil
}

func ListCrashes(device string) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("only supported on macOS")
	}
	cmd := exec.Command(devicectlPath, "device", "info", "files", "--username=mobile", "--domain-type=systemCrashLogs", "--device", device)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to list crashes: %v", err)
	}
	return string(out), nil
}
