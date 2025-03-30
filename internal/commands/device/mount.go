package device

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/blacktop/ipsw/pkg/usb/lockdownd"
	semver "github.com/hashicorp/go-version"
)

type DDIConfig struct {
	Dev *lockdownd.DeviceValues

	ImageType string

	XCodePath      string
	DDIFile        string
	SigFile        string
	TrustcachePath string
	ManifestPath   string
}

// DDIInfo holds all configuration for Developer Disk Images
type DDIInfo struct {
	// Used for image selection from manifest
	ImageType string

	// Image data and signature
	ImageData     []byte
	SignatureData []byte

	// Paths to required files
	TrustcachePath string
	ManifestPath   string

	// DMG mounting info
	MountPoint   string
	NeedsUnmount bool

	// For personalization
	BuildManifest *plist.BuildManifest
}

func (d *DDIInfo) Clean() error {
	if d.NeedsUnmount {
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Unmounting from %s", d.MountPoint))
		if err := utils.Retry(3, 2*time.Second, func() error {
			return utils.Unmount(d.MountPoint, false)
		}); err != nil {
			return fmt.Errorf("failed to unmount from %s: %w", d.MountPoint, err)
		}
	}
	return nil
}

func GetDDIInfo(c *DDIConfig) (*DDIInfo, error) {
	info := &DDIInfo{
		ImageType: c.ImageType,
	}

	ver, err := semver.NewVersion(c.Dev.ProductVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to parse device version: %w", err)
	}

	// Old device (pre-iOS 17)
	if ver.LessThan(semver.Must(semver.NewVersion("17.0"))) {
		if c.XCodePath != "" {
			version := ver.Segments()
			imgPath := filepath.Join(c.XCodePath,
				fmt.Sprintf("/Contents/Developer/Platforms/iPhoneOS.platform/DeviceSupport/%d.%d/DeveloperDiskImage.dmg",
					version[0], version[1]))
			sigPath := imgPath + ".signature"

			info.ImageData, err = os.ReadFile(imgPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read DeveloperDiskImage.dmg: %w", err)
			}

			info.SignatureData, err = os.ReadFile(sigPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read DeveloperDiskImage.dmg.signature: %w", err)
			}

			return info, nil
		} else if c.DDIFile != "" && c.SigFile != "" {
			info.ImageData, err = os.ReadFile(c.DDIFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read image '%s': %w", c.DDIFile, err)
			}

			info.SignatureData, err = os.ReadFile(c.SigFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read signature '%s': %w", c.SigFile, err)
			}

			return info, nil
		} else {
			return nil, fmt.Errorf("for iOS < 17.0, either --xcode or both --ddi-img and --signature must be specified")
		}
	}
	// iOS 17+ device

	// If manifest path is already provided, use it
	if c.ManifestPath != "" && c.TrustcachePath != "" {
		info.ManifestPath = c.ManifestPath
		info.TrustcachePath = c.TrustcachePath

		if c.DDIFile != "" {
			info.ImageData, err = os.ReadFile(c.DDIFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read image '%s': %w", c.DDIFile, err)
			}
		}

		if c.SigFile != "" {
			info.SignatureData, err = os.ReadFile(c.SigFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read signature '%s': %w", c.SigFile, err)
			}
		}

		return info, nil
	}

	// Need to find files based on Xcode or DMG path
	if c.XCodePath != "" {
		xcodeVer, err := utils.GetXCodeVersion(c.XCodePath)
		if err != nil {
			return nil, fmt.Errorf("failed to get Xcode version: %w", err)
		}

		xcver, err := semver.NewVersion(xcodeVer)
		if err != nil {
			return nil, fmt.Errorf("failed to parse Xcode version: %w", err)
		}

		// Xcode Older than 16.0
		if xcver.LessThan(semver.Must(semver.NewVersion("16.0"))) {
			// DDI is in Xcode.app
			dmgPath := filepath.Join(c.XCodePath, "/Contents/Resources/CoreDeviceDDIs/iOS_DDI.dmg")
			if _, err := os.Stat(dmgPath); errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("failed to find iOS_DDI.dmg in '%s'", dmgPath)
			}
		} else { // Newer Xcode (16.0+)
			dmgPath := "/Library/Developer/DeveloperDiskImages/iOS_DDI.dmg"
			if _, err := os.Stat(dmgPath); errors.Is(err, os.ErrNotExist) {
				// Try NEW (as of Xcode 16.2 maybe?) DDI expanded folder structure
				info.ManifestPath = "/Library/Developer/DeveloperDiskImages/iOS_DDI/Restore/BuildManifest.plist"
				if _, err := os.Stat(info.ManifestPath); errors.Is(err, os.ErrNotExist) {
					return nil, fmt.Errorf("failed to find BuildManifest.plist at '%s' (run `%s -runFirstLaunch`)",
						info.ManifestPath, filepath.Join(c.XCodePath, "Contents/Developer/usr/bin/xcodebuild"))
				}
				return info, nil
			}
		}
	} else if c.DDIFile == "" {
		return nil, fmt.Errorf("no valid image source provided (either --xcode or --ddi-img must be specified)")
	}

	// At this point we have a DMG path that needs to be mounted
	utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting %s", c.DDIFile))
	mountPoint, alreadyMounted, err := utils.MountDMG(c.DDIFile)
	if err != nil {
		return nil, fmt.Errorf("failed to mount %s: %w", c.DDIFile, err)
	}

	info.MountPoint = mountPoint

	if alreadyMounted {
		utils.Indent(log.Info, 3)(fmt.Sprintf("%s already mounted", c.DDIFile))
		info.NeedsUnmount = false
	} else {
		info.NeedsUnmount = true
	}

	info.ManifestPath = filepath.Join(mountPoint, "Restore/BuildManifest.plist")

	if c.DDIFile != "" && info.ManifestPath == "" {
		info.ImageData, err = os.ReadFile(c.DDIFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read image '%s': %w", c.DDIFile, err)
		}
	}

	return info, nil
}
