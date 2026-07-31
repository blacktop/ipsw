package pcc

import (
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/plist"
)

// ReleaseSummary returns the compact release identity shared by PCC commands.
// The release date intentionally comes last.
func ReleaseSummary(release *download.PCCRelease) string {
	releaseDate := "????-??-??"
	if created := release.ReleaseCreationTime(); !created.IsZero() {
		releaseDate = created.Format("2006-01-02")
	}

	osVersion := "?"
	var osBuild string
	if release.Version != nil {
		if release.Version.Version != "" {
			osVersion = release.Version.Version
		}
		osBuild = release.Version.BuildLabel()
	}

	cloudBuild, train, app := release.CloudOSInfo()
	label := cloudBuild
	if osBuild != "" {
		if label != "" {
			label += " / "
		}
		label += osBuild
	}
	if train != "" {
		if label != "" {
			label += " "
		}
		label += "(" + train + ")"
	}
	if app != "" {
		if label != "" {
			label += "  "
		}
		label += app
	}
	if label == "" {
		label = release.ReleaseID()
	}
	if label == "" {
		label = "?"
	}

	return fmt.Sprintf("%05d) %s  %s  %s", release.Index, osVersion, label, releaseDate)
}

// ReleaseURLSummary appends every labeled asset URL to ReleaseSummary.
func ReleaseURLSummary(release *download.PCCRelease) string {
	var out strings.Builder
	out.WriteString(ReleaseSummary(release))
	for _, asset := range release.GetAssets() {
		if asset.GetUrl() == "" {
			continue
		}
		assetType := strings.TrimPrefix(asset.GetType().String(), "ASSET_TYPE_")
		fmt.Fprintf(&out, "\n  %-11s  %s", assetType, asset.GetUrl())
	}
	return out.String()
}

// VPhoneFetcher returns a reusable remote vphone600 firmware resolver.
func VPhoneFetcher(config *download.RemoteConfig) func(url string) (download.VPhoneFirmware, error) {
	return func(url string) (download.VPhoneFirmware, error) {
		zr, err := download.NewRemoteZipReader(url, config)
		if err != nil {
			return download.VPhoneFirmware{}, err
		}
		var count int
		for _, file := range zr.File {
			if strings.Contains(file.Name, download.VPhoneFirmwareToken) {
				count++
			}
		}
		return download.VPhoneFirmware{Present: count > 0, Count: count}, nil
	}
}

// VersionFetcher returns a reusable remote BuildManifest version resolver.
func VersionFetcher(config *download.RemoteConfig) func(url string) (download.PCCVersion, error) {
	return func(url string) (download.PCCVersion, error) {
		if url == "" {
			return download.PCCVersion{}, fmt.Errorf("no OS asset URL")
		}
		zr, err := download.NewRemoteZipReader(url, config)
		if err != nil {
			return download.PCCVersion{}, err
		}
		for _, file := range zr.File {
			if path.Base(file.Name) != "BuildManifest.plist" {
				continue
			}
			rc, err := file.Open()
			if err != nil {
				return download.PCCVersion{}, err
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return download.PCCVersion{}, err
			}
			buildManifest, err := plist.ParseBuildManifest(data)
			if err != nil {
				return download.PCCVersion{}, err
			}
			return download.PCCVersion{
				Version: buildManifest.ProductVersion,
				Build:   buildManifest.ProductBuildVersion,
			}, nil
		}
		return download.PCCVersion{}, fmt.Errorf("no BuildManifest in IPSW")
	}
}
