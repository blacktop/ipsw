package ddi

import (
	"errors"
	"fmt"
	"strings"

	"github.com/blacktop/ipsw/internal/colors"
)

const (
	DeveloperDiskImagesDir = "/Library/Developer/DeveloperDiskImages"
	CandidateDDIDir        = "/Library/Developer/CoreDevice/CandidateDDIs"
)

var ErrNoDDIsFound = errors.New("no DDIs found")

type Platform struct {
	Metadata struct {
		BuildUpdate                                       string `json:"buildUpdate"`
		ContentIsCompatible                               bool   `json:"contentIsCompatible"`
		CoreDeviceVersionChecksIncludeDevelopmentRevision bool   `json:"coreDeviceVersionChecksIncludeDevelopmentRevision"`
		DevelopmentRevision                               int    `json:"developmentRevision"`
		EnforcingCoreDeviceVersionChecks                  bool   `json:"enforcingCoreDeviceVersionChecks"`
		IsUsable                                          bool   `json:"isUsable"`
		Platform                                          string `json:"platform"`
		ProjectMetadata                                   []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"projectMetadata"`
		Variant string `json:"variant"`
	} `json:"ddiMetadata"`
	HostDDI string `json:"hostDDI"`
}

var colorField = colors.BoldHiMagenta().SprintFunc()

func (p *Platform) String() string {
	var fields []string
	for _, projectMetadata := range p.Metadata.ProjectMetadata {
		fields = append(fields, fmt.Sprintf("   %s: %s", colorField(projectMetadata.Name), projectMetadata.Version))
	}
	return fmt.Sprintf(
		"%s: %s\n"+
			colorField("Metadata")+":\n"+
			"  %s: %s\n"+
			"  %s: %s\n"+
			"  %s: %t\n"+
			"  %s: %t\n"+
			"  %s: %d\n"+
			"  %s: %t\n"+
			"  %s: %t\n"+
			"  %s: %s\n"+
			colorField("  ProjectMetadata")+":\n"+
			"%s",
		colorField("HostDDI"), p.HostDDI,
		colorField("Platform"), p.Metadata.Platform,
		colorField("BuildUpdate"), p.Metadata.BuildUpdate,
		colorField("ContentIsCompatible"), p.Metadata.ContentIsCompatible,
		colorField("CoreDeviceVersionChecksIncludeDevelopmentRevision"), p.Metadata.CoreDeviceVersionChecksIncludeDevelopmentRevision,
		colorField("DevelopmentRevision"), p.Metadata.DevelopmentRevision,
		colorField("EnforcingCoreDeviceVersionChecks"), p.Metadata.EnforcingCoreDeviceVersionChecks,
		colorField("IsUsable"), p.Metadata.IsUsable,
		colorField("Variant"), p.Metadata.Variant,
		strings.Join(fields, "\n"),
	)
}

type PreferredDDI struct {
	Info struct {
		Arguments   []string `json:"arguments"`
		CommandType string   `json:"commandType"`
		Environment struct {
			TERM string `json:"TERM"`
		} `json:"environment"`
		JSONVersion int    `json:"jsonVersion"`
		Outcome     string `json:"outcome"`
		Version     string `json:"version"`
	} `json:"info"`
	Result struct {
		HostCoreDeviceVersion string `json:"hostCoreDeviceVersion"`
		Platforms             struct {
			IOS     []Platform `json:"iOS"`
			MacOS   []Platform `json:"macOS"`
			TvOS    []Platform `json:"tvOS"`
			WatchOS []Platform `json:"watchOS"`
			XrOS    []Platform `json:"xrOS"`
		} `json:"platforms"`
	} `json:"result"`
}

func (i *PreferredDDI) Empty() bool {
	return i.Result.Platforms.IOS == nil &&
		i.Result.Platforms.MacOS == nil &&
		i.Result.Platforms.TvOS == nil &&
		i.Result.Platforms.WatchOS == nil &&
		i.Result.Platforms.XrOS == nil
}

type Version struct {
	BuildVersion        string
	Platform            string
	ProductBuildVersion string
	ProjectMetadata     []struct {
		Project string
		Version string
	}
	Variant string
}
