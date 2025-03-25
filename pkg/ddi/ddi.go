package ddi

const (
	DeveloperDiskImagesDir = "/Library/Developer/DeveloperDiskImages"
	CandidateDDIDir        = "/Library/Developer/CoreDevice/CandidateDDIs"
)

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

type Info struct {
	Arguments   []string `json:"arguments"`
	CommandType string   `json:"commandType"`
	Environment struct {
		TERM string `json:"TERM"`
	} `json:"environment"`
	JSONVersion int    `json:"jsonVersion"`
	Outcome     string `json:"outcome"`
	Version     string `json:"version"`
	Result      struct {
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
