package download

import (
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/blacktop/go-plist"
	"github.com/pkg/errors"
)

const (
	iOS13OtaDevBetaURL    = "https://mesu.apple.com/assets/iOS13DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS13OtaPublicBetaURL = "https://mesu.apple.com/assets/iOS13PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
)

type otaAssetXML struct {
	Build                 string   `plist:"Build,omitempty"`
	OSVersion             string   `plist:"OSVersion,omitempty"`
	PrerequisiteBuild     string   `plist:"PrerequisiteBuild,omitempty"`
	PrerequisiteOSVersion string   `plist:"PrerequisiteOSVersion,omitempty"`
	SupportedDeviceModels []string `plist:"SupportedDeviceModels,omitempty"`
	SupportedDevices      []string `plist:"SupportedDevices,omitempty"`
	CompressionAlgorithm  string   `plist:"_CompressionAlgorithm,omitempty"`
	DownloadSize          int      `plist:"_DownloadSize,omitempty"`
	IsZipStreamable       bool     `plist:"_IsZipStreamable,omitempty"`
	HashAlgorithm         string   `plist:"_MeasurementAlgorithm,omitempty"`
	Hash                  []byte   `plist:"_Measurement,omitempty"`
	BaseURL               string   `plist:"__BaseURL,omitempty"`
	RelativePath          string   `plist:"__RelativePath,omitempty"`
}

type OtaXML struct {
	Assets      []otaAssetXML `plist:"Assets,omitempty"`
	Certificate []byte        `plist:"Certificate,omitempty"`
	Signature   []byte        `plist:"Signature,omitempty"`
	SigningKey  string        `plist:"SigningKey,omitempty"`
}

// NewOta downloads and parses the itumes plist for iOS13 developer beta OTAs
func NewOta() (*OtaXML, error) {
	resp, err := http.Get(iOS13OtaDevBetaURL)
	// resp, err := http.Get(iOS13OtaPublicBetaURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create http client")
	}

	document, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read plist")
	}

	ota := OtaXML{}

	dec := plist.NewDecoder(bytes.NewReader(document))
	dec.Decode(&ota)

	return &ota, nil
}
