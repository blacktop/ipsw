package download

import (
	"bytes"
	"crypto/tls"
	"io/ioutil"
	"net/http"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/pkg/errors"
)

const (
	iOS13OtaDevBetaURL    = "https://mesu.apple.com/assets/iOS13DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS13OtaPublicBetaURL = "https://mesu.apple.com/assets/iOS13PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS14OtaDevBetaURL    = "https://mesu.apple.com/assets/iOS14DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS14OtaPublicBetaURL = "https://mesu.apple.com/assets/iOS14PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
)

type OtaAsset struct {
	Build                 string   `plist:"Build,omitempty"`
	OSVersion             string   `plist:"OSVersion,omitempty"`
	PrerequisiteBuild     string   `plist:"PrerequisiteBuild,omitempty"`
	PrerequisiteOSVersion string   `plist:"PrerequisiteOSVersion,omitempty"`
	SupportedDeviceModels []string `plist:"SupportedDeviceModels,omitempty"`
	SupportedDevices      []string `plist:"SupportedDevices,omitempty"`
	DocumentationID       string   `plist:"SUDocumentationID,omitempty"`
	ReleaseType           string   `plist:"ReleaseType"`
	CompressionAlgorithm  string   `plist:"_CompressionAlgorithm,omitempty"`
	DownloadSize          int      `plist:"_DownloadSize,omitempty"`
	IsZipStreamable       bool     `plist:"_IsZipStreamable,omitempty"`
	HashAlgorithm         string   `plist:"_MeasurementAlgorithm,omitempty"`
	Hash                  []byte   `plist:"_Measurement,omitempty"`
	BaseURL               string   `plist:"__BaseURL,omitempty"`
	RelativePath          string   `plist:"__RelativePath,omitempty"`
}

type Ota struct {
	Assets      []OtaAsset `plist:"Assets,omitempty"`
	Certificate []byte     `plist:"Certificate,omitempty"`
	Signature   []byte     `plist:"Signature,omitempty"`
	SigningKey  string     `plist:"SigningKey,omitempty"`
}

// NewOTA downloads and parses the itumes plist for iOS13 developer beta OTAs
func NewOTA(proxy string, insecure bool) (*Ota, error) {

	req, err := http.NewRequest("GET", iOS14OtaDevBetaURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "cannot create http request")
	}
	req.Header.Add("User-Agent", utils.RandomAgent())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           getProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	document, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read plist")
	}

	ota := Ota{}

	dec := plist.NewDecoder(bytes.NewReader(document))
	dec.Decode(&ota)

	return &ota, nil
}
