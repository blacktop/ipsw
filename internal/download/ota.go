package download

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/hashicorp/go-version"
)

const (
	clientVersion       = 2
	pallasURL           = "https://gdmf.apple.com/v2/assets"
	otaPublicURL        = "https://mesu.apple.com/assets/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS13OtaDevBetaURL  = "https://mesu.apple.com/assets/iOS13DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS13OtaPublicURL   = "https://mesu.apple.com/assets/iOS13PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	otaPublicWatchOSURL = "https://mesu.apple.com/assets/watch/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	// depricated URLs
	iOS14OtaDevBetaURL = "https://mesu.apple.com/assets/iOS14DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS14OtaPublicURL  = "https://mesu.apple.com/assets/iOS14PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
)

type assetType string

const (
	softwareUpdate assetType = "com.apple.MobileAsset.SoftwareUpdate"
	// For macOS devices
	macSoftwareUpdate assetType = "com.apple.MobileAsset.MacSoftwareUpdate"
	sfrSoftwareUpdate assetType = "com.apple.MobileAsset.SFRSoftwareUpdate"
)

type assetAudienceID string

const ( // CREDIT: Siguza
	iOSRelease           assetAudienceID = "01c1d682-6e8f-4908-b724-5501fe3f5e5c" // iOS release
	iOSInternal          assetAudienceID = "ce9c2203-903b-4fb3-9f03-040dc2202694" // iOS internal (not publicly accessible)
	iOS11Beta            assetAudienceID = "b7580fda-59d3-43ae-9488-a81b825e3c73" // iOS 11 beta
	iOS12Beta            assetAudienceID = "ef473147-b8e7-4004-988e-0ae20e2532ef" // iOS 12 beta
	iOS13Beta            assetAudienceID = "d8ab8a45-ee39-4229-891e-9d3ca78a87ca" // iOS 13 beta
	iOS14DeveloperBeta   assetAudienceID = "dbbb0481-d521-4cdf-a2a4-5358affc224b" // iOS 14 developer beta
	iOS14PublicBeta      assetAudienceID = "84da8706-e267-4554-8207-865ae0c3a120" // iOS 14 public beta
	iOS14SecurityUpdates assetAudienceID = "c724cb61-e974-42d3-a911-ffd4dce11eda" // iOS 14 security updates
	iOS15DeveloperBeta   assetAudienceID = "ce48f60c-f590-4157-a96f-41179ca08278" // iOS 15 developer beta
	iOS15PublicBeta      assetAudienceID = "9e12a7a5-36ac-4583-b4fb-484736c739a8" // iOS 15 public beta

	tvOSRelease assetAudienceID = "356d9da0-eee4-4c6c-bbe5-99b60eadddf0" // tvOS release
	tvOS11Beta  assetAudienceID = "ebd90ea1-6216-4a7c-920e-666faccb2d50" // tvOS 11 beta (returns 404)
	tvOS12Beta  assetAudienceID = "5b220c65-fe50-460b-bac5-b6774b2ff475" // tvOS 12 beta
	tvOS13Beta  assetAudienceID = "975af5cb-019b-42db-9543-20327280f1b2" // tvOS 13 beta
	tvOS14Beta  assetAudienceID = "65254ac3-f331-4c19-8559-cbe22f5bc1a6" // tvOS 14 beta
	tvOS15Beta  assetAudienceID = "4d0dcdf7-12f2-4ebf-9672-ac4a4459a8bc" // tvOS 15 beta

	watchOSRelease assetAudienceID = "b82fcf9c-c284-41c9-8eb2-e69bf5a5269f" // watchOS release
	watchOS4Beta   assetAudienceID = "f659e06d-86a2-4bab-bcbb-61b7c60969ce" // watchOS 4 beta (returns 404)
	watchOS5Beta   assetAudienceID = "e841259b-ad2e-4046-b80f-ca96bc2e17f3" // watchOS 5 beta
	watchOS6Beta   assetAudienceID = "d08cfd47-4a4a-4825-91b5-3353dfff194f" // watchOS 6 beta
	watchOS7Beta   assetAudienceID = "ff6df985-3cbe-4d54-ba5f-50d02428d2a3" // watchOS 7 beta
	watchOS8Beta   assetAudienceID = "b407c130-d8af-42fc-ad7a-171efea5a3d0" // watchOS 8 beta

	audioOSRelease assetAudienceID = "0322d49d-d558-4ddf-bdff-c0443d0e6fac" // audioOS release
	audioOS14Beta  assetAudienceID = "b05ddb59-b26d-4c89-9d09-5fda15e99207" // audioOS 14 beta
	audioOS15Beta  assetAudienceID = "58ff8d56-1d77-4473-ba88-ee1690475e40" // audioOS 15 beta

	macOSRelease         assetAudienceID = "60b55e25-a8ed-4f45-826c-c1495a4ccc65" // macOS release
	macOS11CustomerBeta  assetAudienceID = "215447a0-bb03-4e18-8598-7b6b6e7d34fd" // macOS 11 customer beta
	macOS11DeveloperBeta assetAudienceID = "ca60afc6-5954-46fd-8cb9-60dde6ac39fd" // macOS 11 developer beta
	macOS11PublicBeta    assetAudienceID = "902eb66c-8e37-451f-b0f2-ffb3e878560b" // macOS 11 public beta
	macOS12CustomerBeta  assetAudienceID = "a3799e8a-246d-4dee-b418-76b4519a15a2" // macOS 12 customer beta
	macOS12DeveloperBeta assetAudienceID = "298e518d-b45e-4d36-94be-34a63d6777ec" // macOS 12 developer beta
	macOS12PublicBeta    assetAudienceID = "9f86c787-7c59-45a7-a79a-9c164b00f866" // macOS 12 public beta
)

// Ota is an OTA object
type Ota struct {
	ota
	Config OtaConf
}

// OtaConf is an OTA download configuration
type OtaConf struct {
	Platform string

	Beta bool

	Device  string
	Model   string
	Version *version.Version
	Build   string

	Proxy    string
	Insecure bool
}

type pallasRequest struct {
	ClientVersion           int             `json:"ClientVersion"`
	AssetType               assetType       `json:"AssetType"`
	AssetAudience           assetAudienceID `json:"AssetAudience"`
	ProductType             string          `json:"ProductType"`
	HWModelStr              string          `json:"HWModelStr"`
	ProductVersion          string          `json:"ProductVersion"`
	BuildVersion            string          `json:"BuildVersion"`
	RequestedProductVersion string          `json:"RequestedProductVersion,omitempty"`
	Supervised              bool            `json:"Supervised,omitempty"`
	DelayRequested          bool            `json:"DelayRequested,omitempty"`
}

type ota struct {
	AssetSetID      string          `plist:"AssetSetId,omitempty" json:"AssetSetId,omitempty"`
	Assets          []OtaAsset      `plist:"Assets,omitempty" json:"Assets,omitempty"`
	Certificate     []byte          `plist:"Certificate,omitempty"`
	Signature       []byte          `plist:"Signature,omitempty"`
	SigningKey      string          `plist:"SigningKey,omitempty"`
	Nonce           string          `plist:"Nonce,omitempty" json:"Nonce,omitempty"`
	PallasNonce     string          `plist:"PallasNonce,omitempty" json:"PallasNonce,omitempty"`
	SessionID       string          `plist:"SessionId,omitempty" json:"SessionId,omitempty"`
	LegacyXMLURL    string          `plist:"LegacyXmlUrl,omitempty" json:"LegacyXmlUrl,omitempty"`
	PostingDate     string          `plist:"PostingDate,omitempty" json:"PostingDate,omitempty"`
	Transformations transformations `plist:"Transformations,omitempty" json:"Transformations,omitempty"`
}

type transformations struct {
	RSEPDigest  string `json:"RSEPDigest"`
	SEPDigest   string `json:"SEPDigest"`
	Measurement string `json:"_Measurement"`
}

// OtaAsset is an OTA asset object
type OtaAsset struct {
	ActualMinimumSystemPartition          int            `json:"ActualMinimumSystemPartition" plist:"ActualMinimumSystemPartition,omitempty"`
	AutoUpdate                            bool           `json:"AutoUpdate" plist:"AutoUpdate,omitempty"`
	AssetType                             string         `json:"AssetType" plist:"AssetType,omitempty"`
	Build                                 string         `json:"Build" plist:"Build,omitempty"`
	InstallationSize                      string         `json:"InstallationSize" plist:"InstallationSize,omitempty"`
	InstallationSizeSnapshot              string         `json:"InstallationSize-Snapshot" plist:"InstallationSize-Snapshot,omitempty"`
	MinimumSystemPartition                int            `json:"MinimumSystemPartition" plist:"MinimumSystemPartition,omitempty"`
	OSVersion                             string         `json:"OSVersion" plist:"OSVersion,omitempty"`
	PrerequisiteBuild                     string         `json:"PrerequisiteBuild" plist:"PrerequisiteBuild,omitempty"`
	PrerequisiteOSVersion                 string         `json:"PrerequisiteOSVersion" plist:"PrerequisiteOSVersion,omitempty"`
	RSEPDigest                            []byte         `json:"RSEPDigest" plist:"RSEPDigest,omitempty"`
	Ramp                                  bool           `json:"Ramp" plist:"Ramp,omitempty"`
	RescueMinimumSystemPartition          int            `json:"RescueMinimumSystemPartition" plist:"RescueMinimumSystemPartition,omitempty"`
	SEPDigest                             []byte         `json:"SEPDigest" plist:"SEPDigest,omitempty"`
	ConvReqd                              bool           `json:"SUConvReqd" plist:"SUConvReqd,omitempty"`
	DocumentationID                       string         `json:"SUDocumentationID" plist:"SUDocumentationID,omitempty"`
	ReleaseType                           string         `plist:"ReleaseType"`
	InstallTonightEnabled                 bool           `json:"SUInstallTonightEnabled" plist:"SUInstallTonightEnabled,omitempty"`
	MultiPassEnabled                      bool           `json:"SUMultiPassEnabled" plist:"SUMultiPassEnabled,omitempty"`
	ProductSystemName                     string         `json:"SUProductSystemName" plist:"SUProductSystemName,omitempty"`
	Publisher                             string         `json:"SUPublisher" plist:"SUPublisher,omitempty"`
	SupportedDeviceModels                 []string       `json:"SupportedDeviceModels" plist:"SupportedDeviceModels,omitempty"`
	SupportedDevices                      []string       `json:"SupportedDevices" plist:"SupportedDevices,omitempty"`
	SystemPartitionPadding                map[string]int `json:"SystemPartitionPadding" plist:"SystemPartitionPadding,omitempty"`
	SystemVolumeSealingOverhead           int            `json:"SystemVolumeSealingOverhead" plist:"SystemVolumeSealingOverhead,omitempty"`
	AssetReceipt                          assetReceipt   `json:"_AssetReceipt" plist:"_AssetReceipt,omitempty"`
	CompressionAlgorithm                  string         `json:"_CompressionAlgorithm" plist:"_CompressionAlgorithm,omitempty"`
	DownloadSize                          int            `json:"_DownloadSize" plist:"_DownloadSize,omitempty"`
	EventRecordingServiceURL              string         `json:"_EventRecordingServiceURL" plist:"_EventRecordingServiceURL,omitempty"`
	IsZipStreamable                       bool           `json:"_IsZipStreamable" plist:"_IsZipStreamable,omitempty"`
	Hash                                  []byte         `json:"_Measurement" plist:"_Measurement,omitempty"`
	HashAlgorithm                         string         `json:"_MeasurementAlgorithm" plist:"_MeasurementAlgorithm,omitempty"`
	UnarchivedSize                        int            `json:"_UnarchivedSize" plist:"_UnarchivedSize,omitempty"`
	AssetDefaultGarbageCollectionBehavior string         `json:"__AssetDefaultGarbageCollectionBehavior" plist:"__AssetDefaultGarbageCollectionBehavior,omitempty"`
	BaseURL                               string         `json:"__BaseURL" plist:"__BaseURL,omitempty"`
	CanUseLocalCacheServer                bool           `json:"__CanUseLocalCacheServer" plist:"__CanUseLocalCacheServer,omitempty"`
	HideInstallAlert                      bool           `json:"__HideInstallAlert" plist:"__HideInstallAlert,omitempty"`
	QueuingServiceURL                     string         `json:"__QueuingServiceURL" plist:"__QueuingServiceURL,omitempty"`
	RelativePath                          string         `json:"__RelativePath" plist:"__RelativePath,omitempty"`
}

type assetReceipt struct {
	AssetReceipt   string `json:"AssetReceipt"`
	AssetSignature string `json:"AssetSignature"`
}

// NewOTA downloads and parses the itumes plist for iOS14 release/developer beta OTAs
func NewOTA(conf OtaConf) (*Ota, error) {

	req, err := http.NewRequest("GET", otaPublicURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Add("User-Agent", utils.RandomAgent())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(conf.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: conf.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to connect to URL: %s", resp.Status)
	}

	document, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OTA plist: %v", err)
	}

	o := Ota{Config: conf}

	if err := plist.NewDecoder(bytes.NewReader(document)).Decode(&o.ota); err != nil {
		return nil, fmt.Errorf("failed to decode OTA plist response: %v", err)
	}

	return &o, nil
}

// FilterOtaAssets returns a filtered list of OTA assets
func (o *Ota) FilterOtaAssets(doDownload, doNotDownload []string) []OtaAsset {

	var otas []OtaAsset
	var filteredOtas []OtaAsset
	var outOTAs []OtaAsset

	for _, ota := range uniqueOTAs(o.Assets) {
		if len(o.Config.Device) > 0 {
			if utils.StrSliceContains(ota.SupportedDevices, o.Config.Device) {
				otas = append(otas, ota)
			}
		} else {
			otas = append(otas, ota)
		}
	}

	for _, o := range otas {
		if len(doDownload) > 0 {
			if utils.StrSliceContains(doDownload, o.SupportedDevices[0]) {
				filteredOtas = append(filteredOtas, o)
			}
		} else if len(doNotDownload) > 0 {
			if !utils.StrSliceContains(doNotDownload, o.SupportedDevices[0]) {
				filteredOtas = append(filteredOtas, o)
			}
		} else {
			filteredOtas = append(filteredOtas, o)
		}
	}

	filteredOtas = filterOTADevices(filteredOtas)

	deviceList := make(map[string]string)
	for _, o := range filteredOtas {
		if len(o.SupportedDevices) == 1 && len(o.SupportedDeviceModels) == 1 {
			deviceList[o.SupportedDevices[0]] = o.SupportedDeviceModels[0]
		}
	}

	for dev, model := range deviceList {
		if ota, err := o.GetOtaForDevice(dev, model); err == nil {
			outOTAs = append(outOTAs, ota)
		}
	}

	return outOTAs
}

func (o *Ota) buildPallasRequests(device, hwmodel string) (reqs []pallasRequest, err error) {
	var atype assetType
	var audienceID assetAudienceID

	if len(hwmodel) == 0 {
		hwmodel, err = o.lookupHWModel(device)
		if err != nil {
			return nil, err
		}
	}

	switch o.Config.Platform {
	case "ios":
		atype = softwareUpdate
		audienceID = iOSRelease
		if o.Config.Beta {
			audienceID = iOS15DeveloperBeta
		}
	}

	reqs = append(reqs, pallasRequest{
		ClientVersion:  clientVersion,
		AssetType:      atype,
		AssetAudience:  audienceID,
		ProductType:    device,
		HWModelStr:     hwmodel,
		ProductVersion: "0",
		BuildVersion:   "0",
		// ProductVersion: "14.8.1",
		// BuildVersion:   "18H107",
		// RequestedProductVersion: "15.0",
	})

	return reqs, nil
}

// GetOtaForDevice returns an OTA asset for a given device using the newstyle OTA - CREDIT: https://gist.github.com/Siguza/0331c183c8c59e4850cd0b62fd501424
func (o *Ota) GetOtaForDevice(device, hwmodel string) (OtaAsset, error) {
	var err error
	var atype assetType
	var audienceID assetAudienceID

	if len(hwmodel) == 0 {
		hwmodel, err = o.lookupHWModel(device)
		if err != nil {
			return OtaAsset{}, err
		}
	}

	switch o.Config.Platform {
	case "ios":
		atype = softwareUpdate
		audienceID = iOSRelease
		if o.Config.Beta {
			audienceID = iOS15DeveloperBeta
		}
	}

	jdata, err := json.Marshal(&pallasRequest{
		ClientVersion:  clientVersion,
		AssetType:      atype,
		AssetAudience:  audienceID,
		ProductType:    device,
		HWModelStr:     hwmodel,
		ProductVersion: "0",
		BuildVersion:   "0",
		// ProductVersion: "14.8.1",
		// BuildVersion:   "18H107",
		// RequestedProductVersion: "15.0",
	})
	if err != nil {
		return OtaAsset{}, err
	}

	req, err := http.NewRequest("POST", pallasURL, bytes.NewBuffer(jdata))
	if err != nil {
		return OtaAsset{}, fmt.Errorf("failed to create https request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("User-Agent", utils.RandomAgent())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(o.Config.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: o.Config.Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return OtaAsset{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return OtaAsset{}, fmt.Errorf("failed to connect to URL: got status %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return OtaAsset{}, err
	}

	// repair/parse base64 response data
	parts := strings.Split(string(body), ".")
	b64Str := parts[1]
	b64Str = strings.ReplaceAll(b64Str, "-", "+")
	b64Str = strings.ReplaceAll(b64Str, "_", "/")

	// bas64 decode the results
	b64data, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(b64Str)
	if err != nil {
		return OtaAsset{}, fmt.Errorf("failed to base64 decode pallas response: %v", err)
	}

	res := ota{}
	if err := json.Unmarshal(b64data, &res); err != nil {
		return OtaAsset{}, err
	}

	if len(res.Assets) == 0 {
		return OtaAsset{}, fmt.Errorf("no OTAs found for %s %s", device, hwmodel)
	}

	return res.Assets[0], nil
}

func (o *Ota) lookupHWModel(device string) (string, error) {
	for _, ota := range o.Assets {
		if utils.StrSliceContains(ota.SupportedDevices, device) {
			if len(ota.SupportedDeviceModels) > 1 {
				return "0", fmt.Errorf("found more than one hw model for device %s", device)
			} else if len(ota.SupportedDeviceModels) == 0 {
				return "0", fmt.Errorf("device %s has 0 supported device models", device)
			}
			return ota.SupportedDeviceModels[0], nil
		}
	}
	return "0", fmt.Errorf("failed to find device %s in list of OTAs (please supply a --model)", device)
}

func uniqueOTAs(otas []OtaAsset) []OtaAsset {
	unique := make(map[string]bool, len(otas))
	os := make([]OtaAsset, len(unique))
	for _, elem := range otas {
		if len(elem.BaseURL+elem.RelativePath) != 0 {
			if !unique[elem.BaseURL] {
				os = append(os, elem)
				unique[elem.BaseURL+elem.RelativePath] = true
			}
		}
	}

	return os
}

func filterOTADevices(otas []OtaAsset) []OtaAsset {
	var devices []string
	var filteredOtas []OtaAsset

	for _, ota := range otas {
		devices = append(devices, ota.SupportedDevices...)
	}
	devices = utils.Unique(devices)

	for _, device := range devices {
		var devOTA OtaAsset
		for _, ota := range otas {
			if utils.StrSliceContains(ota.SupportedDevices, device) {
				if devOTA.SupportedDevices == nil {
					devOTA = ota
				} else {
					if ota.DownloadSize > devOTA.DownloadSize {
						devOTA = ota
					}
				}
			}
		}
		filteredOtas = append(filteredOtas, devOTA)
	}

	return uniqueOTAs(filteredOtas)
}
