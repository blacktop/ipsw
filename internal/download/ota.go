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
)

const (
	iOS13OtaDevBetaURL  = "https://mesu.apple.com/assets/iOS13DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS13OtaPublicURL   = "https://mesu.apple.com/assets/iOS13PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS14OtaDevBetaURL  = "https://mesu.apple.com/assets/iOS14DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS14OtaPublicURL   = "https://mesu.apple.com/assets/iOS14PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	otaPublicURL        = "https://mesu.apple.com/assets/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	otaPublicWatchOSURL = "https://mesu.apple.com/assets/watch/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"

	// CREDIT: Siguza
	assetType_SoftwareUpdate    = "com.apple.MobileAsset.SoftwareUpdate"
	assetType_MacSoftwareUpdate = "com.apple.MobileAsset.MacSoftwareUpdate"
	assetType_SFRSoftwareUpdate = "com.apple.MobileAsset.SFRSoftwareUpdate"

	audienceiOSRelease            = "01c1d682-6e8f-4908-b724-5501fe3f5e5c" // iOS release
	audienceiOSInternal           = "ce9c2203-903b-4fb3-9f03-040dc2202694" // iOS internal (not publicly accessible)
	audienceiOS_11Beta            = "b7580fda-59d3-43ae-9488-a81b825e3c73" // iOS 11 beta
	audienceiOS_12Beta            = "ef473147-b8e7-4004-988e-0ae20e2532ef" // iOS 12 beta
	audienceiOS_13Beta            = "d8ab8a45-ee39-4229-891e-9d3ca78a87ca" // iOS 13 beta
	audienceiOS_14DeveloperBeta   = "dbbb0481-d521-4cdf-a2a4-5358affc224b" // iOS 14 developer beta
	audienceiOS_14PublicBeta      = "84da8706-e267-4554-8207-865ae0c3a120" // iOS 14 public beta
	audienceiOS_15DeveloperBeta   = "ce48f60c-f590-4157-a96f-41179ca08278" // iOS 15 developer beta
	audienceiOS_15PublicBeta      = "9e12a7a5-36ac-4583-b4fb-484736c739a8" // iOS 15 public beta
	audienceTvOSRelease           = "356d9da0-eee4-4c6c-bbe5-99b60eadddf0" // tvOS release
	audienceTvOS_11Beta           = "ebd90ea1-6216-4a7c-920e-666faccb2d50" // tvOS 11 beta (returns 404)
	audienceTvOS_12Beta           = "5b220c65-fe50-460b-bac5-b6774b2ff475" // tvOS 12 beta
	audienceTvOS_13Beta           = "975af5cb-019b-42db-9543-20327280f1b2" // tvOS 13 beta
	audienceTvOS_14Beta           = "65254ac3-f331-4c19-8559-cbe22f5bc1a6" // tvOS 14 beta
	audienceTvOS_15Beta           = "4d0dcdf7-12f2-4ebf-9672-ac4a4459a8bc" // tvOS 15 beta
	audienceWatchOSRelease        = "b82fcf9c-c284-41c9-8eb2-e69bf5a5269f" // watchOS release
	audienceWatchOS_4Beta         = "f659e06d-86a2-4bab-bcbb-61b7c60969ce" // watchOS 4 beta (returns 404)
	audienceWatchOS_5Beta         = "e841259b-ad2e-4046-b80f-ca96bc2e17f3" // watchOS 5 beta
	audienceWatchOS_6Beta         = "d08cfd47-4a4a-4825-91b5-3353dfff194f" // watchOS 6 beta
	audienceWatchOS_7Beta         = "ff6df985-3cbe-4d54-ba5f-50d02428d2a3" // watchOS 7 beta
	audienceWatchOS_8Beta         = "b407c130-d8af-42fc-ad7a-171efea5a3d0" // watchOS 8 beta
	audienceAudioOSRelease        = "0322d49d-d558-4ddf-bdff-c0443d0e6fac" // audioOS release
	audienceAudioOS_14Beta        = "b05ddb59-b26d-4c89-9d09-5fda15e99207" // audioOS 14 beta
	audienceAudioOS_15Beta        = "58ff8d56-1d77-4473-ba88-ee1690475e40" // audioOS 15 beta
	audienceMacOS_Release         = "60b55e25-a8ed-4f45-826c-c1495a4ccc65" // macOS release
	audienceMacOS_11CustomerBeta  = "215447a0-bb03-4e18-8598-7b6b6e7d34fd" //  macOS 11 customer beta
	audienceMacOS_11DeveloperBeta = "ca60afc6-5954-46fd-8cb9-60dde6ac39fd" //  macOS 11 developer beta
	audienceMacOS_11PublicBeta    = "902eb66c-8e37-451f-b0f2-ffb3e878560b" //  macOS 11 public beta
	audienceMacOS_12CustomerBeta  = "a3799e8a-246d-4dee-b418-76b4519a15a2" //  macOS 12 customer beta
	audienceMacOS_12DeveloperBeta = "298e518d-b45e-4d36-94be-34a63d6777ec" //  macOS 12 developer beta
	audienceMacOS_12PublicBeta    = "9f86c787-7c59-45a7-a79a-9c164b00f866" //  macOS 12 public beta
)

type OtaAsset struct {
	OSVersion             string   `plist:"OSVersion,omitempty"`
	Build                 string   `plist:"Build,omitempty"`
	PrerequisiteBuild     string   `plist:"PrerequisiteBuild,omitempty"`
	PrerequisiteOSVersion string   `plist:"PrerequisiteOSVersion,omitempty"`
	SupportedDeviceModels []string `plist:"SupportedDeviceModels,omitempty"`
	SupportedDevices      []string `plist:"SupportedDevices,omitempty"`
	ProductSystemName     string   `plist:"SUProductSystemName,omitempty" json:"SUProductSystemName"`
	DocumentationID       string   `plist:"SUDocumentationID,omitempty" json:"SUDocumentationID"`
	ReleaseType           string   `plist:"ReleaseType"`
	CompressionAlgorithm  string   `plist:"_CompressionAlgorithm,omitempty"`
	DownloadSize          int      `plist:"_DownloadSize,omitempty" json:"_DownloadSize"`
	UnarchivedSize        int      `plist:"_UnarchivedSize,omitempty" json:"_UnarchivedSize"`
	IsZipStreamable       bool     `plist:"_IsZipStreamable,omitempty"`
	HashAlgorithm         string   `plist:"_MeasurementAlgorithm,omitempty"`
	Hash                  []byte   `plist:"_Measurement,omitempty"`
	BaseURL               string   `plist:"__BaseURL,omitempty"  json:"__BaseURL"`
	RelativePath          string   `plist:"__RelativePath" json:"__RelativePath"`
}

type transformation struct {
	Measurement string `json:"_Measurement"`
	SEPDigest   string
	RSEPDigest  string
}

type ota struct {
	Assets          []OtaAsset     `plist:"Assets,omitempty" json:"Assets,omitempty"`
	Certificate     []byte         `plist:"Certificate,omitempty"`
	Signature       []byte         `plist:"Signature,omitempty"`
	SigningKey      string         `plist:"SigningKey,omitempty"`
	Nonce           string         `plist:"Nonce,omitempty" json:"Nonce,omitempty"`
	PallasNonce     string         `plist:"PallasNonce,omitempty" json:"PallasNonce,omitempty"`
	SessionID       string         `plist:"SessionId,omitempty" json:"SessionId,omitempty"`
	LegacyXmlURL    string         `plist:"LegacyXmlUrl,omitempty" json:"LegacyXmlUrl,omitempty"`
	PostingDate     string         `plist:"PostingDate,omitempty" json:"PostingDate,omitempty"`
	Transformations transformation `plist:"Transformations,omitempty" json:"Transformations,omitempty"`
	AssetSetID      string         `plist:"AssetSetId,omitempty" json:"AssetSetId,omitempty"`
}

type conf struct {
	Proxy    string
	Insecure bool
	Release  bool
	MacOS    bool
	WatchOS  bool
	TvOS     bool
}

// Ota is an OTA object
type Ota struct {
	ota
	Config conf
}

// NewOTA downloads and parses the itumes plist for iOS14 release/developer beta OTAs
func NewOTA(proxy string, insecure, release, macos bool) (*Ota, error) {

	req, err := http.NewRequest("GET", otaPublicURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http request: %v", err)
	}
	req.Header.Add("User-Agent", utils.RandomAgent())

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
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

	o := Ota{Config: conf{
		Proxy:    proxy,
		Insecure: insecure,
		Release:  release,
		MacOS:    macos,
	}}

	if err := plist.NewDecoder(bytes.NewReader(document)).Decode(&o.ota); err != nil {
		return nil, fmt.Errorf("failed to decode OTA plist response: %v", err)
	}

	return &o, nil
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

// GetOTAs returns a filtered list of OTA assets
func (o *Ota) GetOTAs(device string, doDownload, doNotDownload []string) []OtaAsset {

	var otas []OtaAsset
	var filteredOtas []OtaAsset
	var outOTAs []OtaAsset

	for _, ota := range uniqueOTAs(o.Assets) {
		if len(device) > 0 {
			if utils.StrSliceContains(ota.SupportedDevices, device) {
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

// GetOtaForDevice returns an OTA asset for a given device using the newstyle OTA - CREDIT: https://gist.github.com/Siguza/0331c183c8c59e4850cd0b62fd501424
func (o *Ota) GetOtaForDevice(device, hwmodel string) (OtaAsset, error) {
	var err error

	if len(hwmodel) == 0 {
		hwmodel, err = o.lookupHWModel(device)
		if err != nil {
			return OtaAsset{}, err
		}
	}
	assetType := assetType_SoftwareUpdate
	assetAudience := audienceiOS_15DeveloperBeta
	if o.Config.Release {
		assetAudience = audienceiOSRelease
	}
	if o.Config.MacOS {
		assetType = assetType_MacSoftwareUpdate
		assetAudience = audienceMacOS_12DeveloperBeta
	}

	data := map[string]string{
		"ClientVersion":  "2",
		"AssetType":      assetType,
		"AssetAudience":  assetAudience,
		"ProductType":    device,
		"HWModelStr":     hwmodel,
		"ProductVersion": "0",
		"BuildVersion":   "0",
	}

	jdata, err := json.Marshal(data)
	if err != nil {
		return OtaAsset{}, err
	}

	req, err := http.NewRequest("POST", "https://gdmf.apple.com/v2/assets", bytes.NewBuffer(jdata))
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
	addEq := len(b64Str) % 4
	b64Str += strings.Repeat("=", addEq)

	// bas64 decode the results
	b64data, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		if idx, ok := err.(base64.CorruptInputError); ok {
			return OtaAsset{}, fmt.Errorf("base64 corrupt input at %d in input (char %c): %v", idx, []rune(b64Str)[idx], err)
		}
		return OtaAsset{}, err
	}

	res := ota{}
	if err := json.Unmarshal(b64data, &res); err != nil {
		return OtaAsset{}, err
	}

	return res.Assets[0], nil
}
