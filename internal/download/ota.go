package download

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/ota/types"
	info "github.com/blacktop/ipsw/pkg/plist"
	"github.com/hashicorp/go-version"
	"github.com/ulikunitz/xz"
)

const (
	clientVersion       = 2
	pallasURL           = "https://gdmf.apple.com/v2/assets"
	otaPublicURL        = "https://mesu.apple.com/assets/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS13OtaDevBetaURL  = "https://mesu.apple.com/assets/iOS13DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS13OtaPublicURL   = "https://mesu.apple.com/assets/iOS13PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	otaPublicWatchOSURL = "https://mesu.apple.com/assets/watch/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	// Deprecated: URLs
	iOS14OtaDevBetaURL = "https://mesu.apple.com/assets/iOS14DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS14OtaPublicURL  = "https://mesu.apple.com/assets/iOS14PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
)

type assetType string

const (
	softwareUpdate assetType = "com.apple.MobileAsset.SoftwareUpdate"
	// For macOS devices
	macSoftwareUpdate        assetType = "com.apple.MobileAsset.MacSoftwareUpdate"
	recoveryOsSoftwareUpdate assetType = "com.apple.MobileAsset.SFRSoftwareUpdate"
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
	as     *AssetSets
	Config OtaConf
}

// OtaConf is an OTA download configuration
type OtaConf struct {
	Platform        string
	Beta            bool
	Device          string
	Model           string
	Version         *version.Version
	Build           string
	DeviceWhiteList []string
	DeviceBlackList []string
	Proxy           string
	Insecure        bool
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
	CompatibilityVersion    int             `json:"CompatibilityVersion,omitempty"`
	ReleaseType             string          `json:"ReleaseType,omitempty"`
}

type ota struct {
	AssetSetID      string          `plist:"AssetSetId,omitempty" json:"AssetSetId,omitempty"`
	Assets          []types.Asset   `plist:"Assets,omitempty" json:"Assets,omitempty"`
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

// NewOTA downloads and parses the itumes plist for iOS14 release/developer beta OTAs
func NewOTA(as *AssetSets, conf OtaConf) (*Ota, error) {

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

	o := Ota{
		as:     as,
		Config: conf,
	}

	if err := plist.NewDecoder(bytes.NewReader(document)).Decode(&o.ota); err != nil {
		return nil, fmt.Errorf("failed to decode OTA plist response: %v", err)
	}

	return &o, nil
}

// FilterOtaAssets returns a filtered list of OTA assets
// Deprecated: in favor of the NEW pallas API
func (o *Ota) FilterOtaAssets() []types.Asset {

	var otas []types.Asset
	var filteredOtas []types.Asset
	// var outOTAs []types.Asset

	for _, ota := range uniqueOTAs(o.Assets) {
		if len(o.Config.Device) > 0 {
			if utils.StrSliceHas(ota.SupportedDevices, o.Config.Device) {
				otas = append(otas, ota)
			}
		} else {
			otas = append(otas, ota)
		}
	}

	for _, ota := range otas {
		if len(o.Config.DeviceWhiteList) > 0 {
			if utils.StrSliceHas(o.Config.DeviceWhiteList, ota.SupportedDevices[0]) {
				filteredOtas = append(filteredOtas, ota)
			}
		} else if len(o.Config.DeviceBlackList) > 0 {
			if !utils.StrSliceHas(o.Config.DeviceBlackList, ota.SupportedDevices[0]) {
				filteredOtas = append(filteredOtas, ota)
			}
		} else {
			filteredOtas = append(filteredOtas, ota)
		}
	}

	filteredOtas = o.filterOTADevices(filteredOtas)

	deviceList := make(map[string]string)
	for _, o := range filteredOtas {
		if len(o.SupportedDevices) == 1 && len(o.SupportedDeviceModels) == 1 {
			deviceList[o.SupportedDevices[0]] = o.SupportedDeviceModels[0]
		}
	}

	// for dev, model := range deviceList { FIXME: NOW
	// 	if ota, err := o.GetOtaForDevice(dev, model); err == nil {
	// 		outOTAs = append(outOTAs, ota)
	// 	}
	// }

	return filteredOtas
	// return outOTAs
}

func (o *Ota) getRequestAssetTypes() ([]assetType, error) {
	switch o.Config.Platform {
	case "ios":
		fallthrough
	case "watchos":
		fallthrough
	case "audioos":
		fallthrough
	case "tvos":
		return []assetType{softwareUpdate}, nil
	case "macos":
		return []assetType{macSoftwareUpdate}, nil
	case "recovery":
		return []assetType{recoveryOsSoftwareUpdate}, nil
	}
	return nil, fmt.Errorf("unsupported platform %s", o.Config.Platform)
}

func (o *Ota) getRequestAudienceIDs() ([]assetAudienceID, error) {
	switch o.Config.Platform {
	case "ios":
		if o.Config.Beta {
			if o.Config.Version != nil {
				segs := o.Config.Version.Segments()
				if len(segs) == 0 {
					return nil, fmt.Errorf("invalid version %s (must be in semver format; i.e. 1.1.1)", o.Config.Version)
				}
				switch segs[0] { // MAJOR
				case 0: // empty version
					return []assetAudienceID{iOS15DeveloperBeta}, nil
				case 11:
					return []assetAudienceID{iOS11Beta}, nil
				case 12:
					return []assetAudienceID{iOS12Beta}, nil
				case 13:
					return []assetAudienceID{iOS13Beta}, nil
				case 14:
					return []assetAudienceID{iOS14DeveloperBeta}, nil
				case 15:
					return []assetAudienceID{iOS15DeveloperBeta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 11.x, 12.x, 13.x, 14.x or 15.x)", o.Config.Version)
				}
			}
		} else {
			return []assetAudienceID{iOSRelease, iOS14SecurityUpdates}, nil
		}
	case "watchos":
		if o.Config.Beta {
			if o.Config.Version != nil {
				segs := o.Config.Version.Segments()
				if len(segs) == 0 {
					return nil, fmt.Errorf("invalid version %s (must be in semver format; i.e. 1.1.1)", o.Config.Version)
				}
				switch segs[0] { // MAJOR
				case 0: // empty version
					return []assetAudienceID{watchOS8Beta}, nil
				case 4:
					return []assetAudienceID{watchOS4Beta}, nil
				case 5:
					return []assetAudienceID{watchOS5Beta}, nil
				case 6:
					return []assetAudienceID{watchOS6Beta}, nil
				case 7:
					return []assetAudienceID{watchOS7Beta}, nil
				case 8:
					return []assetAudienceID{watchOS8Beta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 4.x, 5.x, 6.x, 7.x or 8.x)", o.Config.Version)
				}
			}
		} else {
			return []assetAudienceID{watchOSRelease}, nil
		}
	case "tvos":
		if o.Config.Beta {
			if o.Config.Version != nil {
				segs := o.Config.Version.Segments()
				if len(segs) == 0 {
					return nil, fmt.Errorf("invalid version %s (must be in semver format; i.e. 1.1.1)", o.Config.Version)
				}
				switch segs[0] { // MAJOR
				case 0: // empty version
					return []assetAudienceID{tvOS15Beta}, nil
				case 11:
					return []assetAudienceID{tvOS11Beta}, nil
				case 12:
					return []assetAudienceID{tvOS12Beta}, nil
				case 13:
					return []assetAudienceID{tvOS13Beta}, nil
				case 14:
					return []assetAudienceID{tvOS14Beta}, nil
				case 15:
					return []assetAudienceID{tvOS15Beta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 11.x, 12.x, 13.x, 14.x or 15.x)", o.Config.Version)
				}
			}
		} else {
			return []assetAudienceID{tvOSRelease}, nil
		}
	case "audioos":
		if o.Config.Beta {
			if o.Config.Version != nil {
				segs := o.Config.Version.Segments()
				if len(segs) == 0 {
					return nil, fmt.Errorf("invalid version %s (must be in semver format; i.e. 1.1.1)", o.Config.Version)
				}
				switch segs[0] { // MAJOR
				case 0: // empty version
					return []assetAudienceID{audioOS15Beta}, nil
				case 14:
					return []assetAudienceID{audioOS14Beta}, nil
				case 15:
					return []assetAudienceID{audioOS15Beta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 14.x or 15.x)", o.Config.Version)
				}
			}
		} else {
			return []assetAudienceID{audioOSRelease}, nil
		}
	case "recovery":
		fallthrough
	case "macos":
		if o.Config.Beta {
			if o.Config.Version != nil {
				segs := o.Config.Version.Segments()
				if len(segs) == 0 {
					return nil, fmt.Errorf("invalid version %s (must be in semver format; i.e. 1.1.1)", o.Config.Version)
				}
				switch segs[0] { // MAJOR
				case 0: // empty version
					return []assetAudienceID{macOS12DeveloperBeta, macOS12CustomerBeta, macOS12PublicBeta}, nil
				case 11:
					return []assetAudienceID{macOS11DeveloperBeta, macOS11CustomerBeta, macOS11PublicBeta}, nil
				case 12:
					return []assetAudienceID{macOS12DeveloperBeta, macOS12CustomerBeta, macOS12PublicBeta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 11.x, 12.x)", o.Config.Version)
				}
			}
		} else {
			return []assetAudienceID{macOSRelease}, nil
		}
	}
	return nil, fmt.Errorf("unsupported platform %s", o.Config.Platform)
}

func (o *Ota) getRequests(atype assetType, audienceID assetAudienceID, typ string) (reqs []pallasRequest, err error) {

	req := pallasRequest{
		ClientVersion:        clientVersion,
		AssetType:            atype,
		AssetAudience:        audienceID,
		ProductVersion:       o.Config.Version.Original(),
		BuildVersion:         o.Config.Build,
		CompatibilityVersion: 20,
	}

	if o.Config.Version.Original() != "0" {
		req.RequestedProductVersion = o.Config.Version.Original()
		req.Supervised = true
		req.DelayRequested = false
	}
	if o.Config.Beta && o.Config.Platform != "macos" {
		req.ReleaseType = "Beta"
	}
	if len(o.Config.Device) > 0 {
		req.ProductType = o.Config.Device
		if len(o.Config.Model) == 0 {
			model, err := o.lookupHWModel(o.Config.Device) // TODO: replace w/ internal DB
			if err != nil {
				return nil, err
			}
			req.HWModelStr = model
		} else {
			req.HWModelStr = o.Config.Model
		}
	} else if len(o.Config.Model) > 0 {
		req.HWModelStr = o.Config.Model
	} else {
		// var model string
		// devices := o.as.GetDevicesForVersion(o.Config.Version.Original(), typ)
		// if len(devices) == 0 {
		// 	req.RequestedProductVersion = o.as.Latest(typ, o.Config.Platform)
		// 	req.Supervised = true
		// 	req.DelayRequested = false
		// 	devices = o.as.GetDevicesForVersion(req.RequestedProductVersion, typ)
		// }
		// for _, device := range devices {
		// 	req.ProductType = device
		// 	model, err = o.lookupHWModel(device) // TODO: replace w/ internal DB
		// 	if err != nil {
		// 		// return nil, err
		// 		log.Debugf("failed to lookup model for device %s", device)
		// 		// continue
		// 	} else {
		// 		req.HWModelStr = model
		// 	}
		// 	reqNEW := req
		// 	reqs = append(reqs, reqNEW)
		// }
		// return reqs, nil
	}

	reqs = append(reqs, req)

	// if o.Config.Version != nil && len(o.Config.Device) == 0 {
	// 	var model string
	// 	devices := o.as.GetDevicesForVersion(o.Config.Version.Original(), typ)
	// 	if len(devices) == 0 {
	// 		devices = o.as.GetDevicesForVersion(o.as.Latest(typ), typ)
	// 	}
	// 	for _, device := range devices {
	// 		model, err = o.lookupHWModel(device) // TODO: replace w/ internal DB
	// 		if err != nil {
	// 			// return nil, err
	// 			log.Debugf("failed to lookup model for device %s", device)
	// 			continue
	// 		}
	// 		if o.Config.Beta {
	// 			reqs = append(reqs, pallasRequest{
	// 				ClientVersion:        clientVersion,
	// 				AssetType:            atype,
	// 				AssetAudience:        audienceID,
	// 				ProductType:          device,
	// 				HWModelStr:           model,
	// 				ProductVersion:       "0",
	// 				BuildVersion:         o.Config.Build,
	// 				CompatibilityVersion: 20,
	// 				ReleaseType:          "Beta",
	// 			})
	// 		} else {
	// 			reqs = append(reqs, pallasRequest{
	// 				ClientVersion:           clientVersion,
	// 				AssetType:               atype,
	// 				AssetAudience:           audienceID,
	// 				ProductType:             device,
	// 				HWModelStr:              model,
	// 				ProductVersion:          "0",
	// 				BuildVersion:            o.Config.Build,
	// 				RequestedProductVersion: o.Config.Version.Original(),
	// 				Supervised:              true,
	// 				DelayRequested:          false,
	// 				CompatibilityVersion:    20,
	// 			})
	// 		}
	// 	}
	// } else if o.Config.Version != nil && len(o.Config.Device) > 0 {
	// 	reqs = append(reqs, pallasRequest{
	// 		ClientVersion:           clientVersion,
	// 		AssetType:               atype,
	// 		AssetAudience:           audienceID,
	// 		ProductType:             o.Config.Device,
	// 		HWModelStr:              o.Config.Model,
	// 		ProductVersion:          o.Config.Version.Original(),
	// 		BuildVersion:            o.Config.Build,
	// 		RequestedProductVersion: o.Config.Version.Original(),
	// 		Supervised:              true,
	// 		DelayRequested:          false,
	// 		CompatibilityVersion:    20,
	// 	})
	// } else if o.Config.Version == nil && len(o.Config.Device) == 0 {
	// 	var model string
	// 	for _, device := range o.as.GetDevicesForVersion(o.as.Latest(typ), typ) {
	// 		model, err = o.lookupHWModel(device) // TODO: replace w/ internal DB
	// 		if err != nil {
	// 			// return nil, err
	// 			log.Debugf("failed to lookup model for device %s", device)
	// 			continue
	// 		}
	// 		reqs = append(reqs, pallasRequest{
	// 			ClientVersion:        clientVersion,
	// 			AssetType:            atype,
	// 			AssetAudience:        audienceID,
	// 			ProductType:          device,
	// 			HWModelStr:           model,
	// 			ProductVersion:       "0",
	// 			BuildVersion:         o.Config.Build,
	// 			CompatibilityVersion: 20,
	// 		})
	// 	}
	// } else {
	// 	reqs = append(reqs, pallasRequest{
	// 		ClientVersion:        clientVersion,
	// 		AssetType:            atype,
	// 		AssetAudience:        audienceID,
	// 		ProductType:          o.Config.Device,
	// 		HWModelStr:           o.Config.Model,
	// 		ProductVersion:       "0",
	// 		BuildVersion:         o.Config.Build,
	// 		CompatibilityVersion: 20,
	// 	})
	// }

	return reqs, nil
}

func (o *Ota) buildPallasRequests() (reqs []pallasRequest, err error) {

	assetTypes, err := o.getRequestAssetTypes()
	if err != nil {
		return nil, fmt.Errorf("failed to get asset types for requests: %v", err)
	}

	audienceIDs, err := o.getRequestAudienceIDs()
	if err != nil {
		return nil, fmt.Errorf("failed to get audience IDs for requests: %v", err)
	}

	for _, atype := range assetTypes {
		for _, audienceID := range audienceIDs {
			switch o.Config.Platform {
			case "ios":
				fallthrough
			case "watchos":
				fallthrough
			case "audioos":
				fallthrough
			case "tvos":
				rr, err := o.getRequests(atype, audienceID, "iOS")
				if err != nil {
					return nil, fmt.Errorf("failed to get %s pallas requests: %v", o.Config.Platform, err)
				}
				reqs = append(reqs, rr...)
			case "recovery":
				fallthrough
			case "macos":
				rr, err := o.getRequests(atype, audienceID, "macOS")
				if err != nil {
					return nil, fmt.Errorf("failed to get %s pallas requests: %v", o.Config.Platform, err)
				}
				reqs = append(reqs, rr...)
			}
		}
	}

	return reqs, nil
}

// GetPallasOTAs returns an OTA assets for a given config using the newstyle OTA - CREDIT: https://gist.github.com/Siguza/0331c183c8c59e4850cd0b62fd501424
func (o *Ota) GetPallasOTAs() ([]types.Asset, error) {
	var err error
	var oassets []types.Asset

	pallasReqs, err := o.buildPallasRequests()
	if err != nil {
		return nil, fmt.Errorf("failed to build the pallas requests: %v", err)
	}

	for _, pallasReq := range pallasReqs {

		jdata, err := json.Marshal(&pallasReq)
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequest("POST", pallasURL, bytes.NewBuffer(jdata))
		if err != nil {
			return nil, fmt.Errorf("failed to create https request: %v", err)
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
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			// log.Debugf("failed to connect to URL: got status %s", resp.Status)
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("failed to read response body: %v", err)
			continue
		}

		// repair/parse base64 response data
		parts := strings.Split(string(body), ".")
		b64Str := parts[1]
		b64Str = strings.ReplaceAll(b64Str, "-", "+")
		b64Str = strings.ReplaceAll(b64Str, "_", "/")

		// bas64 decode the results
		b64data, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(b64Str)
		if err != nil {
			log.Errorf("failed to base64 decode pallas response: %v", err)
			continue
		}

		res := ota{}
		if err := json.Unmarshal(b64data, &res); err != nil {
			log.Errorf("failed to unmarshall JSON: %v", err)
			continue
		}

		if len(res.Assets) == 0 {
			log.Debugf("no OTAs found for %s %s", pallasReq.ProductType, pallasReq.HWModelStr)
			continue
		}

		oassets = append(oassets, res.Assets...)
	}

	for idx, asset := range oassets { // TODO: what other BuildManifest fields should I capture?
		if asset.PreflightBuildManifest != nil {
			xzBuf := new(bytes.Buffer)
			xr, err := xz.NewReader(bytes.NewReader(asset.PreflightBuildManifest))
			if err != nil {
				return nil, err
			}
			io.Copy(xzBuf, xr)
			bm, err := info.ParseBuildManifest(xzBuf.Bytes())
			if err != nil {
				return nil, err
			}
			sort.Strings(bm.SupportedProductTypes)
			oassets[idx].SupportedDevices = bm.SupportedProductTypes
		}
	}

	oassets = uniqueOTAs(oassets)

	for _, oa := range oassets {
		log.Debug(oa.String())
	}

	return o.filterOTADevices(oassets), nil
}

func (o *Ota) lookupHWModel(device string) (string, error) {
	for _, ota := range o.Assets {
		if utils.StrSliceHas(ota.SupportedDevices, device) {
			if len(ota.SupportedDeviceModels) > 1 {
				return "0", fmt.Errorf("found more than one hw model for device %s", device)
			} else if len(ota.SupportedDeviceModels) == 0 {
				return "0", fmt.Errorf("device %s has 0 supported device models", device)
			}
			return ota.SupportedDeviceModels[0], nil
		}
	}
	return "0", fmt.Errorf("failed to find model for device %s in list of OTAs (please supply a --model)", device)
}

func uniqueOTAs(otas []types.Asset) []types.Asset {
	unique := make(map[string]bool, len(otas))
	os := make([]types.Asset, len(unique))
	for _, elem := range otas {
		if len(elem.BaseURL+elem.RelativePath) != 0 {
			if !unique[elem.BaseURL+elem.RelativePath] {
				os = append(os, elem)
				unique[elem.BaseURL+elem.RelativePath] = true
			}
		}
	}
	return os
}

func (o *Ota) filterOTADevices(otas []types.Asset) []types.Asset {
	var devices []string
	var filteredOtas []types.Asset

	for _, ota := range otas {
		devices = append(devices, ota.SupportedDeviceModels...)
	}
	devices = utils.Unique(devices)

	for _, device := range devices {
		var devOTA types.Asset
		for _, ota := range otas {
			if utils.StrSliceHas(ota.SupportedDeviceModels, device) {
				if devOTA.SupportedDevices == nil {
					if ota.DownloadSize > devOTA.DownloadSize {
						devOTA = ota
					}
				} else {
					devOTA = ota
				}
			}
		}
		filteredOtas = append(filteredOtas, devOTA)
	}

	return uniqueOTAs(filteredOtas)
}
