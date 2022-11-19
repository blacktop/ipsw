package download

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/types"
	ilist "github.com/blacktop/ipsw/pkg/plist"
	"github.com/hashicorp/go-version"
	"github.com/ulikunitz/xz"
	"golang.org/x/sync/errgroup"
)

const (
	clientVersion       = 2
	certIssuanceDay     = "2020-09-29"
	pallasURL           = "https://gdmf.apple.com/v2/assets"
	otaPublicURL        = "https://mesu.apple.com/assets/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS13OtaDevBetaURL  = "https://mesu.apple.com/assets/iOS13DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS13OtaPublicURL   = "https://mesu.apple.com/assets/iOS13PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	otaPublicWatchOSURL = "https://mesu.apple.com/assets/watch/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	// audioOS
	airPodsURL    = "https://mesu.apple.com/assets/com_apple_MobileAsset_MobileAccessoryUpdate_A2032_EA/com_apple_MobileAsset_MobileAccessoryUpdate_A2032_EA.xml"
	airPods3URL   = "https://mesu.apple.com/assets/com_apple_MobileAsset_MobileAccessoryUpdate_A2564_EA/com_apple_MobileAsset_MobileAccessoryUpdate_A2564_EA.xml"
	airPodsProURL = "https://mesu.apple.com/assets/com_apple_MobileAsset_MobileAccessoryUpdate_A2084_EA/com_apple_MobileAsset_MobileAccessoryUpdate_A2084_EA.xml"
	airTagsURL    = "https://mesu.apple.com/assets/com_apple_MobileAsset_MobileAccessoryUpdate_DurianFirmware/com_apple_MobileAsset_MobileAccessoryUpdate_DurianFirmware.xml"
	// Deprecated: URLs
	iOS14OtaDevBetaURL = "https://mesu.apple.com/assets/iOS14DeveloperSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
	iOS14OtaPublicURL  = "https://mesu.apple.com/assets/iOS14PublicSeed/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml"
)

type assetType string

const (
	softwareUpdate      assetType = "com.apple.MobileAsset.SoftwareUpdate"
	rsrUpdate           assetType = "com.apple.MobileAsset.SplatSoftwareUpdate"
	watchSoftwareUpdate assetType = "com.apple.MobileAsset.WatchSoftwareUpdateDocumentation"
	// For macOS devices
	macSoftwareUpdate        assetType = "com.apple.MobileAsset.MacSoftwareUpdate"
	recoveryOsSoftwareUpdate assetType = "com.apple.MobileAsset.SFRSoftwareUpdate"
	accessorySoftwareUpdate  assetType = "com.apple.MobileAsset.DarwinAccessoryUpdate.A2525"
)

type assetAudienceID string

const ( // CREDIT: Siguza
	iOSRelease           assetAudienceID = "01c1d682-6e8f-4908-b724-5501fe3f5e5c" // iOS release
	iOSUnknown           assetAudienceID = "0c88076f-c292-4dad-95e7-304db9d29d34" // iOS unknown
	iOSInternal          assetAudienceID = "ce9c2203-903b-4fb3-9f03-040dc2202694" // iOS internal (not publicly accessible)
	iOS11Beta            assetAudienceID = "b7580fda-59d3-43ae-9488-a81b825e3c73" // iOS 11 beta
	iOS12Beta            assetAudienceID = "ef473147-b8e7-4004-988e-0ae20e2532ef" // iOS 12 beta
	iOS13Beta            assetAudienceID = "d8ab8a45-ee39-4229-891e-9d3ca78a87ca" // iOS 13 beta
	iOS14CustomerBeta    assetAudienceID = "84da8706-e267-4554-8207-865ae0c3a120" // iOS 14 customer beta
	iOS14DeveloperBeta   assetAudienceID = "dbbb0481-d521-4cdf-a2a4-5358affc224b" // iOS 14 public beta
	iOS14SecurityUpdates assetAudienceID = "c724cb61-e974-42d3-a911-ffd4dce11eda" // iOS 14 security updates
	iOS15CustomerBeta    assetAudienceID = "a98cc469-7f15-4e60-aca5-11a26d60f1e7" // iOS 15 customer beta
	iOS15DeveloperBeta   assetAudienceID = "ce48f60c-f590-4157-a96f-41179ca08278" // iOS 15 developer beta
	iOS15PublicBeta      assetAudienceID = "9e12a7a5-36ac-4583-b4fb-484736c739a8" // iOS 15 public beta
	iOS16CustomerBeta    assetAudienceID = "817ce601-f365-4294-8982-b00f547bbe4a" // iOS 16 customer beta
	iOS16DeveloperBeta   assetAudienceID = "a6050bca-50d8-4e45-adc2-f7333396a42c" // iOS 16 developer beta
	iOS16PublicBeta      assetAudienceID = "7466521f-cc37-4267-8f46-78033fa700c2" // iOS 16 public beta

	tvOSRelease assetAudienceID = "356d9da0-eee4-4c6c-bbe5-99b60eadddf0" // tvOS release
	tvOS11Beta  assetAudienceID = "ebd90ea1-6216-4a7c-920e-666faccb2d50" // tvOS 11 beta (returns 404)
	tvOS12Beta  assetAudienceID = "5b220c65-fe50-460b-bac5-b6774b2ff475" // tvOS 12 beta
	tvOS13Beta  assetAudienceID = "975af5cb-019b-42db-9543-20327280f1b2" // tvOS 13 beta
	tvOS14Beta  assetAudienceID = "65254ac3-f331-4c19-8559-cbe22f5bc1a6" // tvOS 14 beta
	tvOS15Beta  assetAudienceID = "4d0dcdf7-12f2-4ebf-9672-ac4a4459a8bc" // tvOS 15 beta
	tvOS16Beta  assetAudienceID = "d6bac98b-9e2a-4f87-9aba-22c898b25d84" // tvOS 16 beta

	watchOSRelease assetAudienceID = "b82fcf9c-c284-41c9-8eb2-e69bf5a5269f" // watchOS release
	watchOS4Beta   assetAudienceID = "f659e06d-86a2-4bab-bcbb-61b7c60969ce" // watchOS 4 beta (returns 404)
	watchOS5Beta   assetAudienceID = "e841259b-ad2e-4046-b80f-ca96bc2e17f3" // watchOS 5 beta
	watchOS6Beta   assetAudienceID = "d08cfd47-4a4a-4825-91b5-3353dfff194f" // watchOS 6 beta
	watchOS7Beta   assetAudienceID = "ff6df985-3cbe-4d54-ba5f-50d02428d2a3" // watchOS 7 beta
	watchOS8Beta   assetAudienceID = "b407c130-d8af-42fc-ad7a-171efea5a3d0" // watchOS 8 beta
	watchOS9Beta   assetAudienceID = "341f2a17-0024-46cd-968d-b4444ec3699f" // watchOS 9 beta

	audioOSRelease assetAudienceID = "0322d49d-d558-4ddf-bdff-c0443d0e6fac" // audioOS release
	audioOS14Beta  assetAudienceID = "b05ddb59-b26d-4c89-9d09-5fda15e99207" // audioOS 14 beta
	audioOS15Beta  assetAudienceID = "58ff8d56-1d77-4473-ba88-ee1690475e40" // audioOS 15 beta
	audioOS16Beta  assetAudienceID = "59377047-7b3f-45b9-8e99-294c0daf3c85" // audioOS 16 beta

	macOSRelease         assetAudienceID = "60b55e25-a8ed-4f45-826c-c1495a4ccc65" // macOS release
	macOS11CustomerBeta  assetAudienceID = "215447a0-bb03-4e18-8598-7b6b6e7d34fd" // macOS 11 customer beta
	macOS11DeveloperBeta assetAudienceID = "ca60afc6-5954-46fd-8cb9-60dde6ac39fd" // macOS 11 developer beta
	macOS11PublicBeta    assetAudienceID = "902eb66c-8e37-451f-b0f2-ffb3e878560b" // macOS 11 public beta
	macOS12CustomerBeta  assetAudienceID = "a3799e8a-246d-4dee-b418-76b4519a15a2" // macOS 12 customer beta
	macOS12DeveloperBeta assetAudienceID = "298e518d-b45e-4d36-94be-34a63d6777ec" // macOS 12 developer beta
	macOS12PublicBeta    assetAudienceID = "9f86c787-7c59-45a7-a79a-9c164b00f866" // macOS 12 public beta
	macOS13CustomerBeta  assetAudienceID = "3c45c074-41be-4b5b-a511-8592336e6783" // macOS 13 customer beta
	macOS13DeveloperBeta assetAudienceID = "683e9586-8a82-4e5f-b0e7-767541864b8b" // macOS 13 developer beta
	macOS13PublicBeta    assetAudienceID = "800034a9-994c-4ecc-af4d-7b3b2ee0a5a6" // macOS 13 public beta

	displayIOSRelease assetAudienceID = macOSRelease         // studio display iOS release
	displayIOSBeta    assetAudienceID = macOS12DeveloperBeta // studio display iOS beta
)

// Ota is an OTA object
type Ota struct {
	ota
	as     *AssetSets
	db     *info.Devices
	Config OtaConf
}

// OtaConf is an OTA download configuration
type OtaConf struct {
	Platform        string
	Beta            bool
	RSR             bool
	Device          string
	Model           string
	Version         *version.Version
	Build           string
	DeviceWhiteList []string
	DeviceBlackList []string
	Proxy           string
	Insecure        bool
	TimeoutSeconds  time.Duration
}

type pallasRequest struct {
	ClientVersion           int             `json:"ClientVersion"`
	AssetType               assetType       `json:"AssetType"`
	AssetAudience           assetAudienceID `json:"AssetAudience"`
	CertIssuanceDay         string          `json:"CertIssuanceDay"`
	ProductType             string          `json:"ProductType"`
	HWModelStr              string          `json:"HWModelStr"`
	ProductVersion          string          `json:"ProductVersion"`
	BuildVersion            string          `json:"BuildVersion"`
	Build                   string          `json:"Build,omitempty"`
	RequestedProductVersion string          `json:"RequestedProductVersion,omitempty"`
	Supervised              bool            `json:"Supervised,omitempty"`
	DelayRequested          bool            `json:"DelayRequested,omitempty"`
	CompatibilityVersion    int             `json:"CompatibilityVersion,omitempty"`
	ReleaseType             string          `json:"ReleaseType,omitempty"`
	RestoreVersion          string          `json:"RestoreVersion,omitempty"`
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

	document, err := io.ReadAll(resp.Body)
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

	o.db, err = info.GetIpswDB()
	if err != nil {
		return nil, fmt.Errorf("failed to get ipsw db: %v", err)
	}

	return &o, nil
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
		return []assetType{softwareUpdate, rsrUpdate}, nil
	case "accessory":
		return []assetType{accessorySoftwareUpdate}, nil
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
					return []assetAudienceID{iOS16DeveloperBeta, iOS16CustomerBeta, iOS16PublicBeta}, nil
				case 11:
					return []assetAudienceID{iOS11Beta}, nil
				case 12:
					return []assetAudienceID{iOS12Beta}, nil
				case 13:
					return []assetAudienceID{iOS13Beta}, nil
				case 14:
					return []assetAudienceID{iOS14DeveloperBeta, iOS14CustomerBeta}, nil
				case 15:
					return []assetAudienceID{iOS15DeveloperBeta, iOS15CustomerBeta}, nil
				case 16:
					return []assetAudienceID{iOS16DeveloperBeta, iOS16CustomerBeta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 11.x, 12.x, 13.x, 14.x, 15.x or 16.x)", o.Config.Version)
				}
			}
		} else {
			return []assetAudienceID{iOSRelease, iOS14SecurityUpdates, displayIOSRelease}, nil
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
					return []assetAudienceID{watchOS9Beta}, nil
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
				case 9:
					return []assetAudienceID{watchOS9Beta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 4.x, 5.x, 6.x, 7.x, 8.x or 9.x)", o.Config.Version)
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
					return []assetAudienceID{tvOS16Beta}, nil
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
				case 16:
					return []assetAudienceID{tvOS16Beta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 11.x, 12.x, 13.x, 14.x, 15.x or 16.x)", o.Config.Version)
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
					return []assetAudienceID{audioOS16Beta}, nil
				case 14:
					return []assetAudienceID{audioOS14Beta}, nil
				case 15:
					return []assetAudienceID{audioOS15Beta}, nil
				case 16:
					return []assetAudienceID{audioOS16Beta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 14.x, 15.x or 16.x)", o.Config.Version)
				}
			}
		} else {
			return []assetAudienceID{audioOSRelease}, nil
		}
	case "accessory", "recovery", "macos":
		if o.Config.Beta {
			if o.Config.Version != nil {
				segs := o.Config.Version.Segments()
				if len(segs) == 0 {
					return nil, fmt.Errorf("invalid version %s (must be in semver format; i.e. 1.1.1)", o.Config.Version)
				}
				switch segs[0] { // MAJOR
				case 0: // empty version
					return []assetAudienceID{macOS13DeveloperBeta, macOS13CustomerBeta, macOS13PublicBeta, macOS12CustomerBeta}, nil
				case 11:
					return []assetAudienceID{macOS11DeveloperBeta, macOS11CustomerBeta, macOS11PublicBeta}, nil
				case 12:
					return []assetAudienceID{macOS12DeveloperBeta, macOS12CustomerBeta, macOS12PublicBeta}, nil
				case 13:
					return []assetAudienceID{macOS13DeveloperBeta, macOS13CustomerBeta, macOS13PublicBeta}, nil
				default:
					return nil, fmt.Errorf("invalid version %s (must be 11.x, 12.x or 13.x)", o.Config.Version)
				}
			}
		} else {
			return []assetAudienceID{macOSRelease}, nil
		}
	}
	return nil, fmt.Errorf("unsupported platform %s", o.Config.Platform)
}

func (o *Ota) getRequests(atype assetType, audienceID assetAudienceID) (reqs []pallasRequest, err error) {

	req := pallasRequest{
		ClientVersion: clientVersion,
		AssetType:     atype,
		AssetAudience: audienceID,
		// CertIssuanceDay:      certIssuanceDay,
		ProductVersion:       o.Config.Version.Original(),
		BuildVersion:         o.Config.Build,
		ProductType:          o.Config.Device,
		HWModelStr:           o.Config.Model,
		CompatibilityVersion: 20,
	}

	if o.Config.Version.Original() != "0" {
		req.RequestedProductVersion = o.Config.Version.Original()
		req.Supervised = true
		req.DelayRequested = false
	}

	if o.Config.Beta {
		switch o.Config.Platform {
		case "ios", "audioos", "tvos":
			req.ReleaseType = "Beta"
		}
	}

	if o.Config.RSR {
		req.RestoreVersion = "0.0.0.0.0,0"
		req.Build = o.Config.Build
	}

	if len(o.Config.Device) > 0 && len(o.Config.Model) == 0 {
		dev, err := o.db.LookupDevice(o.Config.Device)
		if err != nil {
			return nil, err
		}
		for model := range dev.Boards {
			req.HWModelStr = model
			reqNEW := req
			reqs = append(reqs, reqNEW)
		}
	} else if len(o.Config.Device) == 0 && len(o.Config.Model) > 0 {
		prod, err := o.db.GetProductForModel(o.Config.Model)
		if err != nil {
			return nil, err
		}
		req.ProductType = prod
		reqNEW := req
		reqs = append(reqs, reqNEW)
	} else if len(o.Config.Device) > 0 && len(o.Config.Model) > 0 {
		reqNEW := req
		reqs = append(reqs, reqNEW)
	} else {
		devices, err := o.db.GetDevicesForType(o.Config.Platform)
		if err != nil {
			return nil, err
		}
		for prod, dev := range *devices {
			req.ProductType = prod
			for model := range dev.Boards {
				req.HWModelStr = model
				reqNEW := req
				reqs = append(reqs, reqNEW)
			}
		}
	}

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
			rr, err := o.getRequests(atype, audienceID)
			if err != nil {
				return nil, fmt.Errorf("failed to get %s pallas requests: %v", o.Config.Platform, err)
			}
			reqs = append(reqs, rr...)
		}
	}

	return reqs, nil
}

func sendPostAsync(body []byte, rc chan *http.Response, config *OtaConf) error {
	req, err := http.NewRequest("POST", pallasURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create https request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("User-Agent", utils.RandomAgent())
	// req.Header.Add("User-Agent", "Configurator/2.15 (Macintosh; OS X 11.0.0; 16G29) AppleWebKit/2603.3.8")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(config.Proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
		},
		Timeout: config.TimeoutSeconds * time.Second,
	}

	resp, err := client.Do(req)
	if err == nil {
		rc <- resp
	}

	return err
}

// GetPallasOTAs returns an OTA assets for a given config using the newstyle OTA - CREDIT: https://gist.github.com/Siguza/0331c183c8c59e4850cd0b62fd501424
func (o *Ota) GetPallasOTAs() ([]types.Asset, error) {
	var err error
	var oassets []types.Asset

	pallasReqs, err := o.buildPallasRequests()
	if err != nil {
		return nil, fmt.Errorf("failed to build the pallas requests: %v", err)
	}

	rand.Seed(time.Now().UnixNano())
	c := make(chan *http.Response, 1)
	g, _ := errgroup.WithContext(context.Background())

	// perform async requests to pallas server
	for _, pallasReq := range pallasReqs {
		jdata, err := json.Marshal(&pallasReq)
		if err != nil {
			return nil, err
		}
		time.Sleep(time.Duration(rand.Intn(20)) * time.Millisecond)
		g.Go(func() error { return sendPostAsync(jdata, c, &o.Config) })
	}
	go func() {
		g.Wait()
		close(c)
	}()

	for resp := range c {

		if resp.StatusCode >= 500 {
			log.Debugf("[ERROR]\n%s", resp.Status)
			continue
		}

		body, err := io.ReadAll(resp.Body)
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

		if resp.StatusCode != 200 {
			log.Debugf("[ERROR]\n%s", string(b64data))
			continue
		}

		res := ota{}
		if err := json.Unmarshal(b64data, &res); err != nil {
			log.Errorf("failed to unmarshall JSON: %v", err)
			continue
		}

		if len(res.Assets) == 0 {
			continue
		}

		oassets = append(oassets, res.Assets...)

		resp.Body.Close()
	}

	if err := g.Wait(); err != nil {
		log.Errorf("failed to get pallas OTA assets (wait group error): %v", err)
		// return nil, fmt.Errorf("failed to get pallas OTA assets (wait group error): %v", err)
	}

	for idx, asset := range oassets { // TODO: what other BuildManifest fields should I capture?
		if asset.PreflightBuildManifest != nil {
			xzBuf := new(bytes.Buffer)
			xr, err := xz.NewReader(bytes.NewReader(asset.PreflightBuildManifest))
			if err != nil {
				return nil, err
			}
			io.Copy(xzBuf, xr)
			bm, err := ilist.ParseBuildManifest(xzBuf.Bytes())
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
	for idx, o := range os {
		for _, elem := range otas {
			if len(elem.BaseURL+elem.RelativePath) != 0 {
				if o.BaseURL+o.RelativePath == elem.BaseURL+elem.RelativePath {
					os[idx].SupportedDevices = utils.UniqueConcat(os[idx].SupportedDevices, elem.SupportedDevices)
					os[idx].SupportedDeviceModels = utils.UniqueConcat(os[idx].SupportedDeviceModels, elem.SupportedDeviceModels)
					if devs, err := utils.Zip(elem.SupportedDevices, elem.SupportedDeviceModels); err == nil {
						for _, dev := range devs {
							os[idx].Devices = utils.UniqueAppend(os[idx].Devices, fmt.Sprintf("%s_%s", dev.Device, dev.Model))
						}
					}
				}
			}
		}
	}
	return os
}

func (o *Ota) filterOTADevices(otas []types.Asset) []types.Asset { // FIXME: this is too strict and loses some OTAs (i.e. macOS)
	var devices []string
	var filteredDevices []string
	var filteredOtas []types.Asset

	if o.Config.Platform == "macos" {
		return otas
	}

	for _, o := range otas {
		devices = append(devices, o.SupportedDevices...)
	}

	devices = utils.Unique(devices)

	for _, device := range devices {
		if len(o.Config.DeviceWhiteList) > 0 {
			if utils.StrSliceHas(o.Config.DeviceWhiteList, device) {
				filteredDevices = append(filteredDevices, device)
			}
		} else if len(o.Config.DeviceBlackList) > 0 {
			if !utils.StrSliceHas(o.Config.DeviceBlackList, device) {
				filteredDevices = append(filteredDevices, device)
			}
		} else {
			filteredDevices = append(filteredDevices, device)
		}
	}

	for _, device := range filteredDevices {
		for _, ota := range otas {
			if utils.StrSliceHas(ota.SupportedDevices, device) {
				filteredOtas = append(filteredOtas, ota)
			}
		}
	}

	return uniqueOTAs(filteredOtas)
}
