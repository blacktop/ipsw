package download

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/types"
	ilist "github.com/blacktop/ipsw/pkg/plist"
	"github.com/hashicorp/go-version"
	semver "github.com/hashicorp/go-version"
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

//go:embed data/audiences.gz
var audienceData []byte // CREDIT: Siguza
/* NOTE: to find these values grep the symbols in the SoftwareUpdateSettingsUI dylib that start with "
 * _MA_PALLAS_AUDIENCE_CUSTOMER_" and read the address there to get the CFString value */
type assetType string

const (
	softwareUpdate      assetType = "com.apple.MobileAsset.SoftwareUpdate"
	rsrUpdate           assetType = "com.apple.MobileAsset.SplatSoftwareUpdate"
	watchSoftwareUpdate assetType = "com.apple.MobileAsset.WatchSoftwareUpdateDocumentation"
	recoveryOSUpdate    assetType = "com.apple.MobileAsset.RecoveryOSUpdate"
	// For macOS devices
	macSoftwareUpdate        assetType = "com.apple.MobileAsset.MacSoftwareUpdate"
	macRsrUpdate             assetType = "com.apple.MobileAsset.MacSplatSoftwareUpdate"
	recoveryOsSoftwareUpdate assetType = "com.apple.MobileAsset.SFRSoftwareUpdate"
	accessorySoftwareUpdate  assetType = "com.apple.MobileAsset.DarwinAccessoryUpdate.A2525"
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
	Timeout         time.Duration
}

type pallasRequest struct {
	ClientVersion           int       `json:"ClientVersion"`
	AssetType               assetType `json:"AssetType"`
	AssetAudience           string    `json:"AssetAudience"`
	CertIssuanceDay         string    `json:"CertIssuanceDay"`
	ProductType             string    `json:"ProductType"`
	HWModelStr              string    `json:"HWModelStr"`
	ProductVersion          string    `json:"ProductVersion"`
	BuildVersion            string    `json:"BuildVersion"`
	Build                   string    `json:"Build,omitempty"`
	RequestedProductVersion string    `json:"RequestedProductVersion,omitempty"`
	Supervised              bool      `json:"Supervised,omitempty"`
	DelayRequested          bool      `json:"DelayRequested,omitempty"`
	CompatibilityVersion    int       `json:"CompatibilityVersion,omitempty"`
	ReleaseType             string    `json:"ReleaseType,omitempty"`
	RestoreVersion          string    `json:"RestoreVersion,omitempty"`
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

// AssetAudienceIDs is a collection of OTA asset audience IDs
type AssetAudienceIDs map[string]AssetAudienceID

func (a AssetAudienceIDs) GetVersions(platform string) []string {
	var versions []string
	for version := range a[platform].Versions {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool {
		in, _ := strconv.Atoi(versions[i])
		jn, _ := strconv.Atoi(versions[j])
		return in < jn
	})
	return versions
}

func (a AssetAudienceIDs) LatestVersion(platform string) string {
	var versions []int
	for version, _ := range a[platform].Versions {
		i, err := strconv.Atoi(version)
		if err != nil {
			continue
		}
		versions = append(versions, i)
	}
	sort.Ints(versions)
	if len(versions) == 0 {
		return ""
	}
	return strconv.Itoa(versions[len(versions)-1])
}

// AssetAudienceID is an OTA asset audience ID
type AssetAudienceID struct {
	Release  string `json:"release"`
	Generic  string `json:"generic"`
	Versions map[string]struct {
		DeveloperBeta string `json:"developer-beta,omitempty"`
		AppleSeedBeta string `json:"appleseed-beta,omitempty"`
		PublicBeta    string `json:"public-beta,omitempty"`
	}
}

func GetAssetAudienceIDs() (AssetAudienceIDs, error) {
	var db AssetAudienceIDs

	zr, err := gzip.NewReader(bytes.NewReader(audienceData))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	if err := json.NewDecoder(zr).Decode(&db); err != nil {
		return nil, fmt.Errorf("failed unmarshaling audiences data: %w", err)
	}

	return db, nil
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

func (o *Ota) GetLatest() *semver.Version {
	latest := o.as.LatestVersion(o.Config.Platform)
	ver, err := semver.NewVersion(strings.TrimPrefix(latest, "9.9."))
	if err != nil {
		return nil
	}
	return ver
}

// QueryPublicXML queries the public XML for OTA assets that match the config
func (o *Ota) QueryPublicXML() []types.Asset {
	var filtered []types.Asset
	if o.Config.Version.Original() == "0" && o.Config.Build == "0" {
		if latest := o.GetLatest(); latest != nil {
			o.Config.Version = latest
		}
	}
	for _, asset := range o.Assets {
		if !strings.EqualFold(o.Config.Platform, asset.ProductSystemName) {
			continue
		}
		if o.Config.Beta && asset.ReleaseType != "Beta" {
			continue
		}
		if o.Config.Version.Original() != "0" {
			if ver, err := semver.NewVersion(strings.TrimPrefix(asset.OSVersion, "9.9.")); err == nil {
				if !o.Config.Version.Equal(ver) {
					continue
				}
			}
		}
		if o.Config.Build != "0" {
			if !strings.EqualFold(o.Config.Build, asset.Build) {
				continue
			}
		}
		if len(o.Config.Device) > 0 {
			if !slices.Contains(asset.SupportedDevices, o.Config.Device) {
				continue
			}
		}
		if len(o.Config.Model) > 0 {
			if !slices.Contains(asset.SupportedDeviceModels, o.Config.Model) {
				continue
			}
		}
		filtered = append(filtered, asset)
	}
	return uniqueOTAs(filtered)
}

func (o *Ota) getRequestAssetTypes() ([]assetType, error) {
	switch o.Config.Platform {
	case "ios", "watchos", "audioos", "tvos", "visionos":
		if o.Config.RSR {
			return []assetType{rsrUpdate}, nil
		}
		if o.Config.Platform == "ios" {
			return []assetType{softwareUpdate}, nil
		}
		return []assetType{recoveryOSUpdate, softwareUpdate}, nil
	case "accessory":
		return []assetType{accessorySoftwareUpdate}, nil
	case "macos":
		if o.Config.RSR {
			return []assetType{macRsrUpdate}, nil
		}
		return []assetType{macSoftwareUpdate}, nil
	case "recovery":
		return []assetType{recoveryOsSoftwareUpdate}, nil
	}
	return nil, fmt.Errorf("unsupported platform %s", o.Config.Platform)
}

func (o *Ota) getRequestAudienceIDs() ([]string, error) {
	assetAudienceDB, err := GetAssetAudienceIDs()
	if err != nil {
		return nil, err
	}

	switch o.Config.Platform {
	case "accessory", "recovery", "macos":
		if o.Config.Beta {
			if o.Config.Version != nil {
				segs := o.Config.Version.Segments()
				if len(segs) == 0 {
					return nil, fmt.Errorf("invalid version %s (must be in semver format; i.e. 1.1.1)", o.Config.Version)
				}
				if segs[0] == 0 { // empty version
					latest := assetAudienceDB.LatestVersion("macos")
					return []string{
						assetAudienceDB["macos"].Versions[latest].DeveloperBeta,
						assetAudienceDB["macos"].Versions[latest].AppleSeedBeta,
						assetAudienceDB["macos"].Versions[latest].PublicBeta,
						assetAudienceDB["macos"].Generic}, nil
				}
				if o.Config.Platform == "accessory" {
					// looup major version in DB
					if v, ok := assetAudienceDB["ios"].Versions[strconv.Itoa(segs[0])]; ok {
						return []string{
							v.DeveloperBeta,
							v.AppleSeedBeta,
							v.PublicBeta}, nil
					}
				} else {
					// looup major version in DB
					if v, ok := assetAudienceDB["macos"].Versions[strconv.Itoa(segs[0])]; ok {
						return []string{
							v.DeveloperBeta,
							v.AppleSeedBeta,
							v.PublicBeta}, nil
					}
				}

				return nil, fmt.Errorf(
					"invalid version %s (must be one of %s)",
					o.Config.Version,
					strings.Join(utils.StrSliceAddSuffix(assetAudienceDB.GetVersions("macos"), ".x"), ", "))
			}
		} else {
			return []string{assetAudienceDB["macos"].Release, assetAudienceDB["macos"].Generic}, nil
		}
	default:
		if o.Config.Beta {
			if o.Config.Version != nil {
				segs := o.Config.Version.Segments()
				if len(segs) == 0 {
					return nil, fmt.Errorf("invalid version %s (must be in semver format; i.e. 1.1.1)", o.Config.Version)
				}
				if segs[0] == 0 { // empty version
					latest := assetAudienceDB.LatestVersion(o.Config.Platform)
					if latest == "" {
						return []string{
							assetAudienceDB[o.Config.Platform].Release,
							assetAudienceDB[o.Config.Platform].Generic}, nil
					}
					return []string{
						assetAudienceDB[o.Config.Platform].Versions[latest].DeveloperBeta,
						assetAudienceDB[o.Config.Platform].Versions[latest].AppleSeedBeta,
						assetAudienceDB[o.Config.Platform].Versions[latest].PublicBeta,
						assetAudienceDB[o.Config.Platform].Generic}, nil
				}
				// looup major version in DB
				if v, ok := assetAudienceDB[o.Config.Platform].Versions[strconv.Itoa(segs[0])]; ok {
					return []string{
						v.DeveloperBeta,
						v.AppleSeedBeta,
						v.PublicBeta}, nil
				} else {
					return nil, fmt.Errorf(
						"invalid version %s (must be one of %s)",
						o.Config.Version,
						strings.Join(utils.StrSliceAddSuffix(assetAudienceDB.GetVersions(o.Config.Platform), ".x"), ", "))
				}
			}
		} else {
			return []string{assetAudienceDB[o.Config.Platform].Release, assetAudienceDB[o.Config.Platform].Generic}, nil
		}
	}
	return nil, fmt.Errorf("unsupported platform %s", o.Config.Platform)
}

func (o *Ota) getRequests(atype assetType, audienceID string) (reqs []pallasRequest, err error) {

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
		case "ios", "audioos", "tvos", "visionos":
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
			if len(audienceID) > 0 {
				rr, err := o.getRequests(atype, audienceID)
				if err != nil {
					return nil, fmt.Errorf("failed to get %s pallas requests: %v", o.Config.Platform, err)
				}
				reqs = append(reqs, rr...)
			}
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
		Timeout: config.Timeout * time.Second,
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

	oassets := o.QueryPublicXML()

	pallasReqs, err := o.buildPallasRequests()
	if err != nil {
		return nil, fmt.Errorf("failed to build the pallas requests: %v", err)
	}

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
		if len(parts) < 2 {
			log.Errorf("failed to base64 decode pallas response: cannot split response body \"%s\" ", string(body))
			continue
		}
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
							os[idx].Devices = utils.UniqueAppend(os[idx].Devices, fmt.Sprintf("%s_%s", dev.First, dev.Second))
						}
						sort.Strings(os[idx].Devices)
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
		if o.Config.Build != "0" && !o.Config.RSR {
			for _, ota := range otas {
				if strings.EqualFold(ota.Build, o.Config.Build) {
					filteredOtas = append(filteredOtas, ota)
				}
			}
			return filteredOtas
		}
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
