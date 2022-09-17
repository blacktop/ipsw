package download

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/info"
)

// NOTES:
// - https://github.com/Neal/savethemblobs
// - https://github.com/tihmstar/tsschecker
// - https://www.theiphonewiki.com/wiki/SHSH
// - https://www.theiphonewiki.com/wiki/SHSH_Protocol
// - https://tsssaver.1conan.com/v2/
// - https://api.ineal.me/tss/docs

const tssURL = "https://gs.apple.com/TSS/controller?action=2"

type manifest struct {
	Digest      []byte `plist:"Digest,omitempty"`
	BuildString string `plist:"BuildString,omitempty"`
	EPRO        bool   // = true
	ESEC        bool   // = true
	Trusted     bool
}

type manifests map[string]manifest

// TSSRequest is the tss apticket request plist object
type TSSRequest struct {
	ApImg4Ticket              bool   `plist:"@ApImg4Ticket,omitempty"`
	BBTicket                  bool   `plist:"@BBTicket,omitempty"`
	HostPlatformInfo          string `plist:"@HostPlatformInfo,omitempty"`
	Locality                  string `plist:"@Locality,omitempty"`
	VersionInfo               string `plist:"@VersionInfo,omitempty"` // = libauthinstall-850.0.1.0.1 ( /usr/lib/libauthinstall.dylib)
	ApBoardID                 int    `plist:"ApBoardID,omitempty"`
	ApChipID                  int    `plist:"ApChipID,omitempty"`
	ApECID                    int    `plist:"ApECID,omitempty"`
	ApNonce                   []byte `plist:"ApNonce,omitempty"`
	ApProductionMode          bool   `plist:"ApProductionMode,omitempty"`
	ApSecurityDomain          int    `plist:"ApSecurityDomain,omitempty"` // = 1
	ApSecurityMode            bool   `plist:"ApSecurityMode,omitempty"`
	PearlCertificationRootPub []byte `plist:"PearlCertificationRootPub,omitempty"`
	UniqueBuildID             []byte `plist:"UniqueBuildID,omitempty"`
	SepNonce                  []byte `plist:"SepNonce,omitempty"`
	// all the various manifest parts
	// AOP                             manifest `plist:"AOP,omitempty"`
	// ApSystemVolumeCanonicalMetadata manifest `plist:"Ap,SystemVolumeCanonicalMetadata,omitempty"`
	// AppleLogo                       manifest `plist:"AppleLogo,omitempty"`
	// AudioCodecFirmware              manifest `plist:"AudioCodecFirmware,omitempty"`
	// AVE                             manifest `plist:"AVE,omitempty"`
	// BatteryCharging0                manifest `plist:"BatteryCharging0,omitempty"`
	// BatteryCharging1                manifest `plist:"BatteryCharging1,omitempty"`
	// BatteryFull                     manifest `plist:"BatteryFull,omitempty"`
	// BatteryLow0                     manifest `plist:"BatteryLow0,omitempty"`
	// BatteryLow1                     manifest `plist:"BatteryLow1,omitempty"`
	// BatteryPlugin                   manifest `plist:"BatteryPlugin,omitempty"`
	// DeviceTree                      manifest `plist:"DeviceTree,omitempty"`
	// Ftap                            manifest `plist:"ftap,omitempty"`
	// Ftsp                            manifest `plist:"ftsp,omitempty"`
	// IBEC                            manifest `plist:"iBEC,omitempty"`
	// IBoot                           manifest `plist:"iBoot,omitempty"`
	// IBSS                            manifest `plist:"iBSS,omitempty"`
	// ISP                             manifest `plist:"ISP,omitempty"`
	// KernelCache                     manifest `plist:"KernelCache,omitempty"`
	// Liquid                          manifest `plist:"Liquid,omitempty"`
	// LLB                             manifest `plist:"LLB,omitempty"`
	// Multitouch                      manifest `plist:"Multitouch,omitempty"`
	// OS                              manifest `plist:"OS,omitempty"`
	// RecoveryMode                    manifest `plist:"RecoveryMode,omitempty"`
	// RestoreDeviceTree               manifest `plist:"RestoreDeviceTree,omitempty"`
	// RestoreKernelCache              manifest `plist:"RestoreKernelCache,omitempty"`
	// RestoreLogo                     manifest `plist:"RestoreLogo,omitempty"`
	// RestoreRAMDisk                  manifest `plist:"RestoreRamDisk,omitempty"`
	// RestoreSEP                      manifest `plist:"RestoreSEP,omitempty"`
	// RestoreTrustCache               manifest `plist:"RestoreTrustCache,omitempty"`
	// Rfta                            manifest `plist:"rfta,omitempty"`
	// Rfts                            manifest `plist:"rfts,omitempty"`
	// SEP                             manifest `plist:"SEP,omitempty"`
	// StaticTrustCache                manifest `plist:"StaticTrustCache,omitempty"`
	// SystemVolume                    manifest `plist:"SystemVolume,omitempty"`
}

type tssResponse struct {
	Status  int
	Message string
	Plist   string
}

// TSSBlob is the TSS response blob with ApImg4Ticket
type TSSBlob struct {
	ServerVersion string `plist:"@ServerVersion,omitempty"`
	ApImg4Ticket  []byte `plist:"ApImg4Ticket,omitempty"`
}

func randomHex(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func randomHexStr(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// GetTSS returns shsh blob
func GetTSS(version, proxy string, insecure bool) (*TSSBlob, error) {

	sepNonce, err := randomHex(20)
	if err != nil {
		return nil, err
	}

	apNonce, err := randomHex(32)
	if err != nil {
		return nil, err
	}

	build, err := GetBuildID(version, "iPhone10,3")
	if err != nil {
		return nil, err
	}

	ipsw, err := GetIPSW("iPhone10,3", build)
	zr, err := NewRemoteZipReader(ipsw.URL, &RemoteConfig{
		Proxy:    proxy,
		Insecure: insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote ipsw: %v", err)
	}

	info, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote ipsw info: %v", err)
	}

	tssReq := TSSRequest{
		ApImg4Ticket:              true,
		BBTicket:                  true,
		HostPlatformInfo:          "mac",
		Locality:                  "en_US",
		VersionInfo:               "libauthinstall-850.0.1.0.1",
		ApBoardID:                 6,                // device.ApBoardID
		ApChipID:                  32789,            // device.ApChipID
		ApECID:                    6303405673529390, // device.ApECID
		ApNonce:                   apNonce,          // device.ApNonce
		ApProductionMode:          true,             // device.EPRO
		ApSecurityDomain:          1,                // device.ApSecurityDomain
		ApSecurityMode:            true,             // device.ESEC
		SepNonce:                  sepNonce,
		UniqueBuildID:             info.Plists.BuildManifest.BuildIdentities[1].UniqueBuildID,
		PearlCertificationRootPub: info.Plists.BuildManifest.BuildIdentities[1].PearlCertificationRootPub,
		// AOP:                             manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["AOP"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// ApSystemVolumeCanonicalMetadata: manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["Ap,SystemVolumeCanonicalMetadata"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// AppleLogo:                       manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["AppleLogo"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// AudioCodecFirmware:              manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["AudioCodecFirmware"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// AVE:                             manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["AVE"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// BatteryCharging0:                manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["BatteryCharging0"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// BatteryCharging1:                manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["BatteryCharging1"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// BatteryFull:                     manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["BatteryFull"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// BatteryLow0:                     manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["BatteryLow0"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// BatteryLow1:                     manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["BatteryLow1"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// BatteryPlugin:                   manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["BatteryPlugin"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// DeviceTree:                      manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["DeviceTree"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// Ftap:                            manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["ftap"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// Ftsp:                            manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["ftsp"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// IBEC:                            manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["iBEC"].Digest, EPRO: true, ESEC: true, Trusted: true, BuildString: info.Plists.BuildManifest.BuildIdentities[1].Manifest["iBEC"].BuildString},
		// IBoot:                           manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["iBoot"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// IBSS:                            manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["iBSS"].Digest, EPRO: true, ESEC: true, Trusted: true, BuildString: info.Plists.BuildManifest.BuildIdentities[1].Manifest["iBSS"].BuildString},
		// ISP:                             manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["ISP"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// KernelCache:                     manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["KernelCache"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// Liquid:                          manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["Liquid"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// LLB:                             manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["LLB"].Digest, EPRO: true, ESEC: true, Trusted: true, BuildString: info.Plists.BuildManifest.BuildIdentities[1].Manifest["LLB"].BuildString},
		// Multitouch:                      manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["Multitouch"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// OS:                              manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["OS"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// RecoveryMode:                    manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["RecoveryMode"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// RestoreDeviceTree:               manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["RestoreDeviceTree"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// RestoreKernelCache:              manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["RestoreKernelCache"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// RestoreLogo:                     manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["RestoreLogo"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// RestoreRAMDisk:                  manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["RestoreRamDisk"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// RestoreSEP:                      manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["RestoreSEP"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// RestoreTrustCache:               manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["RestoreTrustCache"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// Rfta:                            manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["rfta"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// Rfts:                            manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["rfts"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// SEP:                             manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["SEP"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// StaticTrustCache:                manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["StaticTrustCache"].Digest, EPRO: true, ESEC: true, Trusted: true},
		// SystemVolume:                    manifest{Digest: info.Plists.BuildManifest.BuildIdentities[1].Manifest["SystemVolume"].Digest, EPRO: true, ESEC: true, Trusted: true},
	}

	tdata, err := plist.Marshal(tssReq, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", tssURL, bytes.NewBuffer(tdata))
	if err != nil {
		return nil, fmt.Errorf("failed to create https request: %v", err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-type", "text/xml; charset=\"utf-8\"")
	req.Header.Add("User-Agent", "InetURL/1.0")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to connect to URL: got status %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var tr tssResponse

	respFields := strings.Split(string(body), "&")
	for _, field := range respFields {
		keyValue := strings.SplitN(field, "=", 2)
		switch keyValue[0] {
		case "STATUS":
			sInt, err := strconv.Atoi(keyValue[1])
			if err != nil {
				return nil, err
			}
			tr.Status = sInt
		case "MESSAGE":
			tr.Message = keyValue[1]
		case "REQUEST_STRING":
			tr.Plist = keyValue[1]
		}
	}

	log.WithFields(log.Fields{
		"status":      tr.Status,
		"message":     tr.Message,
		"request_len": len(tr.Plist),
	}).Debug("TSS Response")

	if tr.Status == 0 && tr.Message == "SUCCESS" {
		var blob TSSBlob
		if err := plist.NewDecoder(strings.NewReader(tr.Plist)).Decode(&blob); err != nil {
			return nil, fmt.Errorf("failed to decode TSS request string: %v", err)
		}
		// TODO: parse response body as plist and get `ApImg4Ticket`
		return &blob, nil
	}

	return nil, fmt.Errorf("version %s is no longer being signed: %s (status=%d)", version, tr.Message, tr.Status)
}
