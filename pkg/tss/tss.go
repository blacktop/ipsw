package tss

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/download"
	info "github.com/blacktop/ipsw/pkg/plist"
	"github.com/google/uuid"
	"github.com/mitchellh/mapstructure"
)

// NOTES:
// - https://github.com/Neal/savethemblobs
// - https://github.com/tihmstar/tsschecker
// - https://www.theiphonewiki.com/wiki/SHSH
// - https://www.theiphonewiki.com/wiki/SHSH_Protocol
// - https://tsssaver.1conan.com/v2/
// - https://api.ineal.me/tss/docs

const (
	tssControllerActionURL = "http://gs.apple.com/TSS/controller?action=2"
	tssClientVersion       = "libauthinstall-973.0.1"
)

// Request is the request sent to the TSS server
type Request struct {
	UUID                      string `plist:"@UUID,omitempty" mapstructure:"@UUID,omitempty"`
	ApImg4Ticket              bool   `plist:"@ApImg4Ticket,omitempty" mapstructure:"@ApImg4Ticket,omitempty"`
	BBTicket                  bool   `plist:"@BBTicket,omitempty" mapstructure:"@BBTicket,omitempty"`
	HostPlatformInfo          string `plist:"@HostPlatformInfo,omitempty" mapstructure:"@HostPlatformInfo,omitempty"`
	Locality                  string `plist:"@Locality,omitempty" mapstructure:"@Locality,omitempty"`
	VersionInfo               string `plist:"@VersionInfo,omitempty" mapstructure:"@VersionInfo,omitempty"` // = libauthinstall-850.0.1.0.1 (/usr/lib/libauthinstall.dylib)
	ApBoardID                 uint64 `plist:"ApBoardID,omitempty" mapstructure:"ApBoardID,omitempty"`
	ApChipID                  uint64 `plist:"ApChipID,omitempty" mapstructure:"ApChipID,omitempty"`
	ApECID                    uint64 `plist:"ApECID,omitempty" mapstructure:"ApECID,omitempty"`
	ApNonce                   []byte `plist:"ApNonce,omitempty" mapstructure:"ApNonce,omitempty"`
	ApProductionMode          bool   `plist:"ApProductionMode,omitempty" mapstructure:"ApProductionMode,omitempty"`
	ApSecurityDomain          int    `plist:"ApSecurityDomain,omitempty" mapstructure:"ApSecurityDomain,omitempty"` // = 1
	ApSecurityMode            bool   `plist:"ApSecurityMode,omitempty" mapstructure:"ApSecurityMode,omitempty"`
	ApSupportsImg4            bool   `plist:"ApSupportsImg4,omitempty" mapstructure:"ApSupportsImg4,omitempty"`
	PearlCertificationRootPub []byte `plist:"PearlCertificationRootPub,omitempty" mapstructure:"PearlCertificationRootPub,omitempty"`
	UniqueBuildID             []byte `plist:"UniqueBuildID,omitempty" mapstructure:"UniqueBuildID,omitempty"`
	SepNonce                  []byte `plist:"SepNonce,omitempty" mapstructure:"SepNonce,omitempty"`
	UIDMode                   bool   `plist:"UID_MODE" mapstructure:"UID_MODE"`
	// Personalize
	LoadableTrustCache info.IdentityManifest `plist:"LoadableTrustCache,omitempty" mapstructure:"LoadableTrustCache,omitempty"`
	PersonalizedDMG    info.IdentityManifest `plist:"PersonalizedDMG,omitempty" mapstructure:"PersonalizedDMG,omitempty"`
}

// Response is the response from the TSS server
type Response struct {
	Status  int
	Message string
	Plist   string
}

// Blob is the TSS response blob with ApImg4Ticket
type Blob struct {
	ServerVersion    string `plist:"@ServerVersion,omitempty"`
	ApImg4Ticket     []byte `plist:"ApImg4Ticket,omitempty"`
	BBTicket         []byte `plist:"BBTicket,omitempty"`
	BasebandFirmware struct {
		MiscHashTableBodyBlob        []byte `plist:"Misc-HashTableBody-Blob,omitempty"`
		RestoreSbl1HashTableBodyBlob []byte `plist:"RestoreSBL1-HashTableBody-Blob,omitempty"`
		Sbl1HashTableBodyBlob        []byte `plist:"SBL1-HashTableBody-Blob,omitempty"`
	}
	EUICCTicket []byte `plist:"eUICC,Ticket,omitempty"`
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

func getApImg4Ticket(payload io.Reader, proxy string, insecure bool) (*Blob, error) {
	req, err := http.NewRequest("POST", tssControllerActionURL, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to create https request: %v", err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-type", "text/xml; charset=\"utf-8\"")
	req.Header.Add("User-Agent", "InetURL/1.0")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(proxy),
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

	var tr Response
	for _, field := range strings.Split(string(body), "&") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			log.Error("failed to parse response field")
			continue
		}
		switch key {
		case "STATUS":
			sInt, err := strconv.Atoi(value)
			if err != nil {
				return nil, err
			}
			tr.Status = sInt
		case "MESSAGE":
			tr.Message = value
		case "REQUEST_STRING":
			tr.Plist = value
		}
	}

	log.WithFields(log.Fields{
		"status":      tr.Status,
		"message":     tr.Message,
		"request_len": len(tr.Plist),
	}).Debug("TSS Response")

	if tr.Status == 0 && tr.Message == "SUCCESS" {
		var blob Blob
		if err := plist.NewDecoder(strings.NewReader(tr.Plist)).Decode(&blob); err != nil {
			return nil, fmt.Errorf("failed to decode TSS response REQUEST_STRING: %v", err)
		}
		return &blob, nil
	}

	return nil, fmt.Errorf("failed to personalize TSS blob: %s", tr.Message)
}

// Config represents the configuration for a TSS request.
type Config struct {
	Device          string
	Version         string
	Build           string
	ApNonce         []byte
	SepNonce        []byte
	ECID            uint64
	Image4Supported bool
	Proxy           string
	Insecure        bool
}

// GetTSSResponse retrieves a TSS response for the given configuration.
func GetTSSResponse(conf *Config) ([]byte, error) {
	var err error

	if len(conf.ApNonce) == 0 {
		conf.ApNonce, err = randomHex(32)
		if err != nil {
			return nil, err
		}
	}
	if len(conf.SepNonce) == 0 {
		conf.SepNonce, err = randomHex(20)
		if err != nil {
			return nil, err
		}
	}

	if conf.Build == "" {
		conf.Build, err = download.GetBuildID(conf.Version, conf.Device)
		if err != nil {
			return nil, err
		}
	}

	ipsw, err := download.GetIPSW(conf.Device, conf.Build)
	zr, err := download.NewRemoteZipReader(ipsw.URL, &download.RemoteConfig{
		Proxy:    conf.Proxy,
		Insecure: conf.Insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote ipsw: %v", err)
	}

	info, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return nil, fmt.Errorf("failed to parse remote ipsw info: %v", err)
	}

	tssReq := Request{
		UUID:                      uuid.New().String(),
		ApImg4Ticket:              true,
		BBTicket:                  true,
		HostPlatformInfo:          "mac",
		Locality:                  "en_US",
		VersionInfo:               tssClientVersion,
		ApBoardID:                 6,                // device.ApBoardID
		ApChipID:                  32789,            // device.ApChipID
		ApECID:                    6303405673529390, // device.ApECID
		ApNonce:                   conf.ApNonce,     // device.ApNonce
		ApProductionMode:          true,             // device.EPRO
		ApSecurityDomain:          1,                // device.ApSecurityDomain
		SepNonce:                  conf.SepNonce,
		UniqueBuildID:             info.BuildManifest.BuildIdentities[1].UniqueBuildID,
		PearlCertificationRootPub: info.BuildManifest.BuildIdentities[1].PearlCertificationRootPub,
	}

	if conf.Image4Supported {
		tssReq.ApSecurityMode = true
		tssReq.ApSupportsImg4 = true
	} else {
		tssReq.ApSupportsImg4 = false
	}

	trdata, err := plist.Marshal(tssReq, plist.XMLFormat)
	if err != nil {
		return nil, err
	}
	// os.WriteFile("/tmp/tss.plist", trdata, 0644)

	blob, err := getApImg4Ticket(bytes.NewReader(trdata), conf.Proxy, conf.Insecure)
	if err != nil {
		return nil, err
	}

	plistData, err := plist.Marshal(blob, plist.XMLFormat)
	if err != nil {
		return nil, err
	}

	return plistData, nil
}

// PersonalConfig is the config for personalizing a TSS blob
type PersonalConfig struct {
	Proxy         string
	Insecure      bool
	PersonlID     map[string]any
	BuildManifest *info.BuildManifest
}

// Personalize returns a personalized TSS blob
func Personalize(conf *PersonalConfig) ([]byte, error) {
	nonce, err := hex.DecodeString(conf.PersonlID["ApNonce"].(string))
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce hex-string: %v", err)
	}

	tssReq := Request{
		UUID:             uuid.New().String(),
		ApImg4Ticket:     true,
		BBTicket:         true,
		HostPlatformInfo: "mac",
		VersionInfo:      tssClientVersion,
		ApBoardID:        uint64(conf.PersonlID["BoardId"].(float64)),
		ApChipID:         uint64(conf.PersonlID["ChipID"].(float64)),
		ApECID:           uint64(conf.PersonlID["UniqueChipID"].(float64)),
		ApNonce:          nonce,
		ApProductionMode: true,
		ApSecurityDomain: 1,
		ApSecurityMode:   true,
		UIDMode:          false,
		SepNonce:         []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}

	var manifest map[string]info.IdentityManifest
	for _, bid := range conf.BuildManifest.BuildIdentities {
		boardID, err := strconv.ParseUint(strings.TrimPrefix(bid.ApBoardID, "0x"), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse board id: %v", err)
		}
		chipID, err := strconv.ParseUint(strings.TrimPrefix(bid.ApChipID, "0x"), 16, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse chip id: %v", err)
		}
		if boardID == uint64(conf.PersonlID["BoardId"].(float64)) && chipID == uint64(conf.PersonlID["ChipID"].(float64)) {
			manifest = bid.Manifest
			break
		}
	}

	parameters := map[string]any{
		"ApProductionMode": true,
		"ApSecurityDomain": 1,
		"ApSecurityMode":   true,
		"ApSupportsImg4":   true,
	}

	tssReq.PersonalizedDMG = manifest["PersonalizedDMG"]
	tssReq.PersonalizedDMG.Info = nil
	tssReq.LoadableTrustCache = manifest["LoadableTrustCache"]
	tssReq.LoadableTrustCache.Info = nil

	if rules, ok := manifest["LoadableTrustCache"].Info["RestoreRequestRules"]; ok {
		for _, rule := range rules.([]any) {
			satisfied := true
			if conds, ok := rule.(map[string]any)["Conditions"]; ok {
				for k, v := range conds.(map[string]any) {
					if !satisfied {
						break
					}
					switch k {
					case "ApRawProductionMode":
						satisfied = parameters["ApProductionMode"] == v
					case "ApCurrentProductionMode":
						satisfied = parameters["ApProductionMode"] == v
					case "ApRawSecurityMode":
						satisfied = parameters["ApSecurityMode"] == v
					case "ApRequiresImage4":
						satisfied = parameters["ApSupportsImg4"] == v
					case "ApDemotionPolicyOverride":
						satisfied = parameters["DemotionPolicy"] == v
					case "ApInRomDFU":
						satisfied = parameters["ApInRomDFU"] == v
					default:
						log.Fatalf("unknown LoadableTrustCache->RestoreRequestRules->Condition: %s", k)
					}
				}
			}
			if satisfied {
				if actions, ok := rule.(map[string]any)["Actions"]; ok {
					for k, v := range actions.(map[string]any) {
						switch k {
						case "EPRO":
							tssReq.PersonalizedDMG.EPRO = v.(bool)
							tssReq.LoadableTrustCache.EPRO = v.(bool)
						case "ESEC":
							tssReq.PersonalizedDMG.ESEC = v.(bool)
							tssReq.LoadableTrustCache.ESEC = v.(bool)
						}
					}
				}
			}
		}
	}

	var tssMap map[string]any
	if err := mapstructure.Decode(tssReq, &tssMap); err != nil {
		return nil, err
	}

	for k, v := range conf.PersonlID {
		if strings.HasPrefix(k, "Ap,") {
			switch v.(type) {
			case float64:
				tssMap[k] = uint64(v.(float64))
			default:
				tssMap[k] = v
			}
		}
	}

	buf := new(bytes.Buffer)
	if err := plist.NewEncoder(buf).Encode(tssMap); err != nil {
		return nil, err
	}
	// os.WriteFile("/tmp/tss.plist", buf.Bytes(), 0644)

	blob, err := getApImg4Ticket(buf, conf.Proxy, conf.Insecure)
	if err != nil {
		return nil, err
	}

	return blob.ApImg4Ticket, nil
}
