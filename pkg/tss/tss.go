package tss

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/info"
	bm "github.com/blacktop/ipsw/pkg/plist"
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
	// tssControllerActionURL = "http://gsra.apple.com/TSS/controller?action=2" TODO: maybe this is the new URL?
	tssClientVersion = "libauthinstall-1049.100.21"
)

var ErrNotSigned = fmt.Errorf("not signed")

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
	NeRDEpoch                 int    `plist:"NeRDEpoch,omitempty" mapstructure:"NeRDEpoch,omitempty"`
	PermitNeRDPivot           []byte `plist:"PermitNeRDPivot,omitempty" mapstructure:"PermitNeRDPivot,omitempty"`
	ApSikaFuse                int    `plist:"Ap,SikaFuse,omitempty" mapstructure:"Ap,SikaFuse,omitempty"`
	// Ap,* fields from manifest
	ApOSLongVersion           string `plist:"Ap,OSLongVersion,omitempty" mapstructure:"Ap,OSLongVersion,omitempty"`
	ApProductMarketingVersion string `plist:"Ap,ProductMarketingVersion,omitempty" mapstructure:"Ap,ProductMarketingVersion,omitempty"`
	ApProductType             string `plist:"Ap,ProductType,omitempty" mapstructure:"Ap,ProductType,omitempty"`
	ApSDKPlatform             string `plist:"Ap,SDKPlatform,omitempty" mapstructure:"Ap,SDKPlatform,omitempty"`
	ApTarget                  string `plist:"Ap,Target,omitempty" mapstructure:"Ap,Target,omitempty"`
	ApTargetType              string `plist:"Ap,TargetType,omitempty" mapstructure:"Ap,TargetType,omitempty"`
	// Personalize
	LoadableTrustCache bm.IdentityManifest `plist:"LoadableTrustCache,omitempty" mapstructure:"LoadableTrustCache,omitempty"`
	PersonalizedDMG    bm.IdentityManifest `plist:"PersonalizedDMG,omitempty" mapstructure:"PersonalizedDMG,omitempty"`
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

type RestoreRequestRule struct {
	Actions struct {
		EPRO bool `plist:"EPRO,omitempty"`
		ESEC bool `plist:"ESEC,omitempty"`
	} `plist:"Actions,omitempty"`
	Conditions struct {
		ApRawProductionMode bool `plist:"ApRawProductionMode,omitempty"`
		ApRequiresImage4    bool `plist:"ApRequiresImage4,omitempty"`
	} `plist:"Conditions,omitempty"`
}

func randomHex(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func RandomECID() (uint64, error) {
	b, err := randomHex(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// applyRestoreRequestRules applies restore request rules to a component
func applyRestoreRequestRules(entry map[string]any, parameters map[string]any, rules any) {
	rulesList, ok := rules.([]any)
	if !ok {
		return
	}

	for _, rule := range rulesList {
		ruleMap, ok := rule.(map[string]any)
		if !ok {
			continue
		}

		// Check conditions
		conditions, hasConditions := ruleMap["Conditions"].(map[string]any)
		conditionsFulfilled := true

		if hasConditions {
		conditionLoop:
			for condKey, condValue := range conditions {
				var paramValue any
				switch condKey {
				case "ApRawProductionMode", "ApCurrentProductionMode":
					paramValue = parameters["ApProductionMode"]
				case "ApRawSecurityMode":
					paramValue = parameters["ApSecurityMode"]
				case "ApRequiresImage4":
					paramValue = true // We're always using IMG4
				case "ApDemotionPolicyOverride":
					paramValue = parameters["DemotionPolicy"]
				case "ApInRomDFU":
					paramValue = parameters["ApInRomDFU"]
				default:
					// Unknown condition, assume not fulfilled
					conditionsFulfilled = false
					break conditionLoop
				}

				if paramValue != condValue {
					conditionsFulfilled = false
					break
				}
			}
		}

		// Apply actions if conditions are fulfilled
		if conditionsFulfilled {
			if actions, hasActions := ruleMap["Actions"].(map[string]any); hasActions {
				for actionKey, actionValue := range actions {
					if boolValue, isBool := actionValue.(bool); isBool {
						entry[actionKey] = boolValue
					}
				}
			}
		}
	}
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
	for field := range strings.SplitSeq(string(body), "&") {
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

	return nil, fmt.Errorf("status: %d, message: %s: %w", tr.Status, tr.Message, ErrNotSigned)
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
	Output          string

	Info *info.Info // Optional, if provided will use this info instead of downloading it
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
		conf.Build = conf.Info.Plists.BuildManifest.ProductBuildVersion
	}

	buildIdentity, err := conf.Info.Plists.GetBuildIdentity(conf.Device)
	if err != nil {
		return nil, fmt.Errorf("failed to get build identity for %s: %v", conf.Device, err)
	}

	// Parse board and chip IDs
	chipID, err := strconv.ParseUint(strings.TrimPrefix(buildIdentity.ApChipID, "0x"), 16, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse chip id: %v", err)
	}
	boardID, err := strconv.ParseUint(strings.TrimPrefix(buildIdentity.ApBoardID, "0x"), 16, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse board id: %v", err)
	}
	ecid := conf.ECID
	if ecid == 0 {
		return nil, fmt.Errorf("ECID must be provided to check signing status")
	}

	tssReq := make(map[string]any)
	// Create base request
	tssReq["@HostPlatformInfo"] = "mac"
	tssReq["@VersionInfo"] = tssClientVersion
	tssReq["@UUID"] = strings.ToUpper(uuid.New().String())
	tssReq["ApECID"] = ecid
	tssReq["UniqueBuildID"] = buildIdentity.UniqueBuildID
	tssReq["ApChipID"] = chipID
	tssReq["ApBoardID"] = boardID
	tssReq["ApSecurityDomain"] = uint64(1)
	tssReq["ApSecurityMode"] = true
	tssReq["Ap,OSLongVersion"] = buildIdentity.ApOSLongVersion
	tssReq["Ap,ProductMarketingVersion"] = buildIdentity.ApProductMarketingVersion
	tssReq["Ap,ProductType"] = buildIdentity.ApProductType
	tssReq["Ap,SDKPlatform"] = buildIdentity.ApSDKPlatform
	tssReq["Ap,Target"] = buildIdentity.ApTarget
	tssReq["Ap,TargetType"] = buildIdentity.ApTargetType
	tssReq["ApNonce"] = conf.ApNonce
	tssReq["SepNonce"] = conf.SepNonce
	tssReq["@ApImg4Ticket"] = true
	tssReq["ApProductionMode"] = true
	tssReq["NeRDEpoch"] = 0
	tssReq["PearlCertificationRootPub"] = buildIdentity.PearlCertificationRootPub
	tssReq["PermitNeRDPivot"] = buildIdentity.PermitNeRDPivot
	tssReq["UID_MODE"] = false
	tssReq["Ap,SikaFuse"] = 0

	// Parameters for restore request rules
	parameters := map[string]any{
		"ApProductionMode": true,
		"ApSecurityMode":   true,
		"ApRequiresImage4": true,
	}

	for k, v := range buildIdentity.Manifest {
		m := make(map[string]any)

		if _, ok := v.Info["RestoreRequestRules"]; !ok {
			continue
		}

		m["Digest"] = v.Digest

		if v.Trusted != nil {
			m["Trusted"] = *v.Trusted
		}

		// Apply restore request rules to set EPRO/ESEC
		if RestoreRequestRules, ok := v.Info["RestoreRequestRules"].([]any); ok {
			applyRestoreRequestRules(m, parameters, RestoreRequestRules)
		}

		// Add special fields for specific components
		if v.BuildString != nil {
			m["BuildString"] = *v.BuildString
		}
		if v.MemoryMap != nil {
			m["MemoryMap"] = *v.MemoryMap
		}
		if v.ObjectPayloadPropertyDigest != nil {
			m["ObjectPayloadPropertyDigest"] = *v.ObjectPayloadPropertyDigest
		}
		if v.RawDataDigest != nil {
			m["RawDataDigest"] = *v.RawDataDigest
		}
		if v.TBMDigests != nil {
			m["TBMDigests"] = *v.TBMDigests
		}

		tssReq[k] = m
	}

	trdata, err := plist.MarshalIndent(tssReq, plist.XMLFormat, "  ")
	if err != nil {
		return nil, err
	}

	// log.Debug("Saving TSS request to /tmp/tss_request.plist")
	// if err := os.WriteFile("/tmp/tss_request.plist", trdata, 0644); err != nil {
	// 	return nil, err
	// }

	blob, err := getApImg4Ticket(bytes.NewReader(trdata), conf.Proxy, conf.Insecure)
	if err != nil {
		return nil, err
	}

	plistData, err := plist.MarshalIndent(blob, plist.XMLFormat, "  ")
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
	BuildManifest *bm.BuildManifest
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

	var manifest map[string]bm.IdentityManifest
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
							epro := v.(bool)
							tssReq.PersonalizedDMG.EPRO = &epro
							tssReq.LoadableTrustCache.EPRO = &epro
						case "ESEC":
							esec := v.(bool)
							tssReq.PersonalizedDMG.ESEC = &esec
							tssReq.LoadableTrustCache.ESEC = &esec
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

	// Convert IdentityManifest pointer values to regular values for plist marshalling
	tssMap["PersonalizedDMG"] = tssReq.PersonalizedDMG.MarshalMap()
	tssMap["LoadableTrustCache"] = tssReq.LoadableTrustCache.MarshalMap()

	for k, v := range conf.PersonlID {
		if strings.HasPrefix(k, "Ap,") {
			switch v := v.(type) {
			case float64:
				tssMap[k] = uint64(v)
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
