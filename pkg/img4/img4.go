package img4

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/colors"
)

// Color variables are defined in manifest.go
var (
	colorTitle    = colors.BoldHiMagenta().SprintFunc()
	colorField    = colors.BoldHiBlue().SprintFunc()
	colorSubField = colors.BoldHiCyan().SprintFunc()
)

// ComponentFourCCs is a map of component names to their four-character codes.
var ComponentFourCCs = map[string]string{
	"ACIBT":                             "acib",
	"ACIBTLPEM":                         "lpbt",
	"ACIWIFI":                           "aciw",
	"ANE":                               "anef",
	"ANS":                               "ansf",
	"AOP":                               "aopf",
	"AVE":                               "avef",
	"Alamo":                             "almo",
	"Ap,ANE1":                           "ane1",
	"Ap,ANE2":                           "ane2",
	"Ap,ANE3":                           "ane3",
	"Ap,AudioAccessibilityBootChime":    "auac",
	"Ap,AudioBootChime":                 "aubt",
	"Ap,AudioPowerAttachChime":          "aupr",
	"Ap,BootabilityBrainTrustCache":     "trbb",
	"Ap,CIO":                            "ciof",
	"Ap,HapticAssets":                   "hpas",
	"Ap,LocalBoot":                      "lobo",
	"Ap,LocalPolicy":                    "lpol",
	"Ap,NextStageIM4MHash":              "nsih",
	"Ap,RecoveryOSPolicyNonceHash":      "ronh",
	"Ap,RestoreANE1":                    "ran1",
	"Ap,RestoreANE2":                    "ran2",
	"Ap,RestoreANE3":                    "ran3",
	"Ap,RestoreCIO":                     "rcio",
	"Ap,RestoreTMU":                     "rtmu",
	"Ap,Scorpius":                       "scpf",
	"Ap,SystemVolumeCanonicalMetadata":  "msys",
	"Ap,TMU":                            "tmuf",
	"Ap,VolumeUUID":                     "vuid",
	"Ap,rOSLogo1":                       "rlg1",
	"Ap,rOSLogo2":                       "rlg2",
	"AppleLogo":                         "logo",
	"AudioCodecFirmware":                "acfw",
	"BatteryCharging":                   "glyC",
	"BatteryCharging0":                  "chg0",
	"BatteryCharging1":                  "chg1",
	"BatteryFull":                       "batF",
	"BatteryLow0":                       "bat0",
	"BatteryLow1":                       "bat1",
	"BatteryPlugin":                     "glyP",
	"CFELoader":                         "cfel",
	"CrownFirmware":                     "crwn",
	"DCP":                               "dcpf",
	"Dali":                              "dali",
	"DeviceTree":                        "dtre",
	"Diags":                             "diag",
	"EngineeringTrustCache":             "dtrs",
	"ExtDCP":                            "edcp",
	"GFX":                               "gfxf",
	"Hamm":                              "hamf",
	"Homer":                             "homr",
	"ISP":                               "ispf",
	"InputDevice":                       "ipdf",
	"KernelCache":                       "krnl",
	"LLB":                               "illb",
	"LeapHaptics":                       "lphp",
	"Liquid":                            "liqd",
	"LoadableTrustCache":                "ltrs",
	"LowPowerWallet0":                   "lpw0",
	"LowPowerWallet1":                   "lpw1",
	"LowPowerWallet2":                   "lpw2",
	"MacEFI":                            "mefi",
	"MtpFirmware":                       "mtpf",
	"Multitouch":                        "mtfw",
	"NeedService":                       "nsrv",
	"OS":                                "rosi",
	"OSRamdisk":                         "osrd",
	"PEHammer":                          "hmmr",
	"PERTOS":                            "pert",
	"PHLEET":                            "phlt",
	"PMP":                               "pmpf",
	"PersonalizedDMG":                   "pdmg",
	"RBM":                               "rmbt",
	"RTP":                               "rtpf",
	"Rap,SoftwareBinaryDsp1":            "sbd1",
	"Rap,RTKitOS":                       "rkos",
	"Rap,RestoreRTKitOS":                "rrko",
	"RecoveryMode":                      "recm",
	"RestoreANS":                        "rans",
	"RestoreDCP":                        "rdcp",
	"RestoreDeviceTree":                 "rdtr",
	"RestoreExtDCP":                     "recp",
	"RestoreKernelCache":                "rkrn",
	"RestoreLogo":                       "rlgo",
	"RestoreRTP":                        "rrtp",
	"RestoreRamDisk":                    "rdsk",
	"RestoreSEP":                        "rsep",
	"RestoreTrustCache":                 "rtsc",
	"SCE":                               "scef",
	"SCE1Firmware":                      "sc1f",
	"SEP":                               "sepi",
	"SIO":                               "siof",
	"StaticTrustCache":                  "trst",
	"SystemLocker":                      "lckr",
	"SystemVolume":                      "isys",
	"WCHFirmwareUpdater":                "wchf",
	"ftap":                              "ftap",
	"ftsp":                              "ftsp",
	"iBEC":                              "ibec",
	"iBSS":                              "ibss",
	"iBoot":                             "ibot",
	"iBootData":                         "ibdt",
	"iBootDataStage1":                   "ibd1",
	"iBootTest":                         "itst",
	"rfta":                              "rfta",
	"rfts":                              "rfts",
	"Ap,DCP2":                           "dcp2",
	"Ap,RestoreSecureM3Firmware":        "rsm3",
	"Ap,RestoreSecurePageTableMonitor":  "rspt",
	"Ap,RestoreTrustedExecutionMonitor": "rtrx",
	"Ap,RestorecL4":                     "rxcl",
	"BaseSystem":                        "bsys",
	"Ap,SecurePageTableMonitor":         "sptm",
	"Ap,TrustedExecutionMonitor":        "trxm",
	"Ap,BaseSystemTrustCache":           "bstc",
	"Ap,SCodec":                         "strc",
	"BaseSystemVolume":                  "csys",
	"Cryptex1,AppTrustCache":            "trca",
	"Cryptex1,AppOS":                    "caos",
	"Cryptex1,AppVolume":                "casy",
	"Cryptex1,SystemOS":                 "csos",
	"Cryptex1,SystemTrustCache":         "trcs",
	"Cryptex1,SystemVolume":             "cssy",
	"Ap,RestoreDCP2":                    "rdc2",
}

type IMG4 struct {
	Raw         asn1.RawContent
	Tag         string        `asn1:"ia5"` // IMG4
	Payload     asn1.RawValue `asn1:"optional"`
	Manifest    asn1.RawValue `asn1:"explicit,tag:0,optional"`
	RestoreInfo asn1.RawValue `asn1:"explicit,tag:1,optional"`
}

type Image struct {
	IMG4
	Payload     *Payload
	Manifest    *Manifest
	RestoreInfo *RestoreInfo
}

func Open(path string) (*Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", path, err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Image, error) {
	img := &Image{}

	rest, err := asn1.Unmarshal(data, &img.IMG4)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse IMG4: %v", err)
	}
	if len(rest) > 0 {
		log.Warnf("trailing data after IMG4 structure: %d bytes", len(rest))
	}

	if len(img.IMG4.Payload.Bytes) > 0 {
		// ParsePayload expects a full SEQUENCE, so we use FullBytes
		payload, err := ParsePayload(img.IMG4.Payload.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse payload: %w", err)
		}
		img.Payload = payload
	}

	if len(img.IMG4.Manifest.Bytes) > 0 {
		manifest, err := ParseManifest(img.IMG4.Manifest.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse manifest: %w", err)
		}
		img.Manifest = manifest
	}

	if len(img.IMG4.RestoreInfo.Bytes) > 0 {
		restoreInfo, err := ParseRestoreInfo(img.IMG4.RestoreInfo.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse restore info: %w", err)
		}
		img.RestoreInfo = restoreInfo
	}

	return img, nil
}

// String returns a formatted string representation of the image
func (i *Image) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s:\n", colorTitle("IMG4 (Image)")))
	sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Tag"), i.Tag))
	if i.Payload != nil {
		sb.WriteString(i.Payload.String())
	}
	if i.Manifest != nil {
		sb.WriteString(i.Manifest.String())
	}
	if i.RestoreInfo != nil {
		sb.WriteString(i.RestoreInfo.String())
	}
	return sb.String()
}

// MarshalJSON returns a JSON representation of the image
func (i *Image) MarshalJSON() ([]byte, error) {
	data := map[string]any{
		"tag": i.Tag,
	}

	if i.Payload != nil {
		data["payload"] = i.Payload
	} else {
		data["payload"] = nil
	}

	if i.Manifest != nil {
		data["manifest"] = i.Manifest
	} else {
		data["manifest"] = nil
	}

	if i.RestoreInfo != nil {
		data["restore_info"] = i.RestoreInfo
	} else {
		data["restore_info"] = nil
	}

	return json.Marshal(data)
}

type CreateConfig struct {
	// raw IM4P data
	InputData          []byte
	PayloadType        string
	PayloadVersion     string
	PayloadCompression string
	PayloadExtraData   []byte

	PayloadData     []byte
	ManifestData    []byte
	RestoreInfoData []byte

	// IM4R specific
	BootNonce string
}

// Create creates a complete IMG4 file from component files
func Create(conf *CreateConfig) (*Image, error) {
	var err error

	if conf.InputData == nil && conf.PayloadData == nil {
		return nil, fmt.Errorf("config must contain either InputData or PayloadData")
	}
	if len(conf.RestoreInfoData) > 0 && len(conf.BootNonce) > 0 {
		return nil, fmt.Errorf("cannot specify both RestoreInfoData and BootNonce")
	}

	img := Image{
		IMG4: IMG4{
			Tag: "IMG4",
		},
	}

	if len(conf.InputData) > 0 {
		img.Payload, err = CreatePayload(&CreatePayloadConfig{
			Type:        conf.PayloadType,
			Version:     conf.PayloadVersion,
			Data:        conf.InputData,
			ExtraData:   conf.PayloadExtraData,
			Compression: conf.PayloadCompression,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create IM4P payload from input data: %v", err)
		}
	} else if len(conf.PayloadData) > 0 {
		existingPayload, err := ParsePayload(conf.PayloadData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IM4P payload data: %v", err)
		}

		// If type override is specified, create new payload with overridden type
		if conf.PayloadType != "" {
			payloadData, err := existingPayload.GetData()
			if err != nil {
				return nil, fmt.Errorf("failed to get data from existing payload: %v", err)
			}
			img.Payload, err = CreatePayload(&CreatePayloadConfig{
				Type:        conf.PayloadType,
				Version:     conf.PayloadVersion,
				Data:        payloadData,
				ExtraData:   existingPayload.GetExtraData(),
				Compression: conf.PayloadCompression,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create IM4P payload with overridden type: %v", err)
			}
		} else {
			img.Payload = existingPayload
		}
	}

	if len(conf.ManifestData) > 0 {
		img.Manifest, err = ParseManifest(conf.ManifestData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IM4M manifest data: %v", err)
		}
	}

	if len(conf.RestoreInfoData) > 0 {
		img.RestoreInfo, err = ParseRestoreInfo(conf.RestoreInfoData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IM4R restore info data: %v", err)
		}
	}
	if len(conf.BootNonce) > 0 {
		nonce, err := hex.DecodeString(conf.BootNonce)
		if err != nil {
			return nil, fmt.Errorf("failed to decode boot nonce: %v", err)
		}
		if len(nonce) != 8 {
			return nil, fmt.Errorf("boot nonce must be exactly %d bytes (%d hex characters), got %d bytes", 8, 16, len(nonce))
		}
		img.RestoreInfo, err = CreateRestoreInfo(nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to create IM4R restore info with boot nonce: %v", err)
		}
	}

	return &img, nil
}

func (i *Image) Marshal() ([]byte, error) {
	if i.Payload != nil {
		payloadData, err := i.Payload.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %v", err)
		}
		if _, err = asn1.Unmarshal(payloadData, &i.IMG4.Payload); err != nil {
			return nil, fmt.Errorf("failed to parse payload: %v", err)
		}
	}

	if i.Manifest != nil {
		manifestData, err := i.Manifest.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal manifest: %v", err)
		}
		i.IMG4.Manifest = asn1.RawValue{
			Class:      2, // context-specific (for explicit tagging)
			Tag:        0, // tag:0 as specified in struct
			IsCompound: true,
			Bytes:      manifestData,
		}
	}

	if i.RestoreInfo != nil {
		restoreInfoData, err := i.RestoreInfo.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal restore info: %v", err)
		}
		i.IMG4.RestoreInfo = asn1.RawValue{
			Class:      2, // context-specific (for explicit tagging)
			Tag:        1, // tag:1 as specified in struct
			IsCompound: true,
			Bytes:      restoreInfoData,
		}
	}

	return asn1.Marshal(i.IMG4)
}

/* Validation Functions */

// ValidateImg4Structure performs structural validation on an IMG4 file
func ValidateImg4Structure(r io.Reader) (*ValidationResult, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMG4 data: %v", err)
	}
	img, err := Parse(data)
	if err != nil {
		return &ValidationResult{
			IsValid: false,
			Errors:  []string{fmt.Sprintf("Failed to parse IMG4: %v", err)},
		}, nil
	}

	result := &ValidationResult{
		IsValid:    true,
		Errors:     []string{},
		Warnings:   []string{},
		Structure:  "IMG4",
		Components: []string{},
	}

	validateComponents(img, result)
	return result, nil
}

func validateComponents(img *Image, result *ValidationResult) {
	if img.Tag == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "Missing IMG4 name")
	} else {
		result.Components = append(result.Components, "name")
	}

	if img.Payload != nil && img.Payload.Version == "" {
		result.Warnings = append(result.Warnings, "Missing IM4P version")
	}

	// Parse manifest body to validate properties
	if img.Manifest == nil {
		result.Warnings = append(result.Warnings, "No manifest found")
	} else if len(img.Manifest.Properties) == 0 {
		result.Warnings = append(result.Warnings, "No manifest properties found")
	} else {
		result.Components = append(result.Components, "manifest")
		validateCriticalPropertiesFromSlice(img.Manifest.Properties, result)
	}
}

// validateCriticalPropertiesFromSlice validates critical properties from new []Property format
func validateCriticalPropertiesFromSlice(props []Property, result *ValidationResult) {
	criticalProps := []string{"CHIP", "BORD"}
	for _, criticalProp := range criticalProps {
		found := false
		for _, prop := range props {
			if prop.Name == criticalProp {
				found = true
				break
			}
		}
		if !found {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Missing critical property: %s", criticalProp))
		}
	}
}

// ValidationResult holds the results of IMG4 structure validation
type ValidationResult struct {
	IsValid    bool
	Structure  string
	Components []string
	Errors     []string
	Warnings   []string
}

/* PERSONALIZATION FUNCTIONS */

type PersonalizeConfig struct {
	PayloadData   []byte
	ManifestData  []byte
	Component     string
	APParameters  map[string]any // AP parameters for nonce slot handling
	BuildIdentity map[string]any // Build identity information for nonce requirements
}

// Personalize creates a personalized IMG4 file from component files
func Personalize(conf *PersonalizeConfig) (*Image, error) {
	var err error

	if conf.PayloadData == nil {
		return nil, fmt.Errorf("config must contain PayloadData")
	}
	if conf.ManifestData == nil {
		return nil, fmt.Errorf("config must contain ManifestData")
	}

	img := Image{
		IMG4: IMG4{
			Tag: "IMG4",
		},
	}

	img.Payload, err = ParsePayload(conf.PayloadData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IM4P payload data: %v", err)
	}

	if conf.Component != "" {
		if fourcc, ok := ComponentFourCCs[conf.Component]; ok {
			img.Payload.Type = fourcc
		} else {
			log.Warnf("unknown component: %s", conf.Component)
		}
	}

	img.Manifest, err = ParseManifest(conf.ManifestData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IM4M manifest data: %v", err)
	}

	// Create IM4R from component-specific ticket in manifest
	if ticketName := conf.Component + "-TBM"; img.Manifest.HasTicket(ticketName) {
		ticket, err := img.Manifest.GetTicket(ticketName)
		if err != nil {
			return nil, fmt.Errorf("failed to get ticket %s from manifest: %v", ticketName, err)
		}
		props := make(map[string]any)

		// Add all ticket properties
		for _, p := range ticket.Properties {
			props[p.Name] = p.Value
		}

		// Handle nonce slot requirements based on component and build identity
		if conf.BuildIdentity != nil {
			if info, ok := conf.BuildIdentity["Info"]; ok {
				if infoMap, ok := info.(map[string]any); ok {
					requiresNonceSlot, _ := infoMap["RequiresNonceSlot"].(bool)

					if requiresNonceSlot && (conf.Component == "SEP" || conf.Component == "SepStage1" || conf.Component == "LLB") {
						log.Debugf("%s: RequiresNonceSlot for %s", conf.Component, conf.Component)

						switch conf.Component {
						case "SEP", "SepStage1":
							// Handle SEP nonce slot ID
							var snid = 2 // default value
							if conf.APParameters != nil {
								if val, ok := conf.APParameters["SepNonceSlotID"]; ok {
									if intVal, ok := val.(int); ok {
										snid = intVal
									}
								}
							}
							if val, ok := infoMap["SepNonceSlotID"]; ok {
								if intVal, ok := val.(int); ok {
									snid = intVal
								}
							}
							log.Debugf("snid: %d", snid)
							props["snid"] = snid
						case "LLB":
							// Handle AP nonce slot ID
							var anid = 0 // default value
							if conf.APParameters != nil {
								if val, ok := conf.APParameters["ApNonceSlotID"]; ok {
									if intVal, ok := val.(int); ok {
										anid = intVal
									}
								}
							}
							if val, ok := infoMap["ApNonceSlotID"]; ok {
								if intVal, ok := val.(int); ok {
									anid = intVal
								}
							}
							log.Debugf("anid: %d", anid)
							props["anid"] = anid
						}
					}
				}
			}
		}

		img.RestoreInfo = &RestoreInfo{
			IM4R: IM4R{
				Tag: "IM4R",
			},
			Properties: props,
		}
	}

	return &img, nil
}
