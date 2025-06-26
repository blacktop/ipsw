package img4

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/lzfse-cgo"
	"github.com/dustin/go-humanize"
)

// IM4P Types - these are the four-character codes used to identify different payload types in IMG4 containers
const (
	// ACI Types
	IM4P_ACIBT   = "acib" // ACI Bluetooth
	IM4P_ACIWIFI = "aciw" // ACI WiFi

	// Firmware Types
	IM4P_ALAMO             = "almo" // Alamo
	IM4P_ANE_FIRMWARE      = "anef" // ANE Firmware
	IM4P_AOP               = "aopf" // Always on processor firmware
	IM4P_ANS_FIRMWARE      = "ansf" // Apple NVME Storage controller firmware
	IM4P_AUDIO_CODEC_FW    = "acfw" // Audio Codec Firmware
	IM4P_AVE_FIRMWARE      = "avef" // AVE Firmware
	IM4P_GPU_FIRMWARE      = "gfxf" // GPU Firmware
	IM4P_MAGGIE_FIRMWARE   = "magg" // Maggie Firmware
	IM4P_MULTITOUCH_FW     = "mtfw" // Multitouch Firmware
	IM4P_PMP               = "pmpf" // PMP
	IM4P_RTP               = "rtpf" // RTP
	IM4P_SCE               = "scef" // SCE
	IM4P_SMARTIO_FW        = "siof" // SmartIOFirmware
	IM4P_WCH_FW_UPDATER    = "wchf" // WCHFirmwareUpdater
	IM4P_WIRELESS_CHARGING = "wchf" // Wireless Charging

	// Boot Components
	IM4P_IBEC       = "ibec" // iBEC
	IM4P_IBOOT      = "ibot" // iBoot
	IM4P_IBOOT_TEST = "itst" // iBootTest
	IM4P_IBSS       = "ibss" // iBSS
	IM4P_LLB        = "illb" // LLB
	IM4P_CFE_LOADER = "cfel" // Silicon Validation CFE loader
	IM4P_IBOOT_DATA = "ibdt" // iBoot Data

	// System Components
	IM4P_KERNELCACHE      = "krnl" // KernelCache
	IM4P_DEVICE_TREE      = "dtre" // DeviceTree
	IM4P_SEP              = "sepi" // SEP
	IM4P_HYPERVISOR       = "hypr" // Hypervisor
	IM4P_DIAGS            = "diag" // Diags
	IM4P_INPUT_DEVICE     = "ipdf" // Input Device
	IM4P_ISPOOF           = "ispf" // iSpoof(?)
	IM4P_ENVIRONMENT_VARS = "ienv" // Environment Variables

	// Display Components
	IM4P_APPLE_LOGO = "logo" // Used during boot
	IM4P_DCP_FW     = "dcpf" // Display Coprocessor firmware, used on the iPhone 12 and later
	IM4P_DALI       = "dali" // Dali
	IM4P_HOMER      = "homr" // Homer

	// Battery/Charging UI
	IM4P_BATTERY_CHARGING0 = "chg0" // Charging indicator (bright), used in the battery low screen
	IM4P_BATTERY_CHARGING1 = "chg1" // Charging Indicator (dim), used in the battery low screen
	IM4P_BATTERY_FULL      = "batF" // Only used in China to indicate battery status while device is off
	IM4P_BATTERY_LOW0      = "bat0" // Empty battery, used in the battery low screen
	IM4P_BATTERY_LOW1      = "bat1" // Red composed onto empty battery, used in the battery low screen
	IM4P_GLYPH_CHARGING    = "glyC" // Used in the battery low screen
	IM4P_GLYPH_PLUGIN      = "glyP" // Used in the battery low screen
	IM4P_LOW_POWER_WALLET0 = "lpw0" // Used in the battery low screen with power reserve enabled
	IM4P_LOW_POWER_WALLET1 = "lpw1" // Used in the battery low screen with power reserve enabled
	IM4P_LOW_POWER_WALLET2 = "lpw2" // Used in the battery low screen with power reserve enabled
	IM4P_NEED_SERVICE      = "nsrv" // Need Service screen (removed in iOS 4.0+)
	IM4P_RECOVERY_MODE     = "recm" // Used when device is in Recovery Mode

	// Trust Cache Types
	IM4P_ENGINEERING_TRUST_CACHE = "dtrs" // EngineeringTrustCache
	IM4P_LOADABLE_TRUST_CACHE    = "ltrs" // LoadableTrustCache
	IM4P_STATIC_TRUST_CACHE      = "trst" // StaticTrustCache
	IM4P_BASE_SYSTEM_TRUST_CACHE = "bstc" // Base System Trust Cache
	IM4P_X86_BASE_SYSTEM_TC      = "xbtc" // x86 Base System Trust Cache

	// Restore Components
	IM4P_RESTORE_ANS_FW       = "rans" // Restore Apple NVME storage firmware
	IM4P_RESTORE_RAMDISK      = "rdsk" // RestoreRamDisk
	IM4P_RESTORE_DEVICE_TREE  = "rdtr" // RestoreDeviceTree
	IM4P_RESTORE_KERNEL_CACHE = "rkrn" // RestoreKernelCache
	IM4P_RESTORE_LOGO         = "rlgo" // Same as appleLogo
	IM4P_RESTORE_OS           = "rosi" // RestoreOS
	IM4P_RESTORE_DCP_FW       = "dcpf" // Restore Display Coprocessor firmware, used on the iPhone 12 and later
	IM4P_RESTORE_SEP          = "rsep" // rsep is also present in sepboot
	IM4P_RESTORE_TRUST_CACHE  = "rtsc" // RestoreTrustCache

	// FDR Trust Objects
	IM4P_FDR_TRUST_OBJECT_AP  = "fdrt" // FDR Trust Object for AP
	IM4P_FDR_TRUST_OBJECT_SEP = "fdrs" // FDR Trust Object for SEP

	// Audio Files
	IM4P_BOOT_CHIME          = "aubt" // Raw audio file
	IM4P_ACCESSIBILITY_CHIME = "auac" // Raw audio file
	IM4P_ATTACH_CHIME        = "aupr" // Raw audio file

	// System Volume Components
	IM4P_AUX_KERNEL_CACHE           = "auxk" // Aux Kernel Cache
	IM4P_BASE_SYSTEM_ROOT_HASH      = "csys" // Base System Volume Root Hash
	IM4P_SYSTEM_VOLUME_ROOT_HASH    = "isys" // System Volume Root Hash
	IM4P_X86_SYSTEM_VOLUME_HASH     = "xsys" // x86 System Volume Root hash
	IM4P_SYSTEM_VOLUME_METADATA     = "msys" // System Volume Canonical Metadata (Compressed gzip file)
	IM4P_X86_SYSTEM_VOLUME_METADATA = "xsys" // x86 System Volume Canonical Metadata (Compressed gzip file)

	// Special/Testing Components
	IM4P_AP_TICKET        = "SCAB" // On devices that don't use IMG4
	IM4P_OS_RAMDISK       = "osrd" // OSRamdisk
	IM4P_PE_HAMMER        = "hmmr" // PE Hammer test
	IM4P_PERSONALIZED_DMG = "pdmg" // PersonalizedDMG
	IM4P_PERTOS           = "pert" // PE RTOS environment
	IM4P_PHLEET           = "phlt" // Silicon Validation PHLEET test
	IM4P_RBM              = "rbmt" // Silicon Validation RBM test
	IM4P_SYSTEM_LOCKER    = "lckr" // System Locker
	IM4P_TSYS_TESTER      = "tsys" // TSYS Tester
	IM4P_LEAP_HAPTICS     = "lphp" // LeapHaptics
	IM4P_MAC_EFI          = "mefi" // Used only on T2 Macs

	// Unknown Types
	IM4P_CIOF = "ciof" // Unknown
	IM4P_TMUF = "tmuf" // Unknown
	IM4P_RPMP = "rpmp" // Unknown
	IM4P_LPOL = "lpol" // Unknown
	IM4P_RTMU = "rtmu" // Unknown
	IM4P_RCIO = "rcio" // Unknown
)

type CompressionAlgorithm int

const (
	CompressionAlgorithmLZSS CompressionAlgorithm = iota
	CompressionAlgorithmLZFSE
	CompressionAlgorithmMAX
)

func (c CompressionAlgorithm) String() string {
	switch c {
	case CompressionAlgorithmLZSS:
		return "LZSS"
	case CompressionAlgorithmLZFSE:
		return "LZFSE"
	default:
		return fmt.Sprintf("Unknown (%d)", c)
	}
}

type Compression struct {
	Algorithm        CompressionAlgorithm `asn1:"integer"`
	UncompressedSize int                  `asn1:"integer"`
}

type IM4P struct {
	Raw         asn1.RawContent
	Tag         string `asn1:"ia5"` // IM4P
	Type        string `asn1:"ia5"`
	Version     string `asn1:"ia5"`
	Data        []byte
	Compression Compression   `asn1:"optional"`
	Keybag      []byte        `asn1:"optional"`
	ExtraData   asn1.RawValue `asn1:"optional"`                              // May contain size info
	Properties  asn1.RawValue `asn1:"optional,tag:0,class:context,explicit"` // PAYP properties
	Hash        [48]byte      `asn1:"optional"`
}

type Payload struct {
	IM4P
	Keybags          []Keybag
	CompressionType  string         // LZFSE, LZSS, or none
	UncompressedSize int            // Size after decompression
	Properties       map[string]any // Parsed properties like kcep, kclf, etc.
	ExtraDataSize    int            // Size of extra data (like trailing metadata)
	ExtraDataBytes   []byte         // The actual extra data bytes that were separated
	Encrypted        bool           // Whether the IM4P is encrypted
}

func OpenPayload(path string) (*Payload, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", path, err)
	}
	return ParsePayload(data)
}

func ParsePayload(data []byte) (*Payload, error) {
	var p Payload

	// Parse using the standard IM4P struct format
	if _, err := asn1.Unmarshal(data, &p.IM4P); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse IM4P: %v", err)
	}

	// Parse keybags if present
	if p.Keybag != nil {
		if _, err := asn1.Unmarshal(p.Keybag, &p.Keybags); err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse IM4P KBAG: %v", err)
		}
		if len(p.Keybags) > 0 {
			p.Encrypted = true
		}
	}

	// Parse compression info from the IM4P structure
	if p.IM4P.Compression.Algorithm != 0 {
		p.CompressionType = p.IM4P.Compression.Algorithm.String()
		p.UncompressedSize = p.IM4P.Compression.UncompressedSize
	} else {
		p.CompressionType = "none"
	}

	// Parse PAYP properties if present
	if len(p.IM4P.Properties.Bytes) > 0 {
		parsedProps, err := parsePayloadProperties(p.IM4P.Properties.Bytes)
		if err != nil {
			log.Debugf("Failed to parse PAYP properties: %v", err)
		}
		p.Properties = parsedProps
	}

	// Check for extra data at the end of the Data field (MachO detection)
	if err := detectMachOExtraData(&p); err != nil {
		log.Debugf("Failed to detect MachO extra data: %v", err)
	}

	return &p, nil
}

// String returns a formatted string representation of the payload
func (p *Payload) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s:\n", colorTitle("IM4P (Payload)")))
	sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Tag"), p.Tag))
	sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Type"), p.Type))
	sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Version"), p.Version))
	sb.WriteString(fmt.Sprintf("  %s: %s (%d bytes)\n", colorField("Data"), humanize.Bytes(uint64(len(p.Data))), len(p.Data)))
	if p.CompressionType != "none" {
		sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Compression"), p.CompressionType))
		if p.UncompressedSize > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %s (%d bytes)\n", colorField("Uncompressed Size"), humanize.Bytes(uint64(p.UncompressedSize)), p.UncompressedSize))
		}
	}
	if p.ExtraDataSize > 0 {
		sb.WriteString(fmt.Sprintf("  %s: %d bytes\n", colorField("ExtraData"), p.ExtraDataSize))
	}
	if len(p.Keybags) > 0 {
		sb.WriteString(fmt.Sprintf("  %s: %t\n", colorField("Encrypted:"), p.Encrypted))
		sb.WriteString(fmt.Sprintf("  %s:\n", colorField("Keybags")))
		for i, kb := range p.Keybags {
			sb.WriteString(fmt.Sprintf("    [%d] %s %s\n", i, colorField("Type:"), kb.Type.String()))
			sb.WriteString(fmt.Sprintf("        %s   %x\n", colorField("IV:"), kb.IV))
			sb.WriteString(fmt.Sprintf("        %s  %x\n", colorField("Key:"), kb.Key))
		}
	}
	if p.Properties != nil {
		sb.WriteString(fmt.Sprintf("  %s:\n", colorField("Properties")))
		for k, v := range p.Properties {
			sb.WriteString(fmt.Sprintf("    %s: %v\n", colorSubField(k), v))
		}
	}
	if p.ExtraDataSize > 0 {
		sb.WriteString(fmt.Sprintf("  %s    %s (%d bytes)\n", colorField("Extra Data Size:"), humanize.Bytes(uint64(p.ExtraDataSize)), p.ExtraDataSize))
	}
	return sb.String()
}

// MarshalJSON returns a JSON representation of the payload
func (p *Payload) MarshalJSON() ([]byte, error) {
	data := map[string]any{
		"tag":             p.Tag,
		"type":            p.Type,
		"version":         p.Version,
		"data":            p.Data,
		"encrypted":       p.Encrypted,
		"keybags":         p.Keybags,
		"properties":      p.Properties,
		"extra_data_size": p.ExtraDataSize,
		"compression":     p.Compression,
		"hash":            p.Hash,
	}
	return json.Marshal(data)
}

// Keybag Types
type kbagType int

const (
	PRODUCTION  kbagType = 1
	DEVELOPMENT kbagType = 2
	DECRYPTED   kbagType = 3
)

func (t kbagType) String() string {
	switch t {
	case PRODUCTION:
		return "PRODUCTION"
	case DEVELOPMENT:
		return "DEVELOPMENT"
	case DECRYPTED:
		return "DECRYPTED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func (t kbagType) Short() string {
	switch t {
	case PRODUCTION:
		return "prod"
	case DEVELOPMENT:
		return "dev"
	case DECRYPTED:
		return "dec"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

type Keybag struct {
	Type kbagType
	IV   []byte
	Key  []byte
}

func (k Keybag) String() string {
	return fmt.Sprintf(
		"-\n"+
			"  type: %s\n"+
			"    iv: %x\n"+
			"   key: %x",
		k.Type.String(),
		k.IV,
		k.Key)
}

func (k Keybag) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Type string `json:"type,omitempty"`
		IV   string `json:"iv,omitempty"`
		Key  string `json:"key,omitempty"`
	}{
		Type: k.Type.Short(),
		IV:   hex.EncodeToString(k.IV),
		Key:  hex.EncodeToString(k.Key),
	})
}

// KeyBag Related Types
type im4pKBag struct {
	Name    string   `json:"name,omitempty"`
	Keybags []Keybag `json:"kbags,omitempty"`
}

type KeyBags struct {
	Type    string     `json:"type,omitempty"`
	Version string     `json:"version,omitempty"`
	Build   string     `json:"build,omitempty"`
	Devices []string   `json:"devices,omitempty"`
	Files   []im4pKBag `json:"files,omitempty"`
}

// MetaData contains minimal metadata needed for key bag parsing
type MetaData struct {
	Type                  string
	ProductVersion        string
	ProductBuildVersion   string
	SupportedProductTypes []string
}

func ParseZipKeyBags(files []*zip.File, meta *MetaData, pattern string) (*KeyBags, error) {
	kbags := &KeyBags{
		Type:    meta.Type,
		Version: meta.ProductVersion,
		Build:   meta.ProductBuildVersion,
		Devices: meta.SupportedProductTypes,
	}

	rePattern := `.*im4p$`
	if len(pattern) > 0 {
		if _, err := regexp.Compile(pattern); err != nil {
			return nil, fmt.Errorf("failed to compile --pattern regexp: %v", err)
		}
		rePattern = pattern
	}

	for _, f := range files {
		if regexp.MustCompile(rePattern).MatchString(f.Name) {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("error opening zipped file %s: %v", f.Name, err)
			}
			im4p, err := ParseIm4p(rc)
			if err != nil {
				log.Errorf("failed to parse im4p %s: %v", f.Name, err)
			}
			if im4p.Keybags == nil { // kbags are optional
				continue
			}
			kbags.Files = append(kbags.Files, im4pKBag{
				Name:    filepath.Base(f.Name),
				Keybags: im4p.Keybags,
			})
			if err := rc.Close(); err != nil {
				log.Errorf("failed to close zipped file %s: %v", f.Name, err)
			}
		}
	}

	return kbags, nil
}

// CreateIm4p creates a new IM4P structure
func CreateIm4p(name, fourcc, description string, data []byte, kbags []Keybag) *Payload {
	return CreateIm4pWithExtra(name, fourcc, description, data, kbags, nil)
}

// CreateIm4pWithExtra creates an IM4P structure with optional extra data
func CreateIm4pWithExtra(name, fourcc, description string, data []byte, kbags []Keybag, extraData []byte) *Payload {
	// If extra data is provided, append it to the main data
	finalData := data
	if len(extraData) > 0 {
		finalData = append(data, extraData...)
	}

	im4pStruct := &Payload{
		IM4P: IM4P{
			Tag:     name,
			Type:    fourcc,
			Version: description,
			Data:    finalData,
		},
		Keybags: kbags,
	}

	// Store extra data information for reference
	if len(extraData) > 0 {
		im4pStruct.ExtraDataSize = len(extraData)
		im4pStruct.ExtraDataBytes = make([]byte, len(extraData))
		copy(im4pStruct.ExtraDataBytes, extraData)
	}

	// If there are keybags, marshal them to KbagData
	if len(kbags) > 0 {
		if kbagData, err := asn1.Marshal(kbags); err == nil {
			im4pStruct.Keybag = kbagData
		}
	}

	return im4pStruct
}

// MarshalIm4p marshals an IM4P structure to ASN.1 bytes
func MarshalIm4p(im4p *Payload) ([]byte, error) {
	return asn1.Marshal(im4p.IM4P)
}

// CreateIm4pFile creates a complete IM4P file from raw data
func CreateIm4pFile(fourcc, description string, data []byte) ([]byte, error) {
	return CreateIm4pFileWithExtra(fourcc, description, data, nil)
}

// CreateIm4pFileWithExtra creates a complete IM4P file from raw data with optional extra data
func CreateIm4pFileWithExtra(fourcc, description string, data []byte, extraData []byte) ([]byte, error) {
	if len(fourcc) != 4 {
		return nil, fmt.Errorf("FourCC must be exactly 4 characters, got %d: %s", len(fourcc), fourcc)
	}

	im4pStruct := CreateIm4pWithExtra("IM4P", fourcc, description, data, nil, extraData)
	return MarshalIm4p(im4pStruct)
}

func ParseIm4p(r io.Reader) (*Payload, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	// Use ParsePayload which has all the updated logic
	return ParsePayload(data)
}

// detectMachOExtraData specifically looks for MachO binaries at the end of the payload
func detectMachOExtraData(i *Payload) error {
	if len(i.Data) == 0 {
		return nil
	}

	// MachO magic numbers to look for
	machOMagics := [][]byte{
		{0xce, 0xfa, 0xed, 0xfe}, // MH_MAGIC (32-bit little endian)
		{0xfe, 0xed, 0xfa, 0xce}, // MH_MAGIC (32-bit big endian)
		{0xcf, 0xfa, 0xed, 0xfe}, // MH_MAGIC_64 (64-bit little endian)
		{0xfe, 0xed, 0xfa, 0xcf}, // MH_MAGIC_64 (64-bit big endian)
		{0xca, 0xfe, 0xba, 0xbe}, // FAT_MAGIC (universal binary)
		{0xbe, 0xba, 0xfe, 0xca}, // FAT_MAGIC (universal binary, swapped)
	}

	// Scan backwards for MachO magic numbers
	// Start from end and look for page-aligned positions
	dataLen := len(i.Data)

	// Common alignment sizes where MachO might start
	alignments := []int{4096, 8192, 16384, 32768}

	for _, alignment := range alignments {
		if dataLen <= alignment {
			continue
		}

		// Check at aligned positions from the end
		for offset := alignment; offset < dataLen; offset += alignment {
			checkPos := dataLen - offset
			if checkPos < 0 || checkPos+4 > dataLen {
				continue
			}

			// Check for MachO magic at this position
			for _, magic := range machOMagics {
				if bytes.Equal(i.Data[checkPos:checkPos+4], magic) {
					// Found MachO magic - this is likely extra data
					i.ExtraDataSize = offset
					i.ExtraDataBytes = make([]byte, offset)
					copy(i.ExtraDataBytes, i.Data[checkPos:])

					log.Debugf("Detected MachO binary at offset %d (%d bytes from end)", checkPos, offset)
					return nil
				}
			}
		}
	}

	return nil
}

// GetExtraData returns any extra data that was detected from the payload
func (i *Payload) GetExtraData() []byte {
	return i.ExtraDataBytes
}

// HasExtraData returns true if extra data was detected in the IM4P
func (i *Payload) HasExtraData() bool {
	return i.ExtraDataSize > 0
}

// GetCleanPayloadData returns the payload data without the detected extra data
// This is useful when you want to process only the actual payload without metadata
func (i *Payload) GetCleanPayloadData() []byte {
	if i.ExtraDataSize > 0 && len(i.Data) > i.ExtraDataSize {
		// Return payload without the detected extra data
		cleanData := make([]byte, len(i.Data)-i.ExtraDataSize)
		copy(cleanData, i.Data[:len(i.Data)-i.ExtraDataSize])
		return cleanData
	}
	// If no extra data detected or data is too small, return original data
	return i.Data
}

// GetExtraDataInfo returns information about the detected extra data
func (i *Payload) GetExtraDataInfo() map[string]any {
	if i.ExtraDataSize == 0 {
		return nil
	}

	info := map[string]any{
		"size":     i.ExtraDataSize,
		"has_data": len(i.ExtraDataBytes) > 0,
	}

	if len(i.ExtraDataBytes) > 0 {
		// Analyze the extra data to provide more info
		nullCount := 0
		for _, b := range i.ExtraDataBytes {
			if b == 0 {
				nullCount++
			}
		}

		info["null_bytes"] = nullCount
		info["null_percentage"] = float64(nullCount) / float64(len(i.ExtraDataBytes)) * 100

		// Check if it looks like ASN.1 data
		if len(i.ExtraDataBytes) >= 2 {
			tag := i.ExtraDataBytes[0]
			info["likely_asn1"] = (tag == 0x30 || tag == 0x31 || tag == 0x04 || tag == 0x02)
			info["first_byte"] = fmt.Sprintf("%#02x", tag)
		}
	}

	return info
}

// parsePayloadProperties parses the PAYP properties section
func parsePayloadProperties(data []byte) (map[string]any, error) {
	// Parse the PAYP container
	var payp struct {
		Raw  asn1.RawContent
		Name string        // PAYP
		Set  asn1.RawValue `asn1:"set"`
	}

	if _, err := asn1.Unmarshal(data, &payp); err != nil {
		return nil, fmt.Errorf("failed to parse PAYP container: %w", err)
	}

	if payp.Name != "PAYP" {
		return nil, fmt.Errorf("expected PAYP, got %s", payp.Name)
	}

	// Use ParsePropertyMap from property.go to parse the properties
	return ParsePropertyMap(payp.Set.Bytes)
}

/* Payload Processing Functions */

// DecryptPayload decrypts an IM4P payload using AES-CBC with provided IV and key
func DecryptPayload(path, output string, iv, key []byte) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unable to open file %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()

	i, err := ParseIm4p(f)
	if err != nil {
		return fmt.Errorf("unable to parse IM4P: %v", err)
	}

	if err := validateDecryptionInputs(i.Data, iv, key); err != nil {
		return err
	}

	decryptedData, err := decryptData(i.Data, iv, key)
	if err != nil {
		return err
	}

	return writeDecryptedOutput(decryptedData, output, path)
}

func validateDecryptionInputs(data, iv, key []byte) error {
	if len(data) < aes.BlockSize {
		return fmt.Errorf("IM4P data too short")
	}

	if len(data)%aes.BlockSize != 0 {
		return fmt.Errorf("IM4P data is not a multiple of the block size")
	}

	if len(iv) != aes.BlockSize {
		return fmt.Errorf("IV must be %d bytes, got %d", aes.BlockSize, len(iv))
	}

	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}

	return nil
}

func decryptData(data, iv, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	return data, nil
}

func writeDecryptedOutput(data []byte, output, inputPath string) error {
	of, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", output, err)
	}
	defer func() {
		if err := of.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()

	var r io.Reader

	// Check for LZFSE compression and decompress if needed
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("bvx2")) {
		log.Debug("Detected LZFSE compression")
		decompressed := lzfse.DecodeBuffer(data)
		if len(decompressed) == 0 {
			return fmt.Errorf("failed to LZFSE decompress %s", inputPath)
		}
		r = bytes.NewReader(decompressed)
	} else {
		r = bytes.NewReader(data)
	}

	if _, err := io.Copy(of, r); err != nil {
		return fmt.Errorf("failed to write decrypted data to file %s: %v", output, err)
	}

	return nil
}

// ExtractPayload extracts payload data from IMG4 or IM4P files with optional decompression
func ExtractPayload(inputPath, outputPath string, isImg4 bool) error {
	f, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()

	payloadData, err := extractPayloadData(f, isImg4)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", filepath.Dir(outputPath), err)
	}

	// Check for LZFSE compression and decompress if needed
	if len(payloadData) >= 4 && bytes.Equal(payloadData[:4], []byte("bvx2")) {
		log.Debug("Detected LZFSE compression")
		decompressed := lzfse.DecodeBuffer(payloadData)
		if len(decompressed) == 0 {
			return fmt.Errorf("failed to LZFSE decompress %s", inputPath)
		}
		payloadData = decompressed
	}

	return os.WriteFile(outputPath, payloadData, 0o660)
}

func extractPayloadData(f *os.File, isImg4 bool) ([]byte, error) {
	// Read the file data
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}

	if isImg4 {
		i, err := ParseImage(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IMG4: %v", err)
		}
		return i.Payload.Data, nil
	}

	// For IM4P, use ParsePayload directly
	i, err := ParsePayload(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IM4P: %v", err)
	}
	return i.Data, nil
}
