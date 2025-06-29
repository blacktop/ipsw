package img4

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/adler32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/comp"
	"github.com/blacktop/lzss"
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

var ErrNotCompressed = fmt.Errorf("payload is not compressed")

// CompressionTypes is a list of supported compression algorithms
var CompressionTypes = []string{"none", "lzss", "lzfse", "lzfse_iboot"}

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
	Algorithm        CompressionAlgorithm `asn1:"integer" json:"algorithm,omitempty"`
	UncompressedSize int                  `asn1:"integer" json:"uncompressed_size,omitempty"`
}

type PAYP struct {
	Raw asn1.RawContent
	Tag string        `asn1:"ia5"` // PAYP
	Set asn1.RawValue `asn1:"set"`
}

type IM4P struct {
	Raw         asn1.RawContent
	Tag         string `asn1:"ia5"` // IM4P
	Type        string `asn1:"ia5"`
	Version     string `asn1:"ia5"`
	Data        []byte
	Compression Compression `asn1:"optional,omitempty"`
	Keybag      []byte      `asn1:"optional"`
	Properties  PAYP        `asn1:"optional,tag:0,class:context,explicit"`
	Hash        []byte      `asn1:"optional"`
}

type Payload struct {
	IM4P
	Encrypted  bool
	Keybags    []Keybag
	Properties map[string]any

	decompressedData []byte
	extraData        []byte // Any extra data appended after the compressed payload
}

func OpenPayload(path string) (*Payload, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open payload %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close payload %s: %v", path, err)
		}
	}()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload %s: %v", path, err)
	}
	return ParsePayload(data)
}

func ParsePayload(data []byte) (*Payload, error) {

	if len(data) == 0 {
		return nil, fmt.Errorf("empty payload data")
	}

	var p Payload
	rest, err := asn1.Unmarshal(data, &p.IM4P)
	if err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse IM4P: %v", err)
	}
	if len(rest) > 0 {
		log.Warnf("unexpected trailing data after IM4P structure: %d bytes", len(rest))
	}

	if p.Tag != "IM4P" {
		return nil, fmt.Errorf("invalid payload tag: expected 'IM4P', got '%s'", p.Tag)
	}

	if p.Keybag != nil {
		if _, err := asn1.Unmarshal(p.Keybag, &p.Keybags); err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse IM4P KBAG: %v", err)
		}
		if len(p.Keybags) > 0 {
			p.Encrypted = true
		}
	}

	if len(p.IM4P.Properties.Raw) > 0 {
		if p.IM4P.Properties.Tag != "PAYP" {
			return nil, fmt.Errorf("invalid payload properties tag: expected 'PAYP', got '%s'", p.IM4P.Properties.Tag)
		}
		p.Properties, err = ParsePropertyMap(p.IM4P.Properties.Set.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse payload properties: %v", err)
		}
	}

	return &p, nil
}

func (p *Payload) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s:\n", colorTitle("IM4P (Payload)")))
	sb.WriteString(fmt.Sprintf("  %s:          %s\n", colorField("Tag"), p.Tag))
	sb.WriteString(fmt.Sprintf("  %s:         %s\n", colorField("Type"), p.Type))
	if len(p.Version) > 0 {
		sb.WriteString(fmt.Sprintf("  %s:      %s\n", colorField("Version"), p.Version))
	}
	sb.WriteString(fmt.Sprintf("  %s:         %s (%d bytes)\n", colorField("Data"), humanize.Bytes(uint64(len(p.Data))), len(p.Data)))
	if p.Compression.UncompressedSize > 0 {
		sb.WriteString(fmt.Sprintf("  %s:  %s\n", colorField("Compression"), p.Compression.Algorithm.String()))
		if p.Compression.UncompressedSize > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %s (%d bytes)\n", colorField("Uncompressed"), humanize.Bytes(uint64(p.Compression.UncompressedSize)), p.Compression.UncompressedSize))
		}
	}
	if p.HasExtraData() {
		extraData := p.GetExtraData()
		if len(extraData) > 0 {
			sb.WriteString(fmt.Sprintf("  %s:    %s (%d bytes)\n", colorField("ExtraData"), humanize.Bytes(uint64(len(extraData))), len(extraData)))
		}
	}
	if len(p.Keybags) > 0 {
		sb.WriteString(fmt.Sprintf("  %s: %t\n", colorField("Encrypted"), p.Encrypted))
		sb.WriteString(fmt.Sprintf("  %s:\n", colorField("Keybags")))
		for i, kb := range p.Keybags {
			sb.WriteString(fmt.Sprintf("    [%d] %s: %s\n", i, colorField("Type"), kb.Type.String()))
			sb.WriteString(fmt.Sprintf("        %s:   %x\n", colorField("IV"), kb.IV))
			sb.WriteString(fmt.Sprintf("        %s:  %x\n", colorField("Key"), kb.Key))
		}
	}
	if p.Properties != nil {
		sb.WriteString(fmt.Sprintf("  %s:\n", colorField("Properties")))
		for k, v := range p.Properties {
			sb.WriteString(fmt.Sprintf("    %s: %v\n", colorSubField(k), FormatPropertyValue(v)))
		}
	}
	return sb.String()
}

func (p *Payload) MarshalJSON() ([]byte, error) {
	data := map[string]any{
		"tag":         p.Tag,
		"type":        p.Type,
		"version":     p.Version,
		"data_size":   len(p.Data),
		"encrypted":   p.Encrypted,
		"keybags":     p.Keybags,
		"properties":  p.Properties,
		"compression": p.Compression,
		"hash":        p.Hash,
	}
	if p.HasExtraData() {
		data["extra_data_size"] = len(p.GetExtraData())
	}
	return json.Marshal(data)
}

func (p *Payload) Marshal() ([]byte, error) {
	return asn1.Marshal(p.IM4P)
}

func (p *Payload) Decompress() ([]byte, error) {
	if p.decompressedData != nil {
		return p.decompressedData, nil
	}
	// confirm that the payload is compressed and detect compression type
	isCompressed := false
	hasCompressField := false

	var detectedAlgorithm CompressionAlgorithm
	if p.Compression.UncompressedSize > 0 {
		isCompressed = true
		hasCompressField = true
		detectedAlgorithm = p.Compression.Algorithm
	} else if isLzss, err := magic.IsLZSS(p.Data); err != nil {
		return nil, fmt.Errorf("failed to check if data is LZSS: %v", err)
	} else if isLzss {
		isCompressed = true
		detectedAlgorithm = CompressionAlgorithmLZSS
	} else if isLzfse, err := magic.IsLZFSE(p.Data); err != nil {
		return nil, fmt.Errorf("failed to check if data is LZFSE: %v", err)
	} else if isLzfse {
		isCompressed = true
		detectedAlgorithm = CompressionAlgorithmLZFSE
	}
	if !isCompressed {
		return nil, ErrNotCompressed
	}

	switch detectedAlgorithm {
	case CompressionAlgorithmLZSS:
		if len(p.Data) < binary.Size(lzss.Header{}) {
			return nil, fmt.Errorf("data too short to contain valid LZSS header")
		}
		var hdr lzss.Header
		if err := binary.Read(bytes.NewReader(p.Data[:binary.Size(hdr)]), binary.BigEndian, &hdr); err != nil {
			return nil, fmt.Errorf("failed to read LZSS header: %v", err)
		}
		if hdr.Signature != lzss.Signature || hdr.CompressionType != lzss.CompressionType {
			return nil, fmt.Errorf("invalid LZSS header magic: %x", string(p.Data[:8]))
		}
		if hdr.CompressedSize == 0 {
			return nil, fmt.Errorf("LZSS header indicates zero compressed size")
		}
		if len(p.Data) < int(hdr.CompressedSize)+binary.Size(hdr) {
			return nil, fmt.Errorf("data too short to contain valid LZSS compressed payload")
		}
		// Only decompress the compressed payload part, not any extra data
		compressedData := p.Data[binary.Size(hdr) : binary.Size(hdr)+int(hdr.CompressedSize)]
		decompressed := lzss.Decompress(compressedData)
		if len(decompressed) == 0 {
			return nil, fmt.Errorf("failed to decompress LZSS payload: got empty result")
		}
		// Trim decompressed data to the expected uncompressed size
		if len(decompressed) > int(hdr.UncompressedSize) {
			log.Warnf("trimming decompressed LZSS data from %d to expected size %d", len(decompressed), hdr.UncompressedSize)
			decompressed = decompressed[:hdr.UncompressedSize]
		} else if len(decompressed) < int(hdr.UncompressedSize) {
			return nil, fmt.Errorf("decompressed LZSS size (%d) is less than expected size (%d)", len(decompressed), hdr.UncompressedSize)
		}
		p.decompressedData = decompressed
		if len(p.Data) > int(hdr.CompressedSize)+binary.Size(hdr) {
			// Extract any extra data after the LZSS payload
			p.extraData = p.Data[int(hdr.CompressedSize)+binary.Size(hdr):]
			if len(p.extraData) > 0 {
				log.Debugf("extracted %d bytes of extra data after LZSS payload", len(p.extraData))
			}
		}
		if !hasCompressField {
			p.Compression.Algorithm = detectedAlgorithm
			p.Compression.UncompressedSize = len(decompressed)
		}
		return decompressed, nil
	case CompressionAlgorithmLZFSE:
		if len(p.Data) < 4 {
			return nil, fmt.Errorf("data too short to contain valid LZFSE header")
		}
		if isLzfse, err := magic.IsLZFSE(p.Data); err != nil {
			return nil, fmt.Errorf("failed to check if data is LZFSE: %v", err)
		} else if !isLzfse {
			return nil, fmt.Errorf("data is not LZFSE compressed")
		}
		// Use the comp package for decompression
		var algo comp.Algorithm
		if p.Type == IM4P_IBOOT ||
			p.Type == IM4P_IBOOT_DATA ||
			p.Type == IM4P_IBOOT_TEST ||
			p.Type == IM4P_IBEC ||
			p.Type == IM4P_IBSS ||
			p.Type == IM4P_LLB ||
			p.Type == IM4P_CFE_LOADER {
			algo = comp.LZFSE_IBOOT
		} else {
			algo = comp.LZFSE
		}
		decompressed, err := comp.Decompress(p.Data, algo)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress %s payload: %v", detectedAlgorithm.String(), err)
		}
		if len(decompressed) == 0 {
			return nil, fmt.Errorf("failed to decompress %s payload", detectedAlgorithm.String())
		}
		p.decompressedData = decompressed
		// Extract any extra data after the LZFSE payload
		p.extraData = p.extractExtraDataFromLzfse(p.Data)
		if len(p.extraData) > 0 {
			log.Debugf("extracted %d bytes of extra data after LZFSE payload", len(p.extraData))
		}
		if !hasCompressField {
			p.Compression.Algorithm = detectedAlgorithm
			p.Compression.UncompressedSize = len(decompressed)
		}
		return decompressed, nil
	}

	return nil, fmt.Errorf("unsupported compression algorithm: %v", detectedAlgorithm)
}

func (i *Payload) GetData() ([]byte, error) {
	data, err := i.Decompress()
	if err != nil {
		if err == ErrNotCompressed {
			return i.Data, nil // Return original data if not compressed
		}
		return nil, fmt.Errorf("failed to get decompressed data: %v", err)
	}
	return data, nil
}

// HasExtraData returns true if extra data was detected in the IM4P
func (i *Payload) HasExtraData() bool {
	return len(i.GetExtraData()) > 0
}

// GetExtraData returns any extra data appended after the compressed payload
func (i *Payload) GetExtraData() []byte {
	if i.decompressedData == nil {
		if _, err := i.Decompress(); err != nil && err != ErrNotCompressed {
			log.Errorf("failed to decompress payload to get extra data: %v", err)
			return nil
		}
	}
	return i.extraData
}

// extractExtraDataFromLzfse extracts extra data from LZFSE compressed format
// LZFSE uses block-based format, so we need to parse all blocks to find total size
func (i *Payload) extractExtraDataFromLzfse(data []byte) []byte {
	// Parse LZFSE blocks to determine total compressed size
	totalCompressedSize, err := i.calculateLzfseTotalSize(data)
	if err != nil {
		return nil
	}

	// Check if there's extra data after the LZFSE stream
	if totalCompressedSize >= len(data) {
		// No extra data
		return nil
	}

	// Return the extra data portion
	extraData := make([]byte, len(data)-totalCompressedSize)
	copy(extraData, data[totalCompressedSize:])
	return extraData
}

// calculateLzfseTotalSize parses LZFSE blocks to determine total compressed stream size
func (i *Payload) calculateLzfseTotalSize(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("data too short to contain LZFSE block magic")
	}

	// Verify that data starts with valid LZFSE block magic
	firstMagic := binary.LittleEndian.Uint32(data[0:4])
	switch firstMagic {
	case 0x2d787662, // bvx- (uncompressed block)
		0x31787662, // bvx1 (lzfse compressed, uncompressed tables)
		0x32787662, // bvx2 (lzfse compressed, compressed tables)
		0x6e787662: // bvxn (lzvn compressed)
		// Valid starting block magic
	default:
		return 0, fmt.Errorf("data does not start with valid LZFSE block magic: %#08x", firstMagic)
	}

	// Search for the end-of-stream marker (bvx$)
	endMarker := []byte{'b', 'v', 'x', '$'}
	endOffset := bytes.Index(data, endMarker)
	if endOffset != -1 {
		return endOffset + 4, nil
	}

	// If no end-of-stream marker is found, it's an invalid LZFSE stream
	return 0, fmt.Errorf("LZFSE end-of-stream marker (bvx$) not found")
}

/* PAYLOAD KEYBAGS */

type keybagType int

const (
	PRODUCTION  keybagType = 1
	DEVELOPMENT keybagType = 2
	DECRYPTED   keybagType = 3
)

func (t keybagType) String() string {
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

func (t keybagType) Short() string {
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
	Type keybagType
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

type Im4pKeybag struct {
	Name    string   `json:"name,omitempty"`
	Keybags []Keybag `json:"kbags,omitempty"`
}

type KeybagMetaData struct {
	Type    string   `json:"type,omitempty"`
	Version string   `json:"product_version,omitempty"`
	Build   string   `json:"product_build_version,omitempty"`
	Devices []string `json:"supported_product_types,omitempty"`
}

type KeyBags struct {
	KeybagMetaData
	Files []Im4pKeybag `json:"files,omitempty"`
}

func GetKeybagsFromIPSW(files []*zip.File, meta KeybagMetaData, pattern string) (*KeyBags, error) {
	kbags := &KeyBags{KeybagMetaData: meta}

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
			data, err := io.ReadAll(rc)
			if err != nil {
				log.Errorf("failed to read zipped file %s: %v", f.Name, err)
				if err := rc.Close(); err != nil {
					log.Errorf("failed to close zipped file %s: %v", f.Name, err)
				}
				continue
			}
			im4p, err := ParsePayload(data)
			if err != nil {
				log.Errorf("failed to parse im4p %s: %v", f.Name, err)
			}
			if im4p.Keybags == nil { // kbags are optional
				continue
			}
			kbags.Files = append(kbags.Files, Im4pKeybag{
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

/* CREATE PAYLOAD */

type CreatePayloadConfig struct {
	Type        string
	Version     string
	Data        []byte
	ExtraData   []byte // Optional extra data to append after the main data
	Compression string
	Keybags     []Keybag
}

// CreatePayload creates a new IM4P structure
func CreatePayload(conf *CreatePayloadConfig) (*Payload, error) {
	var pdata []byte

	var compAlgo CompressionAlgorithm
	switch strings.ToLower(conf.Compression) {
	case "lzss":
		compAlgo = CompressionAlgorithmLZSS
	case "lzfse", "lzfse_iboot":
		compAlgo = CompressionAlgorithmLZFSE
	case "none", "":
		compAlgo = CompressionAlgorithmMAX // No compression
	}

	switch compAlgo {
	case CompressionAlgorithmLZSS:
		compressedData := lzss.Compress(conf.Data)
		if len(compressedData) == 0 {
			return nil, fmt.Errorf("failed to LZSS compress data")
		}
		utils.Indent(log.Debug, 2)(
			fmt.Sprintf("LZSS compression: %d → %d bytes (%.1f%% reduction)",
				len(conf.Data), len(compressedData),
				float64(len(conf.Data)-len(compressedData))/float64(len(conf.Data))*100),
		)
		hdr := lzss.Header{
			Signature:        lzss.Signature,
			CompressionType:  lzss.CompressionType,
			CheckSum:         adler32.Checksum(conf.Data), // Calculate Adler32 of uncompressed data
			UncompressedSize: uint32(len(conf.Data)),
			CompressedSize:   uint32(len(compressedData)),
			Version:          1, // LZSS version
		}
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.BigEndian, hdr); err != nil {
			return nil, fmt.Errorf("failed to write LZSS header: %v", err)
		}
		if _, err := buf.Write(compressedData); err != nil {
			return nil, fmt.Errorf("failed to write LZSS compressed data: %v", err)
		}
		pdata = append(buf.Bytes(), conf.ExtraData...) // Append any extra data after the compressed payload
	case CompressionAlgorithmLZFSE:
		var algo comp.Algorithm
		if strings.ToLower(conf.Compression) == "lzfse_iboot" {
			algo = comp.LZFSE_IBOOT
		} else {
			algo = comp.LZFSE
		}
		compressedData, err := comp.Compress(conf.Data, algo)
		if err != nil {
			return nil, fmt.Errorf("failed to %s compress data: %v", conf.Compression, err)
		}
		if len(compressedData) == 0 {
			return nil, fmt.Errorf("failed to %s compress data", conf.Compression)
		}
		utils.Indent(log.Debug, 2)(
			fmt.Sprintf("%s compression: %d → %d bytes (%.1f%% reduction)",
				conf.Compression,
				len(conf.Data), len(compressedData),
				float64(len(conf.Data)-len(compressedData))/float64(len(conf.Data))*100),
		)
		pdata = append(compressedData, conf.ExtraData...)
	default:
		pdata = append(conf.Data, conf.ExtraData...)
	}

	im4p := &Payload{
		IM4P: IM4P{
			Tag:     "IM4P",
			Type:    conf.Type,
			Version: conf.Version,
			Data:    pdata,
		},
	}

	// Add the compression block if a compression algorithm was used and there's no extra data.
	if len(conf.ExtraData) == 0 {
		switch compAlgo {
		case CompressionAlgorithmLZSS, CompressionAlgorithmLZFSE:
			im4p.Compression = Compression{
				Algorithm:        compAlgo,
				UncompressedSize: len(conf.Data),
			}
		}
	}

	if len(conf.Keybags) > 0 {
		data, err := asn1.Marshal(conf.Keybags)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal keybags: %v", err)
		}
		im4p.Keybag = data
		im4p.Keybags = conf.Keybags
		im4p.Encrypted = true
	}

	return im4p, nil
}

/* Payload Processing Functions */

// DecryptPayload decrypts an IM4P payload using AES-CBC with provided IV and key
func DecryptPayload(inputPath, outputPath string, iv, key []byte) error {
	i, err := OpenPayload(inputPath)
	if err != nil {
		return fmt.Errorf("unable to parse IM4P: %v", err)
	}

	if len(i.Data) < aes.BlockSize {
		return fmt.Errorf("IM4P data too short")
	}
	if len(i.Data)%aes.BlockSize != 0 {
		return fmt.Errorf("IM4P data is not a multiple of the block size")
	}
	if len(iv) != aes.BlockSize {
		return fmt.Errorf("IV must be %d bytes, got %d", aes.BlockSize, len(iv))
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}

	data, err := decryptData(i.Data, iv, key)
	if err != nil {
		return err
	}

	of, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", outputPath, err)
	}
	defer func() {
		if err := of.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()

	var r io.Reader

	// Check for LZSS compression and decompress if needed
	if isLzss, err := magic.IsLZSS(data); err != nil {
		return fmt.Errorf("failed to check if data is LZSS: %v", err)
	} else if isLzss {
		log.Debug("Detected LZSS compression")
		decompressed := lzss.Decompress(data)
		if len(decompressed) == 0 {
			return fmt.Errorf("failed to LZSS decompress %s", inputPath)
		}
		r = bytes.NewReader(decompressed)
	} else if isLzfse, err := magic.IsLZFSE(data); err != nil { // Check for LZFSE compression and decompress if needed
		return fmt.Errorf("failed to check if data is LZFSE: %v", err)
	} else if isLzfse {
		log.Debug("Detected LZFSE compression")
		// Determine if it's LZFSE_IBOOT based on the payload type
		// TODO: this is an assumption that Apple uses LZFSE_IBOOT for iBoot-related payloads (might be dumb)
		var algo comp.Algorithm
		if i.Type == IM4P_IBOOT || i.Type == IM4P_IBEC || i.Type == IM4P_IBSS || i.Type == IM4P_LLB {
			algo = comp.LZFSE_IBOOT
		} else {
			algo = comp.LZFSE
		}
		decompressed, err := comp.Decompress(data, algo)
		if err != nil {
			return fmt.Errorf("failed to decompress %s: %v", inputPath, err)
		}
		if len(decompressed) == 0 {
			return fmt.Errorf("failed to LZFSE decompress %s", inputPath)
		}
		r = bytes.NewReader(decompressed)
	} else {
		r = bytes.NewReader(data)
	}

	if _, err := io.Copy(of, r); err != nil {
		return fmt.Errorf("failed to write decrypted data to file %s: %v", outputPath, err)
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
