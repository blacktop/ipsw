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
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"

	"github.com/apex/log"
	"github.com/blacktop/lzfse-cgo"
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
	IM4P_KERNEL_CACHE     = "krnl" // KernelCache
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

// IM4P Types
type Im4p struct {
	im4p
	Kbags            []Keybag
	CompressionType  string         // LZFSE, LZSS, or none
	UncompressedSize int            // Size after decompression
	Properties       map[string]any // Parsed properties like kcep, kclf, etc.
	ExtraDataSize    int            // Size of extra data (like trailing metadata)
	ExtraDataBytes   []byte         // The actual extra data bytes that were separated
	Encrypted        bool           // Whether the IM4P is encrypted
}

type im4p struct {
	Raw         asn1.RawContent
	Name        string `asn1:"ia5"` // IM4P
	Type        string `asn1:"ia5"`
	Description string `asn1:"ia5"`
	Data        []byte
	KbagData    []byte        `asn1:"optional"`
	ExtraData   asn1.RawValue `asn1:"optional"`                              // May contain size info
	Properties  asn1.RawValue `asn1:"optional,tag:0,class:context,explicit"` // PAYP properties
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
			if im4p.Kbags == nil { // kbags are optional
				continue
			}
			kbags.Files = append(kbags.Files, im4pKBag{
				Name:    filepath.Base(f.Name),
				Keybags: im4p.Kbags,
			})
			if err := rc.Close(); err != nil {
				log.Errorf("failed to close zipped file %s: %v", f.Name, err)
			}
		}
	}

	return kbags, nil
}

// CreateIm4p creates a new IM4P structure
func CreateIm4p(name, fourcc, description string, data []byte, kbags []Keybag) *Im4p {
	return CreateIm4pWithExtra(name, fourcc, description, data, kbags, nil)
}

// CreateIm4pWithExtra creates an IM4P structure with optional extra data
func CreateIm4pWithExtra(name, fourcc, description string, data []byte, kbags []Keybag, extraData []byte) *Im4p {
	// If extra data is provided, append it to the main data
	finalData := data
	if len(extraData) > 0 {
		finalData = append(data, extraData...)
	}

	im4pStruct := &Im4p{
		im4p: im4p{
			Name:        name,
			Type:        fourcc,
			Description: description,
			Data:        finalData,
		},
		Kbags: kbags,
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
			im4pStruct.KbagData = kbagData
		}
	}

	return im4pStruct
}

// MarshalIm4p marshals an IM4P structure to ASN.1 bytes
func MarshalIm4p(im4p *Im4p) ([]byte, error) {
	return asn1.Marshal(im4p.im4p)
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

func ParseIm4p(r io.Reader) (*Im4p, error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}

	var i Im4p

	// Try parsing with the default struct (ExtraData before Properties)
	if _, err := asn1.Unmarshal(data, &i.im4p); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Im4p: %v", err)
	}

	// If no properties found, try alternative struct ordering
	if len(i.im4p.Properties.Bytes) == 0 {
		// Define alternative struct with Properties before ExtraData
		type im4pAlt struct {
			Raw         asn1.RawContent
			Name        string `asn1:"ia5"` // IM4P
			Type        string `asn1:"ia5"`
			Description string `asn1:"ia5"`
			Data        []byte
			KbagData    []byte        `asn1:"optional"`
			Properties  asn1.RawValue `asn1:"optional,tag:0,class:context,explicit"` // PAYP properties
			ExtraData   asn1.RawValue `asn1:"optional"`                              // May contain size info
		}

		var iAlt im4pAlt
		if _, err := asn1.Unmarshal(data, &iAlt); err == nil {
			// Copy the alternative parsing result back
			i.im4p.Raw = iAlt.Raw
			i.im4p.Name = iAlt.Name
			i.im4p.Type = iAlt.Type
			i.im4p.Description = iAlt.Description
			i.im4p.Data = iAlt.Data
			i.im4p.KbagData = iAlt.KbagData
			i.im4p.Properties = iAlt.Properties
			i.im4p.ExtraData = iAlt.ExtraData
		}
	}

	if i.KbagData != nil {
		if _, err := asn1.Unmarshal(i.KbagData, &i.Kbags); err != nil {
			return nil, fmt.Errorf("failed to ASN.1 parse Im4p KBAG: %v", err)
		}
		if len(i.Kbags) > 0 {
			i.Encrypted = true
		}
	}

	// Parse extra data if present (may contain uncompressed size)
	if len(i.ExtraData.Bytes) > 0 {
		var extra []asn1.RawValue
		if _, err := asn1.Unmarshal(i.ExtraData.Bytes, &extra); err == nil && len(extra) >= 2 {
			// Check if first element is integer 1 (version/type indicator)
			var indicator int
			if _, err := asn1.Unmarshal(extra[0].FullBytes, &indicator); err == nil && indicator == 1 {
				// Second element should be the uncompressed size
				var size int
				if _, err := asn1.Unmarshal(extra[1].FullBytes, &size); err == nil {
					i.UncompressedSize = size
				}
			}
		}
	}

	// Parse PAYP properties if present
	if len(i.im4p.Properties.Bytes) > 0 {
		i.Properties = parsePayloadProperties(i.im4p.Properties.Bytes)
	} else {
		// Fallback: search for PAYP in raw data
		i.Properties = searchForPayloadProperties(data)
	}

	// Check for extra data at the end of the Data field (non-destructive)
	if err := detectAndSeparateExtraData(&i); err != nil {
		log.Debugf("Failed to detect extra data: %v", err)
	}

	// Detect compression type
	i.CompressionType = detectCompressionType(i.Data)

	return &i, nil
}

// detectCompressionType detects the compression type of the data
func detectCompressionType(data []byte) string {
	if len(data) < 4 {
		return "none"
	}

	// Check for LZFSE magic
	if bytes.Equal(data[:4], []byte("bvx2")) || bytes.Equal(data[:4], []byte("bvx-")) || bytes.Equal(data[:4], []byte("bvxn")) {
		return "LZFSE"
	}

	// Check for LZSS compression (complzss header)
	if len(data) >= 8 && bytes.Equal(data[:8], []byte("complzss")) {
		return "LZSS"
	}

	return "none"
}

// detectAndSeparateExtraData detects extra metadata but keeps original data intact
func detectAndSeparateExtraData(i *Im4p) error {
	if len(i.Data) == 0 {
		return nil
	}

	originalDataLen := len(i.Data)

	// First, try to detect extra data using content-based heuristics
	if extraSize := detectExtraDataAdvanced(i.Data); extraSize > 0 {
		// Copy the suspected extra data (non-destructive)
		i.ExtraDataBytes = make([]byte, extraSize)
		copy(i.ExtraDataBytes, i.Data[originalDataLen-extraSize:])
		i.ExtraDataSize = extraSize

		log.Debugf("Detected %d bytes of potential extra data at end of payload", extraSize)
		return nil
	}

	// Fallback to common size patterns for backward compatibility
	commonExtraDataSizes := []int{32768, 16384, 8192, 4096} // 32KB, 16KB, 8KB, 4KB

	for _, extraSize := range commonExtraDataSizes {
		if originalDataLen <= extraSize {
			continue
		}

		// Check if the last extraSize bytes contain structured data
		candidateExtraStart := originalDataLen - extraSize
		candidateExtra := i.Data[candidateExtraStart:]

		if isLikelyExtraData(candidateExtra) {
			// Copy the suspected extra data (non-destructive)
			i.ExtraDataBytes = make([]byte, extraSize)
			copy(i.ExtraDataBytes, candidateExtra)
			i.ExtraDataSize = extraSize

			log.Debugf("Detected %d bytes of potential extra data at end of payload (fallback)", extraSize)
			return nil
		}
	}

	return nil
}

// detectExtraDataAdvanced uses improved heuristics to detect extra data
// This uses multiple strategies for better accuracy
func detectExtraDataAdvanced(data []byte) int {
	if len(data) < 4096 { // Minimum reasonable size for extra data
		return 0
	}

	dataLen := len(data)

	// Strategy 1: Look for compression boundary markers
	// Extra data often starts right after compressed payload ends
	if extraSize := detectCompressionBoundary(data); extraSize > 0 {
		return extraSize
	}

	// Strategy 2: Scan for distinct entropy changes
	// Extra data typically has different entropy than payload data
	if extraSize := detectEntropyBoundary(data); extraSize > 0 {
		return extraSize
	}

	// Apple often aligns extra data to 4KB or 16KB boundaries
	pageAlignedSizes := []int{
		// Most common sizes observed in practice
		32768, // 32KB - very common for kernel caches
		16384, // 16KB - common for smaller components
		8192,  // 8KB - less common but observed
		4096,  // 4KB - minimum page size
	}

	for _, size := range pageAlignedSizes {
		if dataLen <= size {
			continue
		}

		candidateStart := dataLen - size
		candidate := data[candidateStart:]

		// Check if this looks like structured extra data
		if isExtraData(candidate) {
			return size
		}
	}

	// Strategy 4: Scan for null-padded regions (conservative approach)
	// This technique can find extra data of any size, not just common alignments
	// Made more conservative to reduce false positives
	if extraSize := detectNullPaddedExtraData(data); extraSize > 0 {
		return extraSize
	}

	return 0
}

// detectCompressionBoundary looks for the end of compressed data
func detectCompressionBoundary(data []byte) int {
	// For LZFSE compressed data, look for the natural end of the stream
	if len(data) >= 4 && bytes.Equal(data[:4], []byte("bvx2")) {
		// LZFSE has internal structure that can help identify the end
		// This is a simplified heuristic - in practice, proper LZFSE parsing
		// would be needed for 100% accuracy
		return scanForCompressionEnd(data, "lzfse")
	}

	// For LZSS compressed data
	if len(data) >= 8 && bytes.Equal(data[:8], []byte("complzss")) {
		return scanForCompressionEnd(data, "lzss")
	}

	return 0
}

// scanForCompressionEnd scans for natural end of compressed stream
func scanForCompressionEnd(data []byte, _ string) int {
	// This is a heuristic approach - look for areas where
	// data patterns change significantly (indicating end of compression)

	dataLen := len(data)
	minScanSize := 1024 // Start scanning from 1KB in

	for i := minScanSize; i < dataLen-4096; i += 4096 { // Scan in 4KB chunks
		// Look for significant pattern changes that might indicate
		// transition from compressed payload to extra data
		if hasSignificantPatternChange(data, i) {
			remainingSize := dataLen - i
			// Only consider if remaining size matches common extra data sizes
			if remainingSize == 32768 || remainingSize == 16384 ||
				remainingSize == 8192 || remainingSize == 4096 {
				return remainingSize
			}
		}
	}

	return 0
}

// detectEntropyBoundary looks for entropy changes that indicate data boundaries
func detectEntropyBoundary(data []byte) int {
	dataLen := len(data)

	// Sample entropy at different points
	sampleSize := 1024
	step := 4096

	var prevEntropy float64
	var entropyJumps []int

	for i := sampleSize; i < dataLen-sampleSize; i += step {
		if i+sampleSize >= dataLen {
			break
		}

		sample := data[i : i+sampleSize]
		entropy := calculateEntropy(sample)

		// Look for significant entropy changes
		if prevEntropy > 0 && abs(entropy-prevEntropy) > 1.5 { // Threshold tuned empirically
			entropyJumps = append(entropyJumps, i)
		}

		prevEntropy = entropy
	}

	// Check if any entropy jumps correspond to valid extra data sizes
	for _, jumpPos := range entropyJumps {
		remainingSize := dataLen - jumpPos
		if remainingSize == 32768 || remainingSize == 16384 ||
			remainingSize == 8192 || remainingSize == 4096 {
			// Additional validation: check if the data after jump looks like extra data
			if isExtraData(data[jumpPos:]) {
				return remainingSize
			}
		}
	}

	return 0
}

// isExtraData performs more sophisticated extra data detection
func isExtraData(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Extra data characteristics (based on analysis of real firmware):

	// 1. Often starts with specific patterns or is highly structured
	if hasExtraDataSignatures(data) {
		return true
	}

	// 2. High percentage of null bytes (but not 100% - that would be just padding)
	nullPercentage := calculateNullPercentage(data)
	if nullPercentage > 0.7 && nullPercentage < 0.99 { // 70-99% null bytes
		return true
	}

	// 3. Contains structured metadata patterns
	if hasStructuredMetadata(data) {
		return true
	}

	// 4. Low but non-zero entropy (indicating structure but not randomness)
	entropy := calculateEntropy(data)
	if entropy > 0.1 && entropy < 2.0 { // Low entropy range typical of extra data
		return true
	}

	return false
}

// hasExtraDataSignatures checks for known extra data signatures
func hasExtraDataSignatures(data []byte) bool {
	// Known signatures found in extra data
	signatures := [][]byte{
		[]byte("WATCHTOWER"), // Sometimes literally named
		[]byte("WTWR"),       // Abbreviated form
		[]byte("META"),       // Metadata marker
		[]byte("KERN"),       // Kernel metadata
		[]byte("KPEP"),       // Kernel performance measurement
		[]byte("AMFI"),       // Apple Mobile File Integrity
	}

	for _, sig := range signatures {
		if bytes.Contains(data, sig) {
			return true
		}
	}

	// Look for ASN.1 structures which are common in Apple metadata
	if len(data) >= 2 {
		tag := data[0]
		if tag == 0x30 || tag == 0x31 || tag == 0x04 || tag == 0x02 {
			// Basic ASN.1 validation
			return true
		}
	}

	return false
}

// hasStructuredMetadata checks for structured metadata patterns
func hasStructuredMetadata(data []byte) bool {
	// Look for repeating structures that indicate metadata

	// Check for aligned 4-byte or 8-byte structures
	alignedPatterns := 0
	for i := 0; i < len(data)-8; i += 4 {
		if i+8 < len(data) {
			// Look for patterns that repeat at regular intervals
			pattern := data[i : i+4]
			if bytes.Equal(pattern, data[i+4:i+8]) {
				alignedPatterns++
			}
		}
	}

	// If we find multiple aligned patterns, it's likely structured metadata
	return alignedPatterns > 2
}

// calculateEntropy calculates Shannon entropy of data
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (log2(p))
		}
	}

	return entropy
}

// calculateNullPercentage calculates percentage of null bytes
func calculateNullPercentage(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	nullCount := 0
	for _, b := range data {
		if b == 0 {
			nullCount++
		}
	}

	return float64(nullCount) / float64(len(data))
}

// hasSignificantPatternChange detects significant pattern changes at position
func hasSignificantPatternChange(data []byte, pos int) bool {
	if pos < 1024 || pos+1024 >= len(data) {
		return false
	}

	// Compare entropy before and after position
	before := data[pos-1024 : pos]
	after := data[pos : pos+1024]

	entropyBefore := calculateEntropy(before)
	entropyAfter := calculateEntropy(after)

	// Significant change threshold
	return abs(entropyBefore-entropyAfter) > 1.0
}

// Helper functions
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func log2(x float64) float64 {
	return math.Log(x) / math.Log(2)
}

// isLikelyExtraData checks if the given data looks like extra metadata
func isLikelyExtraData(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for ASN.1 structure at the beginning
	if len(data) >= 2 {
		// ASN.1 typically starts with a tag byte followed by length
		tag := data[0]
		// Common ASN.1 tags: SEQUENCE (0x30), SET (0x31), OCTET STRING (0x04), etc.
		if tag == 0x30 || tag == 0x31 || tag == 0x04 || tag == 0x02 {
			return true
		}
	}

	// Check for high percentage of null bytes (common in padding)
	nullCount := 0
	for _, b := range data {
		if b == 0 {
			nullCount++
		}
	}

	// If more than 50% null bytes, likely padding/metadata
	if float64(nullCount)/float64(len(data)) > 0.5 {
		return true
	}

	// Check for repeating patterns that might indicate structured metadata
	if hasRepeatingPattern(data) {
		return true
	}

	// Check for known metadata signatures
	knownSigs := [][]byte{
		[]byte("META"), []byte("SIZE"), []byte("HASH"),
		[]byte("CERT"), []byte("SIGN"), []byte("KEYS"),
	}

	for _, sig := range knownSigs {
		if bytes.Contains(data, sig) {
			return true
		}
	}

	return false
}

// hasRepeatingPattern checks if data has repeating patterns that suggest metadata
func hasRepeatingPattern(data []byte) bool {
	if len(data) < 16 {
		return false
	}

	// Check for 4-byte repeating patterns
	for i := 0; i < len(data)-12; i += 4 {
		if len(data) >= i+12 {
			pattern := data[i : i+4]
			if bytes.Equal(pattern, data[i+4:i+8]) && bytes.Equal(pattern, data[i+8:i+12]) {
				return true
			}
		}
	}

	return false
}

// detectNullPaddedExtraData detects null-padded regions that might be extra data
func detectNullPaddedExtraData(data []byte) int {
	if len(data) < 1024 {
		return 0
	}

	// Scan backwards from the end to find where null padding starts
	nullStart := -1
	consecutiveNulls := 0
	minNullSequence := 4096 // Minimum sequence of nulls to consider as padding

	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0 {
			consecutiveNulls++
			if consecutiveNulls >= minNullSequence && nullStart == -1 {
				nullStart = i
			}
		} else {
			// Found non-null byte
			if consecutiveNulls >= minNullSequence {
				break
			}
			consecutiveNulls = 0
			nullStart = -1
		}
	}

	if nullStart != -1 {
		// Check if there's structured data before the null padding
		if nullStart > 0 {
			start := max(nullStart-100, 0)
			preNullData := data[start:nullStart]
			if isLikelyExtraData(preNullData) {
				return len(data) - nullStart
			}
		}

		// If we have a large null-padded region at the end, it's likely extra data
		nullSize := len(data) - nullStart
		if nullSize >= 4096 { // At least 4KB of null padding
			return nullSize
		}
	}

	return 0
}

// GetExtraData returns any extra data that was detected from the payload
func (i *Im4p) GetExtraData() []byte {
	return i.ExtraDataBytes
}

// HasExtraData returns true if extra data was detected in the IM4P
func (i *Im4p) HasExtraData() bool {
	return i.ExtraDataSize > 0
}

// GetCleanPayloadData returns the payload data without the detected extra data
// This is useful when you want to process only the actual payload without metadata
func (i *Im4p) GetCleanPayloadData() []byte {
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
func (i *Im4p) GetExtraDataInfo() map[string]any {
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
func parsePayloadProperties(data []byte) map[string]any {
	props := make(map[string]any)

	// Parse the PAYP container
	var payp struct {
		Raw  asn1.RawContent
		Name string        // PAYP
		Set  asn1.RawValue `asn1:"set"`
	}

	if _, err := asn1.Unmarshal(data, &payp); err != nil {
		return props
	}

	if payp.Name != "PAYP" {
		return props
	}

	// Parse properties from the set
	rest := payp.Set.Bytes
	for len(rest) > 0 {
		var prop asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &prop)
		if err != nil {
			break
		}

		// Each property is a sequence with fourcc and value
		var propSeq struct {
			Raw    asn1.RawContent
			FourCC string
			Value  asn1.RawValue
		}

		if _, err := asn1.Unmarshal(prop.Bytes, &propSeq); err == nil {
			// Parse the value based on its type
			switch propSeq.Value.Tag {
			case asn1.TagInteger:
				// Try parsing as int64 first, then as big.Int for large values
				var intVal int64
				if _, err := asn1.Unmarshal(propSeq.Value.FullBytes, &intVal); err == nil {
					props[propSeq.FourCC] = intVal
				} else {
					// Parse large integer from raw bytes
					if len(propSeq.Value.Bytes) > 0 {
						bigVal := new(big.Int)
						bigVal.SetBytes(propSeq.Value.Bytes)
						if bigVal.IsUint64() {
							props[propSeq.FourCC] = bigVal.Uint64()
						} else {
							props[propSeq.FourCC] = bigVal.String()
						}
					}
				}
			case asn1.TagOctetString:
				props[propSeq.FourCC] = propSeq.Value.Bytes
			}
		}
	}

	return props
}

// searchForPayloadProperties searches for PAYP properties in raw ASN.1 data
func searchForPayloadProperties(data []byte) map[string]any {
	props := make(map[string]any)

	// Search for "PAYP" signature
	paypSig := []byte("PAYP")
	idx := bytes.Index(data, paypSig)
	if idx == -1 {
		return props
	}

	// Start parsing from a few bytes before PAYP to capture the ASN.1 structure
	start := max(idx-20, 0)

	remainder := data[start:]

	// Try to parse the PAYP container starting from various offsets
	for offset := 0; offset < 25 && offset < len(remainder); offset++ {
		testData := remainder[offset:]
		if len(testData) < 10 {
			continue
		}

		var payp struct {
			Raw  asn1.RawContent
			Name string        // PAYP
			Set  asn1.RawValue `asn1:"set"`
		}

		if _, err := asn1.Unmarshal(testData, &payp); err != nil {
			continue
		}

		if payp.Name != "PAYP" {
			continue
		}

		// Parse properties from the set
		rest := payp.Set.Bytes
		for len(rest) > 0 {
			var prop asn1.RawValue
			var err error
			rest, err = asn1.UnmarshalWithParams(rest, &prop, "private")
			if err != nil {
				break
			}

			// Each property is a sequence with fourcc and value
			var propSeq struct {
				Raw    asn1.RawContent
				FourCC string
				Value  asn1.RawValue
			}

			if _, err := asn1.Unmarshal(prop.Bytes, &propSeq); err == nil {
				// Parse the value based on its type
				switch propSeq.Value.Tag {
				case asn1.TagInteger:
					var intVal int64
					if _, err := asn1.Unmarshal(propSeq.Value.FullBytes, &intVal); err == nil {
						props[propSeq.FourCC] = intVal
					}
				case asn1.TagOctetString:
					props[propSeq.FourCC] = propSeq.Value.Bytes
				}
			}
		}

		// If we found properties, return them
		if len(props) > 0 {
			return props
		}
	}

	return props
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
	if isImg4 {
		i, err := ParseImg4(f)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IMG4: %v", err)
		}
		return i.IM4P.Data, nil
	}

	i, err := ParseIm4p(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IM4P: %v", err)
	}
	return i.Data, nil
}
