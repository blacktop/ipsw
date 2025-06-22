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
	"github.com/blacktop/go-plist"
	"github.com/blacktop/lzfse-cgo"
)

// ASN.1 Private Tag Constants
const (
	// Manifest tags
	typeMANB = "private,tag:1296125506" // MANB
	typeMANP = "private,tag:1296125520" // MANP
	typeBNCN = "private,tag:1112425294" // BNCN

	// Manifest property tags
	typeBNCH = "private,tag:1112425288" // BNCH
	typeBORD = "private,tag:1112494660" // BORD
	typeCEPO = "private,tag:1128616015" // CEPO
	typeCHIP = "private,tag:1128810832" // CHIP
	typeCPRO = "private,tag:1129337423" // CPRO
	typeCSEC = "private,tag:1129530691" // CSEC
	typeECID = "private,tag:1162037572" // ECID
	typeSDOM = "private,tag:1396985677" // SDOM
	typeSnon = "private,tag:1936617326" // snon
	typeSrvn = "private,tag:1936881262" // srvn

	// SEPI tags
	typeImpl = "private,tag:1768779884" // impl
	typeArms = "private,tag:1634889075" // arms
	typeTbmr = "private,tag:1952607602" // tbmr
	typeTbms = "private,tag:1952607603" // tbms
	typeTz0s = "private,tag:1954164851" // tz0s
)

// Core IMG4 Types
type Img4 struct {
	Name        string
	Description string
	Manifest    Manifest
	RestoreInfo RestoreInfo
}

type Manifest struct {
	Properties   ManifestProperties
	ApImg4Ticket asn1.RawValue
	img4Manifest
}

type RestoreInfo struct {
	Generator dataProp
	img4RestoreInfo
}

type img4 struct {
	Raw         asn1.RawContent
	Name        string // IMG4
	IM4P        im4p
	Manifest    asn1.RawValue   `asn1:"explicit,tag:0,optional"`
	RestoreInfo img4RestoreInfo `asn1:"explicit,tag:1,optional"`
}

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

// Internal ASN.1 Types
type img4RestoreInfo struct {
	Raw       asn1.RawContent
	Name      string // IM4R
	Generator asn1.RawValue
}

type img4Manifest struct {
	Raw     asn1.RawContent
	Name    string // IM4M
	Version int
	Body    asn1.RawValue
	Data    []byte
}

type manifestBody struct {
	Raw        asn1.RawContent
	Name       string // MANB
	Properties asn1.RawValue
}

type manifestProperties struct {
	Raw        asn1.RawContent
	Name       string // MANP
	Properties asn1.RawValue
}

// Property Types
type idProp struct {
	Raw  asn1.RawContent
	Name string
	ID   int
}

type dataProp struct {
	Raw  asn1.RawContent
	Name string
	Data []byte
}

type boolProp struct {
	Raw  asn1.RawContent
	Name string
	Bool bool
}

type ManifestProperties map[string]any

// Specific Property Types (embedded types for organization)
type (
	BNCH struct{ dataProp }
	BORD struct{ idProp }
	CEPO struct{ idProp }
	CHIP struct{ idProp }
	CPRO struct{ boolProp }
	CSEC struct{ boolProp }
	ECID struct{ idProp }
	SDOM struct{ idProp }
	snon struct{ dataProp }
	srvn struct{ dataProp }
	arms struct{ idProp }
	tbmr struct{ dataProp }
	tbms struct{ dataProp }
	tz0s struct{ idProp }
)

// Common buffer reading helper
func readBuffer(r io.Reader) ([]byte, error) {
	data := new(bytes.Buffer)
	if _, err := data.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("failed to read data: %v", err)
	}
	return data.Bytes(), nil
}

// Generic property parser
func parseProperty[T any](data []byte, pType string) (*T, []byte, error) {
	var props []T
	rest, err := asn1.UnmarshalWithParams(data, &props, pType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to ASN.1 parse property %s: %v", pType, err)
	}
	if len(props) == 0 {
		return nil, nil, fmt.Errorf("no properties found for type %s", pType)
	}
	return &props[0], rest, nil
}

// Specific property parsers (for backward compatibility)
func parseDataProp(data []byte, pType string) (*dataProp, []byte, error) {
	return parseProperty[dataProp](data, pType)
}

func parseIDProp(data []byte, pType string) (*idProp, []byte, error) {
	return parseProperty[idProp](data, pType)
}

func parseBoolProp(data []byte, pType string) (*boolProp, []byte, error) {
	return parseProperty[boolProp](data, pType)
}

// Property definition for ordered parsing
type propertyDef struct {
	tag       string
	parseFunc func([]byte, string) (any, []byte, error)
	storeFunc func(ManifestProperties, string, any)
}

var manifestPropertyDefs = []propertyDef{
	{typeBNCH, parseDataProperty, storeDataProperty},
	{typeBORD, parseIDProperty, storeIDProperty},
	{typeCEPO, parseIDProperty, storeIDProperty},
	{typeCHIP, parseIDProperty, storeIDProperty},
	{typeCPRO, parseBoolProperty, storeBoolProperty},
	{typeCSEC, parseBoolProperty, storeBoolProperty},
	{typeECID, parseIDProperty, storeIDProperty},
	{typeSDOM, parseIDProperty, storeIDProperty},
	{typeSnon, parseDataProperty, storeDataProperty},
	{typeSrvn, parseDataProperty, storeDataProperty},
}

// Property parsers and storage functions
func parseDataProperty(data []byte, pType string) (any, []byte, error) {
	return parseDataProp(data, pType)
}

func parseIDProperty(data []byte, pType string) (any, []byte, error) {
	return parseIDProp(data, pType)
}

func parseBoolProperty(data []byte, pType string) (any, []byte, error) {
	return parseBoolProp(data, pType)
}

func storeDataProperty(props ManifestProperties, name string, value any) {
	if prop, ok := value.(*dataProp); ok {
		props[prop.Name] = prop.Data
	}
}

func storeIDProperty(props ManifestProperties, name string, value any) {
	if prop, ok := value.(*idProp); ok {
		props[prop.Name] = prop.ID
	}
}

func storeBoolProperty(props ManifestProperties, name string, value any) {
	if prop, ok := value.(*boolProp); ok {
		props[prop.Name] = prop.Bool
	}
}

func parseManifestProperties(data []byte) (*ManifestProperties, error) {
	mProps := make(ManifestProperties)
	remaining := data

	for _, def := range manifestPropertyDefs {
		value, rest, err := def.parseFunc(remaining, def.tag)
		if err != nil {
			return nil, fmt.Errorf("failed to parse property %s: %v", def.tag, err)
		}
		def.storeFunc(mProps, def.tag, value)
		remaining = rest
	}

	return &mProps, nil
}

// Parse parses a Img4
func Parse(r io.Reader) (*Img4, error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}

	var i img4
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	result := &Img4{
		Name:        i.IM4P.Name,
		Description: i.IM4P.Description,
	}

	// Parse manifest if present
	if err := parseManifest(&i, result); err != nil {
		return nil, err
	}

	// Parse restore info if present
	if err := parseRestoreInfo(&i, result); err != nil {
		return nil, err
	}

	return result, nil
}

func parseManifest(i *img4, result *Img4) error {
	if len(i.Manifest.Bytes) == 0 {
		return nil
	}

	var m img4Manifest
	if _, err := asn1.Unmarshal(i.Manifest.Bytes, &m); err != nil {
		return fmt.Errorf("failed to ASN.1 parse Img4 manifest: %v", err)
	}

	var mb []manifestBody
	if _, err := asn1.UnmarshalWithParams(m.Body.Bytes, &mb, typeMANB); err != nil {
		return fmt.Errorf("failed to ASN.1 parse Img4 manifest body: %v", err)
	}

	var mProps []manifestProperties
	if _, err := asn1.UnmarshalWithParams(mb[0].Properties.Bytes, &mProps, typeMANP); err != nil {
		return fmt.Errorf("failed to ASN.1 parse Img4 manifest properties: %v", err)
	}

	props, err := parseManifestProperties(mProps[0].Properties.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse Img4 manifest properties: %v", err)
	}

	result.Manifest = Manifest{
		Properties:   *props,
		ApImg4Ticket: i.Manifest,
		img4Manifest: m,
	}

	return nil
}

func parseRestoreInfo(i *img4, result *Img4) error {
	if i.RestoreInfo.Name == "" {
		return nil
	}

	// Try the complex parseDataProp approach first (for legacy IM4R files)
	if gen, _, err := parseDataProp(i.RestoreInfo.Generator.Bytes, typeBNCN); err == nil {
		result.RestoreInfo = RestoreInfo{
			Generator:       *gen,
			img4RestoreInfo: i.RestoreInfo,
		}
		return nil
	}

	// If that fails, try parsing our simplified format
	if len(i.RestoreInfo.Generator.Bytes) > 0 {
		bootNonce, err := parseStandaloneIm4rGenerator(i.RestoreInfo.Generator.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse IM4R generator data: %v", err)
		}

		// Create a dataProp structure from the parsed boot nonce
		gen := &dataProp{
			Name: "BNCN",
			Data: bootNonce,
		}

		result.RestoreInfo = RestoreInfo{
			Generator:       *gen,
			img4RestoreInfo: i.RestoreInfo,
		}
		return nil
	}

	return fmt.Errorf("no generator data found in restore info")
}

func OpenIm4p(path string) (*Im4p, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()
	return ParseIm4p(f)
}

// ParseIm4r parses a standalone IM4R file and returns the restore info
func ParseIm4r(r io.Reader) (*RestoreInfo, error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}

	var restoreInfo img4RestoreInfo
	if _, err := asn1.Unmarshal(data, &restoreInfo); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse IM4R: %v", err)
	}

	if restoreInfo.Name != "IM4R" {
		return nil, fmt.Errorf("invalid IM4R file: expected name 'IM4R', got '%s'", restoreInfo.Name)
	}

	// For standalone IM4R files, the generator data may be structured differently
	// than when embedded in IMG4 files. Try multiple parsing approaches.
	
	// First, try the standard parseDataProp approach (for IMG4-embedded IM4R)
	if gen, _, err := parseDataProp(restoreInfo.Generator.Bytes, typeBNCN); err == nil {
		return &RestoreInfo{
			Generator:       *gen,
			img4RestoreInfo: restoreInfo,
		}, nil
	}

	// If that fails, try parsing as a raw BNCN structure for standalone IM4R files
	if len(restoreInfo.Generator.Bytes) > 0 {
		// Try to parse the generator bytes directly
		bootNonce, err := parseStandaloneIm4rGenerator(restoreInfo.Generator.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse IM4R generator data: %v", err)
		}

		// Create a dataProp structure from the parsed boot nonce
		gen := &dataProp{
			Name: "BNCN",
			Data: bootNonce,
		}

		return &RestoreInfo{
			Generator:       *gen,
			img4RestoreInfo: restoreInfo,
		}, nil
	}

	return nil, fmt.Errorf("no generator data found in IM4R")
}

// parseStandaloneIm4rGenerator parses generator data from standalone IM4R files
func parseStandaloneIm4rGenerator(data []byte) ([]byte, error) {
	// For standalone IM4R files, the structure might be different
	// Based on the reference implementations, look for BNCN tag and extract boot nonce
	
	// Check if data contains "BNCN" directly (simple format)
	if bytes.Contains(data, []byte("BNCN")) {
		// Find BNCN and extract the following data
		bncnIndex := bytes.Index(data, []byte("BNCN"))
		if bncnIndex != -1 && len(data) >= bncnIndex+4+8 { // BNCN + 8 bytes boot nonce
			return data[bncnIndex+4 : bncnIndex+4+8], nil
		}
	}

	// Try parsing as ASN.1 OCTET STRING (our created format)
	var bootNonce []byte
	if _, err := asn1.Unmarshal(data, &bootNonce); err == nil && len(bootNonce) == 8 {
		return bootNonce, nil
	}

	// Try parsing the raw bytes if they look like a boot nonce (8 bytes)
	if len(data) == 8 {
		return data, nil
	}

	// Last resort: if data ends with 8 bytes that could be a boot nonce
	if len(data) >= 8 {
		return data[len(data)-8:], nil
	}

	return nil, fmt.Errorf("could not extract boot nonce from generator data")
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

	// Check for extra data at the end of the Data field
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

// detectAndSeparateExtraData detects and separates extra metadata
func detectAndSeparateExtraData(i *Im4p) error {
	if len(i.Data) == 0 {
		return nil
	}

	originalDataLen := len(i.Data)

	// First, try to detect extra data using content-based heuristics
	if extraSize := detectExtraDataAdvanced(i.Data); extraSize > 0 {
		// Store the extra data before separating it
		i.ExtraDataBytes = make([]byte, extraSize)
		copy(i.ExtraDataBytes, i.Data[originalDataLen-extraSize:])

		// Separate the extra data from the main payload
		i.Data = i.Data[:originalDataLen-extraSize]
		i.ExtraDataSize = extraSize

		log.Debugf("Detected and separated %d bytes of extra data from payload", extraSize)
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
			// Store the extra data before separating it
			i.ExtraDataBytes = make([]byte, extraSize)
			copy(i.ExtraDataBytes, candidateExtra)

			// Separate the extra data from the main payload
			i.Data = i.Data[:candidateExtraStart]
			i.ExtraDataSize = extraSize

			log.Debugf("Detected and separated %d bytes of extra data from payload (fallback)", extraSize)
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

// GetExtraData returns any extra data that was detected and separated from the payload
func (i *Im4p) GetExtraData() []byte {
	return i.ExtraDataBytes
}

// HasExtraData returns true if extra data was detected in the IM4P
func (i *Im4p) HasExtraData() bool {
	return i.ExtraDataSize > 0
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

func OpenImg4(path string) (*img4, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close file: %v", err)
		}
	}()
	return ParseImg4(f)
}

func ParseImg4(r io.Reader) (*img4, error) {
	data, err := readBuffer(r)
	if err != nil {
		return nil, err
	}

	var i img4
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	return &i, nil
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

// CreateImg4File creates a complete IMG4 file from component files
func CreateImg4File(im4pData, manifestData, restoreInfoData []byte) ([]byte, error) {
	if len(im4pData) == 0 {
		return nil, fmt.Errorf("IM4P payload data is required")
	}

	img4Struct := img4{
		Name: "IMG4",
	}

	// Parse the IM4P data to embed it
	var im4pParsed im4p
	if _, err := asn1.Unmarshal(im4pData, &im4pParsed); err != nil {
		return nil, fmt.Errorf("failed to parse IM4P data: %v", err)
	}
	img4Struct.IM4P = im4pParsed

	// Add optional manifest data with explicit tag:0
	if len(manifestData) > 0 {
		img4Struct.Manifest = asn1.RawValue{
			FullBytes: manifestData,
		}
	}

	// Add optional restore info data with explicit tag:1
	if len(restoreInfoData) > 0 {
		img4Struct.RestoreInfo = img4RestoreInfo{
			Name: "IM4R",
			Generator: asn1.RawValue{
				FullBytes: restoreInfoData,
			},
		}
	}

	return asn1.Marshal(img4Struct)
}

// DetectFileType attempts to detect if a file is IMG4 or IM4P by examining its structure
func DetectFileType(r io.Reader) (string, error) {
	data, err := readBuffer(r)
	if err != nil {
		return "", err
	}

	var img4Test img4
	if _, err := asn1.Unmarshal(data, &img4Test); err == nil && img4Test.Name == "IMG4" {
		return "IMG4", nil
	}

	var im4pTest im4p
	if _, err := asn1.Unmarshal(data, &im4pTest); err == nil && im4pTest.Name == "IM4P" {
		return "IM4P", nil
	}

	return "", fmt.Errorf("unknown file type - not IMG4 or IM4P")
}

/* SHSH Extraction Functions */

// ExtractManifestFromShsh extracts IM4M manifest from SHSH blob with proper ASN.1 parsing
func ExtractManifestFromShsh(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read SHSH data: %v", err)
	}

	// Look for direct IM4M signature in the data
	im4mSig := []byte("IM4M")
	if idx := bytes.Index(data, im4mSig); idx != -1 {
		return extractManifestFromRawData(data, idx)
	}

	// Look for plist structure with ApImg4Ticket
	if bytes.Contains(data, []byte("ApImg4Ticket")) {
		return extractManifestFromPlistShsh(data)
	}

	return nil, fmt.Errorf("no recognizable IM4M manifest found in SHSH blob")
}

func extractManifestFromRawData(data []byte, startIdx int) ([]byte, error) {
	remainder := data[startIdx:]

	// Try to parse the ASN.1 structure to determine the correct length
	var manifest img4Manifest
	if _, err := asn1.Unmarshal(remainder, &manifest); err == nil {
		return manifest.Raw, nil
	}

	// Fallback to simple search approach
	manifestEnd := len(data)
	for i := startIdx + 4; i < len(data)-3; i++ {
		if bytes.Equal(data[i:i+4], []byte("IM4R")) ||
			bytes.Equal(data[i:i+4], []byte("IM4P")) {
			manifestEnd = i
			break
		}
	}

	if manifestEnd <= startIdx+4 {
		return nil, fmt.Errorf("invalid manifest structure in SHSH blob")
	}

	return data[startIdx:manifestEnd], nil
}

func extractManifestFromPlistShsh(data []byte) ([]byte, error) {
	var shsh struct {
		ApImg4Ticket []byte `plist:"ApImg4Ticket"`
		Generator    string `plist:"generator,omitempty"`
		BBTicket     []byte `plist:"BBTicket,omitempty"`
	}

	decoder := plist.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&shsh); err != nil {
		return nil, fmt.Errorf("failed to decode SHSH plist: %v", err)
	}

	if len(shsh.ApImg4Ticket) == 0 {
		return nil, fmt.Errorf("no ApImg4Ticket found in SHSH plist")
	}

	return shsh.ApImg4Ticket, nil
}

/* Validation Functions */

// ValidateImg4Structure performs structural validation on an IMG4 file
func ValidateImg4Structure(r io.Reader) (*ValidationResult, error) {
	img, err := Parse(r)
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

func validateComponents(img *Img4, result *ValidationResult) {
	if img.Name == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, "Missing IMG4 name")
	} else {
		result.Components = append(result.Components, "name")
	}

	if img.Description == "" {
		result.Warnings = append(result.Warnings, "Missing description")
	}

	if len(img.Manifest.Properties) == 0 {
		result.Warnings = append(result.Warnings, "No manifest properties found")
	} else {
		result.Components = append(result.Components, "manifest")
		validateCriticalProperties(img.Manifest.Properties, result)
	}
}

func validateCriticalProperties(props ManifestProperties, result *ValidationResult) {
	criticalProps := []string{"CHIP", "BORD"}
	for _, prop := range criticalProps {
		if _, exists := props[prop]; !exists {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Missing critical property: %s", prop))
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
