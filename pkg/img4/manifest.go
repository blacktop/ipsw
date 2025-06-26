package img4

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/fatih/color"
)

// Core ASN.1 Private Tag Constants (stable tags that won't change)
const (
	tagMANB = 1296125506 // MANB - Manifest Body
	tagMANP = 1296125520 // MANP - Manifest Properties
	tagBNCN = 1112425294 // BNCN - Boot Nonce
	tagDGST = 1145525076 // DGST - Digest
)

// Known Private Tag Constants (for documentation and type hints)
// These are the private tags we've observed in Apple firmware manifests
const (
	// Manifest Properties
	tagBNCH = 1112425288 // BNCH - Boot nonce hash ([]byte)
	tagBORD = 1112494660 // BORD - Board ID (int)
	tagCEPO = 1128616015 // CEPO - Certificate epoch (int)
	tagCHIP = 1128810832 // CHIP - Chip ID (int)
	tagCPRO = 1129337423 // CPRO - Certificate production status (bool)
	tagCSEC = 1129530691 // CSEC - Certificate security mode (bool)
	tagECID = 1162037572 // ECID - Exclusive chip identifier (int)
	tagSDOM = 1396985677 // SDOM - Security domain (int)
	tagSnon = 1936617326 // snon - Security nonce ([]byte)
	tagSrvn = 1936881262 // srvn - Security revision number ([]byte - hash)

	// Additional Properties
	tagAugs = 1635084147 // augs - Augmented security (int)
	tagClas = 1668047219 // clas - Device class (int)
	tagFchp = 1717790832 // fchp - Firmware chip (int)
	tagPave = 1885435493 // pave - Platform version ([]byte - string)
	tagStyp = 1937013104 // styp - Security type (int)
	tagType = 1954115685 // type - Type (int)
	tagVnum = 1986950509 // vnum - Version number ([]byte - string)

	// SEPI Properties
	tagImpl = 1768779884 // impl - Implementation (int)
	tagArms = 1634889075 // arms - ARM security (int)
	tagTbmr = 1952607602 // tbmr - Trusted boot measurement register ([]byte)
	tagTbms = 1952607603 // tbms - Trusted boot measurement signature ([]byte)
	tagTz0s = 1954164851 // tz0s - TrustZone 0 security (int)

	// Observed Unknown Properties
	tagApmv = 1634758006 // apmv - Apple PMU version ([]byte - string)
	tagLove = 1819244133 // love - Version string ([]byte - string) "25.1.279.5.13,0"
	tagPrtp = 1886549104 // prtp - Platform type ([]byte - string) "Mac14,8"
	tagSdkp = 1935960944 // sdkp - SDK platform ([]byte - string) "macosx"
	tagTagt = 1952540532 // tagt - Target tag ([]byte - string)
	tagTatp = 1952543856 // tatp - Target platform ([]byte - string)
	tagTstp = 1953723504 // tstp - Timestamp (int)

	// Image Properties
	tagEKEY = 1162891593 // EKEY - Encryption key required (bool)
	tagEPRO = 1163154511 // EPRO - Encryption production (bool)
	tagESEC = 1163154515 // ESEC - Encryption security (bool)
)

// PropType represents the expected type for a property
type PropType int

const (
	PropTypeAuto PropType = iota
	PropTypeInt
	PropTypeBool
	PropTypeString
	PropTypeHash
	PropTypeTimestamp
)

// propertyTypeMap provides a centralized lookup for property types based on their ASN.1 tags
var propertyTypeMap = map[int]PropType{
	// String properties (stored as OCTET STRING but should be displayed as text)
	tagLove: PropTypeString, // love - Version string
	tagPrtp: PropTypeString, // prtp - Platform type
	tagSdkp: PropTypeString, // sdkp - SDK platform
	tagTagt: PropTypeString, // tagt - Target tag
	tagTatp: PropTypeString, // tatp - Target platform
	tagPave: PropTypeString, // pave - Platform version
	tagVnum: PropTypeString, // vnum - Version number
	tagApmv: PropTypeString, // apmv - Apple PMU version

	// Hash/binary properties (stored as OCTET STRING, display as hex)
	tagSrvn: PropTypeHash, // srvn - Security revision number
	tagSnon: PropTypeHash, // snon - Security nonce
	tagBNCH: PropTypeHash, // BNCH - Boot nonce hash
	tagTbmr: PropTypeHash, // tbmr - Trusted boot measurement register
	tagTbms: PropTypeHash, // tbms - Trusted boot measurement signature

	// Boolean properties
	tagCPRO: PropTypeBool, // CPRO - Certificate production status
	tagCSEC: PropTypeBool, // CSEC - Certificate security mode
	tagEKEY: PropTypeBool, // EKEY - Encryption key required
	tagEPRO: PropTypeBool, // EPRO - Encryption production
	tagESEC: PropTypeBool, // ESEC - Encryption security

	// Timestamp properties (stored as INTEGER, display as time)
	tagTstp: PropTypeTimestamp, // tstp - Timestamp

	// Integer properties
	tagBORD: PropTypeInt, // BORD - Board ID
	tagCEPO: PropTypeInt, // CEPO - Certificate epoch
	tagCHIP: PropTypeInt, // CHIP - Chip ID
	tagECID: PropTypeInt, // ECID - Exclusive chip identifier
	tagSDOM: PropTypeInt, // SDOM - Security domain
	tagAugs: PropTypeInt, // augs - Augmented security
	tagClas: PropTypeInt, // clas - Device class
	tagFchp: PropTypeInt, // fchp - Firmware chip
	tagStyp: PropTypeInt, // styp - Security type
	tagType: PropTypeInt, // type - Type
	tagImpl: PropTypeInt, // impl - Implementation
	tagArms: PropTypeInt, // arms - ARM security
	tagTz0s: PropTypeInt, // tz0s - TrustZone 0 security
}

// getPropertyType returns the expected type for a given property tag
func getPropertyType(tag int) PropType {
	if propType, exists := propertyTypeMap[tag]; exists {
		return propType
	}
	return PropTypeAuto // Auto-detect for unknown properties
}

// Manifest represents a unified IM4M manifest structure
type Img4Manifest struct {
	Raw       asn1.RawContent
	Name      string // IM4M
	Version   int
	Body      asn1.RawValue `asn1:"set"`      // Manifest body as SET - parsed dynamically
	Signature []byte        `asn1:"optional"` // Optional signature data
	CertChain asn1.RawValue `asn1:"optional"` // Optional certificate chain
}

// ManifestImage represents an image entry in the manifest
type ManifestImage struct {
	Name       string     // 4-character image name
	Properties []Property // Image-specific properties
}

type ManifestBody struct {
	Properties []Property
	Images     []ManifestImage // Parsed images from the manifest body
}

// Manifest represents the complete IM4M manifest structure
type Manifest struct {
	Img4Manifest
	ManifestBody
}

// ParseManifest parses a raw IM4M manifest from bytes
func ParseManifest(data []byte) (*Manifest, error) {
	var manifest Manifest
	rest, err := asn1.Unmarshal(data, &manifest.Img4Manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing data in manifest")
	}

	if manifest.Name != "IM4M" {
		return nil, fmt.Errorf("invalid manifest magic: expected 'IM4M', got '%s'", manifest.Name)
	}

	if err := manifest.ParseBody(); err != nil {
		return nil, fmt.Errorf("failed to parse manifest body: %w", err)
	}

	return &manifest, nil
}

// ParseBody parses the manifest body to extract properties and images dynamically
func (m *Manifest) ParseBody() error {
	if len(m.Body.Bytes) == 0 {
		return fmt.Errorf("manifest body is empty")
	}
	// Parse each entry in the SET
	remaining := m.Body.Bytes
	for len(remaining) > 0 {
		var entry asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &entry)
		if err != nil {
			break // No more entries to parse
		}

		// Only process private class entries (class 3)
		if entry.Class != 3 {
			log.Debugf("skipping non-private class entry: class=%d tag=%d", entry.Class, entry.Tag)
			remaining = rest
			continue
		}

		switch entry.Tag {
		case tagMANB:
			// Parse manifest body container
			if err := m.parseMANB(entry.Bytes); err != nil {
				return fmt.Errorf("failed to parse MANB: %v", err)
			}
		default:
			// Skip unknown top-level entries
			log.Debugf("skipping unknown top-level entry with tag=%d (%c%c%c%c)", entry.Tag,
				byte(entry.Tag>>24), byte(entry.Tag>>16), byte(entry.Tag>>8), byte(entry.Tag))
			remaining = rest
			continue
		}

		remaining = rest
	}

	return nil
}

func (m *Manifest) MarshalJSON() ([]byte, error) {
	data := map[string]any{
		"name":    m.Name,
		"version": m.Version,
	}
	if len(m.Properties) > 0 {
		data["properties"] = ConvertPropertySliceToMap(m.Properties)
	}
	if len(m.Images) > 0 {
		images := make(map[string]any)
		for _, image := range m.Images {
			imageProps := make(map[string]any)
			for _, prop := range image.Properties {
				imageProps[prop.Name] = prop.Value
			}
			images[image.Name] = imageProps
		}
		data["images"] = images
	}
	if len(m.Signature) > 0 {
		data["signature"] = m.Signature
	}
	if len(m.CertChain.Bytes) > 0 {
		data["certificate_chain"] = m.CertChain.Bytes
	}
	return json.Marshal(data)
}

// parseMANB parses the MANB container which contains MANP properties and image descriptors
func (m *Manifest) parseMANB(data []byte) error {
	// MANB contains a SEQUENCE with "MANB" string and a SET of entries
	var manb struct {
		Name string        // "MANB"
		Set  asn1.RawValue `asn1:"set"`
	}

	if _, err := asn1.Unmarshal(data, &manb); err != nil {
		return fmt.Errorf("failed to parse MANB structure: %v", err)
	}

	if manb.Name != "MANB" {
		return fmt.Errorf("expected MANB, got %s", manb.Name)
	}

	remaining := manb.Set.Bytes
	for len(remaining) > 0 {
		var entry asn1.RawValue
		rest, err := asn1.Unmarshal(remaining, &entry)
		if err != nil {
			break // No more entries to parse
		}

		// Only process private class entries (class 3)
		if entry.Class != 3 {
			remaining = rest
			continue
		}

		switch entry.Tag {
		case tagMANP:
			if err := m.parseMANP(entry.Bytes); err != nil {
				return fmt.Errorf("failed to parse MANP: %v", err)
			}
		default:
			// All other private tags are potentially image descriptors
			image, err := m.parseImageDescriptor(entry.Bytes)
			if err != nil {
				// Skip if not a valid image descriptor
				remaining = rest
				continue
			}
			m.Images = append(m.Images, *image)
		}

		remaining = rest
	}

	return nil
}

// parseMANP parses manifest properties dynamically
func (m *Manifest) parseMANP(data []byte) error {
	// MANP contains a SEQUENCE with "MANP" string and a SET of properties
	var manp struct {
		Name string        // "MANP"
		Set  asn1.RawValue `asn1:"set"`
	}

	if _, err := asn1.Unmarshal(data, &manp); err != nil {
		return fmt.Errorf("failed to parse MANP structure: %v", err)
	}

	if manp.Name != "MANP" {
		return fmt.Errorf("expected MANP, got %s", manp.Name)
	}

	// Parse properties from the SET dynamically
	properties, err := ParsePropertySet(manp.Set.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse MANP properties: %v", err)
	}

	m.Properties = properties

	return nil
}

// parseImageDescriptor parses an image descriptor entry dynamically
func (m *Manifest) parseImageDescriptor(data []byte) (*ManifestImage, error) {
	// Image descriptor contains a SEQUENCE with image name and a SET of properties
	var imgDesc struct {
		Name string        // 4-character image name
		Set  asn1.RawValue `asn1:"set"`
	}

	if _, err := asn1.Unmarshal(data, &imgDesc); err != nil {
		return nil, fmt.Errorf("failed to parse image descriptor structure: %v", err)
	}

	// Validate image name (should be 4 characters)
	if len(imgDesc.Name) != 4 {
		return nil, fmt.Errorf("invalid image name length: %d", len(imgDesc.Name))
	}

	// Parse image properties dynamically
	properties, err := ParsePropertySet(imgDesc.Set.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image properties: %v", err)
	}

	return &ManifestImage{
		Name:       imgDesc.Name,
		Properties: properties,
	}, nil
}

// String returns a formatted string representation of the manifest
func (m *Manifest) String() string {
	var sb strings.Builder
	colorField := color.New(color.Bold, color.FgHiBlue).SprintFunc()

	sb.WriteString(fmt.Sprintf("%s:\n", colorTitle("IM4M (IMG4 Manifest)")))
	sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Name"), m.Name))
	sb.WriteString(fmt.Sprintf("  %s: %d\n", colorField("Version"), m.Version))
	sb.WriteString(fmt.Sprintf("  %s: %d bytes\n", colorField("Body Size"), len(m.Body.Bytes)))

	sb.WriteString(fmt.Sprintf("  %s: %d\n", colorField("Properties"), len(m.Properties)))

	for _, prop := range m.Properties {
		sb.WriteString(fmt.Sprintf("    %s: %v\n", colorSubField(prop.Name), FormatPropertyValue(prop.Value)))
	}

	if len(m.Images) > 0 {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", colorField("Images"), len(m.Images)))
		for _, img := range m.Images {
			sb.WriteString(fmt.Sprintf("    %s:\n", colorSubField(img.Name)))
			for _, prop := range img.Properties {
				sb.WriteString(fmt.Sprintf("      %s: %v\n", colorField(prop.Name), FormatPropertyValue(prop.Value)))
			}
		}
	}
	if len(m.Signature) > 0 {
		sb.WriteString(fmt.Sprintf("  %s: %d bytes", colorField("Signature"), len(m.Signature)))
		if sigInfo := analyzeSignature(m.Signature); sigInfo != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", sigInfo))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("  Signature: none\n")
	}

	if len(m.CertChain.Bytes) > 0 {
		sb.WriteString(fmt.Sprintf("  %s: %d bytes\n", colorField("Certificate Chain"), len(m.CertChain.Bytes)))

		if cert, err := parseCertificateFromChain(m.CertChain.Bytes); err == nil && cert != nil {
			sb.WriteString(fmt.Sprintf("    %s: %s\n", colorField("Subject"), cert.Subject.CommonName))
			sb.WriteString(fmt.Sprintf("    %s: %s\n", colorField("Issuer"), cert.Issuer.CommonName))
			sb.WriteString(fmt.Sprintf("    %s: %s to %s\n",
				colorField("Valid"), cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")))

			if rsaPubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
				sb.WriteString(fmt.Sprintf("    %s: %d bits\n", colorField("RSA Key Size"), rsaPubKey.N.BitLen()))
			}
		}
	} else {
		sb.WriteString("  Certificate Chain: none\n")
	}

	return sb.String()
}

// analyzeSignature determines the signature algorithm based on signature size
func analyzeSignature(signature []byte) string {
	switch len(signature) {
	case 256:
		return "RSA-2048"
	case 384:
		return "RSA-3072"
	case 512:
		return "RSA-4096"
	case 64:
		return "ECDSA P-256"
	case 96:
		return "ECDSA P-384"
	default:
		return fmt.Sprintf("Unknown (%d bytes)", len(signature))
	}
}

// parseCertificateFromChain attempts to parse the first certificate from the chain
func parseCertificateFromChain(certChainData []byte) (*x509.Certificate, error) {
	// Try to parse as a certificate directly first
	if cert, err := x509.ParseCertificate(certChainData); err == nil {
		return cert, nil
	}

	// Try to parse as a certificate chain (SEQUENCE of certificates)
	var chain struct {
		Certificates []asn1.RawValue
	}

	if _, err := asn1.Unmarshal(certChainData, &chain); err == nil {
		if len(chain.Certificates) > 0 {
			if cert, err := x509.ParseCertificate(chain.Certificates[0].FullBytes); err == nil {
				return cert, nil
			}
		}
	}

	// Scan for certificate patterns in the data
	for i := 0; i < len(certChainData)-10; i++ {
		if certChainData[i] == 0x30 && certChainData[i+1] == 0x82 {
			// Found a potential certificate (SEQUENCE with long form length)
			certLen := int(certChainData[i+2])<<8 | int(certChainData[i+3])
			if i+4+certLen <= len(certChainData) {
				if cert, err := x509.ParseCertificate(certChainData[i : i+4+certLen]); err == nil {
					return cert, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("failed to parse certificate from chain data")
}

/* SHSH Extraction Functions */

// ExtractManifestFromShsh extracts IM4M manifest from SHSH blob with proper ASN.1 parsing
func ExtractManifestFromShsh(r io.Reader) ([]byte, error) {
	return ExtractManifestFromShshWithOptions(r, false, false)
}

// ExtractManifestFromShshWithOptions extracts IM4M manifest from SHSH blob with options
func ExtractManifestFromShshWithOptions(r io.Reader, extractUpdate, extractNoNonce bool) ([]byte, error) {
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
		return extractManifestFromPlistShshWithOptions(data, extractUpdate, extractNoNonce)
	}

	return nil, fmt.Errorf("no recognizable IM4M manifest found in SHSH blob")
}

func extractManifestFromRawData(data []byte, startIdx int) ([]byte, error) {
	remainder := data[startIdx:]

	// Try to parse the ASN.1 structure to determine the correct length
	var manifest Manifest
	if _, err := asn1.Unmarshal(remainder, &manifest.Img4Manifest); err == nil {
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

func extractManifestFromPlistShshWithOptions(data []byte, extractUpdate, extractNoNonce bool) ([]byte, error) {
	var shsh struct {
		ApImg4Ticket        []byte `plist:"ApImg4Ticket"`
		ApImg4TicketUpdate  []byte `plist:"ApImg4TicketUpdate,omitempty"`
		ApImg4TicketNoNonce []byte `plist:"ApImg4TicketNoNonce,omitempty"`
		Generator           string `plist:"generator,omitempty"`
		BBTicket            []byte `plist:"BBTicket,omitempty"`
	}

	decoder := plist.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&shsh); err != nil {
		return nil, fmt.Errorf("failed to decode SHSH plist: %v", err)
	}

	// Priority: specific manifest types if requested
	if extractUpdate && len(shsh.ApImg4TicketUpdate) > 0 {
		return shsh.ApImg4TicketUpdate, nil
	}

	if extractNoNonce && len(shsh.ApImg4TicketNoNonce) > 0 {
		return shsh.ApImg4TicketNoNonce, nil
	}

	// Fallback to standard manifest
	if len(shsh.ApImg4Ticket) == 0 {
		return nil, fmt.Errorf("no ApImg4Ticket found in SHSH plist")
	}

	return shsh.ApImg4Ticket, nil
}

/* utilities */
