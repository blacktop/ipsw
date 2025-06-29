package img4

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	bm "github.com/blacktop/ipsw/pkg/plist"
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
	tagAr1s = 1634888563 // ar1s - ARM1 security (int)
	tagCons = 1668246131 // cons - Console (int)
	tagDrmc = 1685287523 // drmc - DRMC (int)
	tagMmap = 1835099760 // mmap - Memory map ([]byte)
	tagRddg = 1919181927 // rddg - RD Debug ([]byte)
	tagTbmr = 1952607602 // tbmr - Trusted boot measurement register ([]byte)
	tagTbms = 1952607603 // tbms - Trusted boot measurement signature ([]byte)
	tagTz0s = 1954164851 // tz0s - TrustZone 0 security (int)
	tagTz1s = 1954165107 // tz1s - TrustZone 1 security (int)

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

func getComponentNameByFourCC(fourCC string) (string, bool) {
	if len(fourCC) == 4 {
		if name, exists := ComponentFourCCs[fourCC]; exists {
			return name, true
		}
	}
	return "", false
}

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

// Manifest represents a unified IM4M manifest structure
type IM4M struct {
	Raw       asn1.RawContent
	Tag       string `asn1:"ia5"` // IM4M
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

// Manifest represents the manifest structure
type Manifest struct {
	IM4M
	ManifestBody
}

func OpenManifest(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			log.Errorf("failed to close manifest %s: %v", path, err)
		}
	}()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", path, err)
	}
	return ParseManifest(data)
}

// ParseManifest parses a raw IM4M manifest from bytes
func ParseManifest(data []byte) (*Manifest, error) {
	var manifest Manifest
	rest, err := asn1.Unmarshal(data, &manifest.IM4M)
	if err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing data in manifest")
	}

	if manifest.Tag != "IM4M" {
		return nil, fmt.Errorf("invalid manifest magic: expected 'IM4M', got '%s'", manifest.Tag)
	}

	if err := manifest.parseBody(); err != nil {
		return nil, fmt.Errorf("failed to parse manifest body: %w", err)
	}

	return &manifest, nil
}

// parseBody parses the manifest body to extract properties and images dynamically
func (m *Manifest) parseBody() error {
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
				log.Debugf("skipping entry with tag=%d, not a valid image descriptor: %v", entry.Tag, err)
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

func (m *Manifest) GetTicket(name string) (*ManifestImage, error) {
	for _, image := range m.Images {
		if image.Name == name {
			return &image, nil
		}
	}
	return nil, fmt.Errorf("ticket %s not found in manifest", name)
}

func (m *Manifest) HasTicket(name string) bool {
	for _, image := range m.Images {
		if image.Name == name {
			return true
		}
	}
	return false
}

// String returns a formatted string representation of the manifest
func (m *Manifest) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s:\n", colorTitle("IM4M (Manifest)")))
	sb.WriteString(fmt.Sprintf("  %s: %s\n", colorField("Tag"), m.Tag))
	sb.WriteString(fmt.Sprintf("  %s: %d\n", colorField("Version"), m.Version))
	sb.WriteString(fmt.Sprintf("  %s: %d bytes\n", colorField("Body Size"), len(m.Body.Bytes)))
	sb.WriteString(fmt.Sprintf("  %s: %d bytes\n", colorField("Raw Size"), len(m.Raw)))

	// Categorize properties for better organization
	deviceProps := []string{"CHIP", "BORD", "ECID", "SDOM", "CEPO"}
	securityProps := []string{"CPRO", "CSEC", "srvn", "snon", "BNCH"}
	versionProps := []string{"pave", "vnum", "love", "prtp", "sdkp"}
	otherProps := []string{}

	devicePropCount := 0
	securityPropCount := 0
	versionPropCount := 0

	// Count properties by category
	propMap := make(map[string]any)
	for _, prop := range m.Properties {
		propMap[prop.Name] = prop.Value
		switch {
		case slices.Contains(deviceProps, prop.Name):
			devicePropCount++
		case slices.Contains(securityProps, prop.Name):
			securityPropCount++
		case slices.Contains(versionProps, prop.Name):
			versionPropCount++
		default:
			otherProps = append(otherProps, prop.Name)
		}
	}

	sb.WriteString(fmt.Sprintf("  %s: %d\n", colorField("Properties"), len(m.Properties)))

	// Display properties by category
	if devicePropCount > 0 {
		sb.WriteString(fmt.Sprintf("    %s:\n", colorSubField("Device Properties")))
		for _, propName := range deviceProps {
			if val, exists := propMap[propName]; exists {
				sb.WriteString(fmt.Sprintf("      %s: %v\n", colorField(propName), FormatPropertyValue(val)))
			}
		}
	}

	if securityPropCount > 0 {
		sb.WriteString(fmt.Sprintf("    %s:\n", colorSubField("Security Properties")))
		for _, propName := range securityProps {
			if val, exists := propMap[propName]; exists {
				sb.WriteString(fmt.Sprintf("      %s: %v\n", colorField(propName), FormatPropertyValue(val)))
			}
		}
	}

	if versionPropCount > 0 {
		sb.WriteString(fmt.Sprintf("    %s:\n", colorSubField("Version Properties")))
		for _, propName := range versionProps {
			if val, exists := propMap[propName]; exists {
				sb.WriteString(fmt.Sprintf("      %s: %v\n", colorField(propName), FormatPropertyValue(val)))
			}
		}
	}

	if len(otherProps) > 0 {
		sb.WriteString(fmt.Sprintf("    %s:\n", colorSubField("Other Properties")))
		for _, propName := range otherProps {
			if val, exists := propMap[propName]; exists {
				sb.WriteString(fmt.Sprintf("      %s: %v\n", colorField(propName), FormatPropertyValue(val)))
			}
		}
	}

	if len(m.Images) > 0 {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", colorField("Images"), len(m.Images)))
		for _, img := range m.Images {
			if componentName, exists := getComponentNameByFourCC(img.Name); exists && !strings.EqualFold(img.Name, componentName) {
				sb.WriteString(fmt.Sprintf("    %s (%s):\n", colorSubField(img.Name), componentName))
			} else {
				sb.WriteString(fmt.Sprintf("    %s:\n", colorSubField(img.Name)))
			}
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
			sb.WriteString(fmt.Sprintf("    %s: %x\n", colorField("Serial Number"), cert.SerialNumber))
			if len(cert.Subject.Organization) > 0 {
				sb.WriteString(fmt.Sprintf("    %s: %s\n", colorField("Organization"), cert.Subject.Organization[0]))
			}
		}
	} else {
		sb.WriteString("  Certificate Chain: none\n")
	}

	return sb.String()
}

func (m *Manifest) MarshalJSON() ([]byte, error) {
	data := map[string]any{
		"tag":     m.Tag,
		"version": m.Version,
	}
	if len(m.Properties) > 0 {
		data["properties"] = PropertiesSliceToMap(m.Properties)
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

// Marshal generates ASN.1 bytes for the manifest
func (m *Manifest) Marshal() ([]byte, error) {
	var manpSetEntries []asn1.RawValue
	if len(m.Properties) > 0 {
		var err error
		manpSetEntries, err = marshalPropertiesToSet(m.Properties)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal manifest properties: %v", err)
		}
	}

	manpSetBytes, err := asn1.Marshal(manpSetEntries)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MANP SET: %v", err)
	}

	manpStruct := struct {
		Name string
		Set  asn1.RawValue `asn1:"set"`
	}{
		Name: "MANP",
		Set: asn1.RawValue{
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      manpSetBytes,
		},
	}
	manpBytes, err := asn1.Marshal(manpStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MANP: %v", err)
	}

	// Combine MANP and images into the MANB structure
	var manbSetEntries []asn1.RawValue
	if len(m.Properties) > 0 { // Only add MANP if there are properties
		manbSetEntries = append(manbSetEntries, asn1.RawValue{
			Class:      asn1.ClassPrivate,
			Tag:        tagMANP,
			IsCompound: true,
			Bytes:      manpBytes,
		})
	}

	// Add images
	for _, img := range m.Images {
		imagePropSetEntries, err := marshalPropertiesToSet(img.Properties)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal image properties for %s: %v", img.Name, err)
		}

		imagePropSetBytes, err := asn1.Marshal(imagePropSetEntries)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal image property set for %s: %v", img.Name, err)
		}

		imageDescStruct := struct {
			Name string
			Set  asn1.RawValue `asn1:"set"`
		}{
			Name: img.Name,
			Set: asn1.RawValue{
				Tag:        asn1.TagSet,
				IsCompound: true,
				Bytes:      imagePropSetBytes,
			},
		}

		imageDescBytes, err := asn1.Marshal(imageDescStruct)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal image descriptor for %s: %v", img.Name, err)
		}

		manbSetEntries = append(manbSetEntries, asn1.RawValue{
			Class:      asn1.ClassPrivate,
			Tag:        fourCCtoInt(img.Name), // The tag for the image entry is its FourCC name
			IsCompound: true,
			Bytes:      imageDescBytes,
		})
	}

	manbSetBytes, err := asn1.Marshal(manbSetEntries)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MANB SET: %v", err)
	}

	manbStruct := struct {
		Name string
		Set  asn1.RawValue `asn1:"set"`
	}{
		Name: "MANB",
		Set: asn1.RawValue{
			Tag:        asn1.TagSet,
			IsCompound: true,
			Bytes:      manbSetBytes,
		},
	}
	manbBytes, err := asn1.Marshal(manbStruct)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MANB: %v", err)
	}

	m.Body = asn1.RawValue{
		Tag:        asn1.TagSet,
		IsCompound: true,
		Bytes:      manbBytes,
	}

	return asn1.Marshal(m.IM4M)
}

// marshalPropertiesToSet marshals a slice of Properties into ASN.1 RawValues
func marshalPropertiesToSet(props []Property) ([]asn1.RawValue, error) {
	return MarshalPropertiesSlice(props, ManifestFormat)
}

// analyzeSignature determines the signature algorithm based on signature size and format
func analyzeSignature(signature []byte) string {
	switch len(signature) {
	case 256:
		return "RSA-2048"
	case 384:
		return "RSA-3072"
	case 512:
		return "RSA-4096"
	case 64:
		return "ECDSA P-256 (or DER-encoded variable length)"
	case 96:
		return "ECDSA P-384 (or DER-encoded variable length)"
	default:
		// For DER-encoded ECDSA signatures, try to detect the format
		if len(signature) > 6 && signature[0] == 0x30 {
			return fmt.Sprintf("DER-encoded signature (%d bytes)", len(signature))
		}
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

	// Only try more advanced parsing if the data is large enough to contain a certificate
	if len(certChainData) < 100 { // Minimum reasonable certificate size
		return nil, fmt.Errorf("certificate chain data too small: %d bytes", len(certChainData))
	}

	// Scan for certificate patterns in the data (more robust approach)
	for i := 0; i < len(certChainData)-10; i++ {
		if certChainData[i] == 0x30 && certChainData[i+1] == 0x82 {
			// Found a potential certificate (SEQUENCE with long form length)
			if i+4 >= len(certChainData) {
				continue
			}
			certLen := int(certChainData[i+2])<<8 | int(certChainData[i+3])
			// Validate certificate length is reasonable
			if certLen < 50 || certLen > 4096 || i+4+certLen > len(certChainData) {
				continue
			}
			if cert, err := x509.ParseCertificate(certChainData[i : i+4+certLen]); err == nil {
				return cert, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to parse certificate from chain data")
}

func CreateManifest() (*Manifest, error) {
	// Create an empty manifest with default values
	manifest := &Manifest{
		IM4M: IM4M{
			Tag:     "IM4M",
			Version: 1,
			Body: asn1.RawValue{
				Class: 3,
				Tag:   tagMANB,
				// Bytes: asn1.RawValue{
				// 	Class: 3,        // Private class
				// 	Tag:   tagMANP,  // MANB - Manifest Body
				// 	Bytes: []byte{}, // Will be filled later
				// },
			},
		},
	}

	// Initialize the body with an empty property set
	// manifest.Body.Properties = []Property{}

	return manifest, nil
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
	if _, err := asn1.Unmarshal(remainder, &manifest.IM4M); err == nil {
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

/* VERIFICATION */

// VerificationResult holds the results of manifest verification
type VerificationResult struct {
	IsValid           bool
	PropertiesChecked int
	Mismatches        []PropertyMismatch
}

// PropertyMismatch represents a property that doesn't match between manifests
type PropertyMismatch struct {
	Property string
	Expected any
	Actual   any
}

// VerifyManifestProperties verifies an IM4M manifest against a build manifest
func VerifyManifestProperties(im4m *Manifest, bm *bm.BuildManifest, verbose, allowExtra bool) (*VerificationResult, error) {
	result := &VerificationResult{
		IsValid:    true,
		Mismatches: []PropertyMismatch{},
	}

	im4mProps := PropertiesSliceToMap(im4m.Properties)

	if len(bm.BuildIdentities) == 0 {
		return nil, fmt.Errorf("no build identities found in build manifest")
	}
	// TODO: support multiple build identities
	buildIdentity := bm.BuildIdentities[0]

	// Map build manifest fields to IM4M property names and convert hex strings to integers
	bmProps := make(map[string]any)
	if val, err := strconv.ParseInt(strings.TrimPrefix(buildIdentity.ApBoardID, "0x"), 16, 64); err == nil {
		bmProps["BORD"] = int(val)
	}
	if val, err := strconv.ParseInt(strings.TrimPrefix(buildIdentity.ApChipID, "0x"), 16, 64); err == nil {
		bmProps["CHIP"] = int(val)
	}
	if val, err := strconv.ParseInt(strings.TrimPrefix(buildIdentity.ApSecurityDomain, "0x"), 16, 64); err == nil {
		bmProps["SDOM"] = int(val)
	}

	// Add more mappings from BuildManifest to IM4M properties
	bmProps["love"] = buildIdentity.ApOSLongVersion
	// Always parse ProductMarketingVersion as float64 for consistent comparison
	if val, err := strconv.ParseFloat(buildIdentity.ProductMarketingVersion, 64); err == nil {
		bmProps["apmv"] = val
	} else {
		// Fallback to string if parsing fails
		bmProps["apmv"] = buildIdentity.ProductMarketingVersion
	}
	bmProps["prtp"] = buildIdentity.ApProductType
	bmProps["sdkp"] = buildIdentity.ApSDKPlatform
	bmProps["tagt"] = buildIdentity.ApTarget
	bmProps["tatp"] = buildIdentity.ApTargetType

	// Handle Ap,Timestamp from Info dictionary
	if buildIdentity.Info.ApTimestamp != 0 {
		bmProps["tstp"] = time.Unix(int64(buildIdentity.Info.ApTimestamp), 0).UTC()
	}

	// Verify all properties from the build manifest are present and correct in the IM4M
	for bmKey, bmVal := range bmProps {
		result.PropertiesChecked++

		im4mVal, im4mExists := im4mProps[bmKey]

		if !im4mExists {
			result.IsValid = false
			result.Mismatches = append(result.Mismatches, PropertyMismatch{
				Property: bmKey,
				Expected: bmVal,
				Actual:   "(missing)",
			})
			continue
		}

		if !CompareManifestValues(im4mVal, bmVal) {
			result.IsValid = false
			result.Mismatches = append(result.Mismatches, PropertyMismatch{
				Property: bmKey,
				Expected: bmVal,
				Actual:   im4mVal,
			})
		}
	}

	// If not allowing extra properties, check for properties in IM4M that are not in the build manifest
	if !allowExtra {
		for im4mKey := range im4mProps {
			if _, bmExists := bmProps[im4mKey]; !bmExists {
				// Ignore ECID and snon as they are often unique to the manifest
				if im4mKey == "ECID" || im4mKey == "snon" {
					continue
				}
				result.IsValid = false
				result.Mismatches = append(result.Mismatches, PropertyMismatch{
					Property: im4mKey,
					Expected: "(not present in build manifest)",
					Actual:   im4mProps[im4mKey],
				})
			}
		}
	}

	return result, nil
}

// CompareManifestValues compares two manifest property values
func CompareManifestValues(a, b any) bool {
	// Handle different types that might represent the same value
	switch va := a.(type) {
	case []byte:
		if vb, ok := b.([]byte); ok {
			return bytes.Equal(va, vb)
		}
	case int:
		if vb, ok := b.(int); ok {
			return va == vb
		} else if vb, ok := b.(float64); ok {
			return float64(va) == vb
		}
	case float64:
		if vb, ok := b.(float64); ok {
			return va == vb
		} else if vb, ok := b.(int); ok {
			return va == float64(vb)
		}
	case bool:
		if vb, ok := b.(bool); ok {
			return va == vb
		}
	case string:
		if vb, ok := b.(string); ok {
			return va == vb
		}
	}

	// Fallback to basic equality check
	return a == b
}
