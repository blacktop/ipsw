package img4

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"strings"
)

// oidAppleImg4ManifestCertSpec is the X.509 extension OID 1.2.840.113635.100.6.1.15.
// It carries the IMG4 manifest property constraints that the certificate is permitted to sign.
var oidAppleImg4ManifestCertSpec = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 6, 1, 15}

const (
	tagCRTP = 1129469008 // CRTP - Certificate Properties (IM4C constraint container)
	tagPUBK = 1347764811 // PUBK - Public Key (IM4C signing key)
)

// ConstraintKind describes how a constraint binds a manifest property.
type ConstraintKind int

const (
	// ConstraintPinned: property must equal the encoded concrete value.
	ConstraintPinned ConstraintKind = iota
	// ConstraintRequired: property must be present (any value). Encoded as [0] EXPLICIT NULL.
	ConstraintRequired
	// ConstraintOptional: property may be present (any value). Encoded as [1] EXPLICIT NULL.
	ConstraintOptional
)

// Constraint is a single 4cc property constraint from an IMG4 cert spec.
type Constraint struct {
	Name  string
	Kind  ConstraintKind
	Value any // populated when Kind == ConstraintPinned
}

// ConstraintGroup is a named SET of constraints (MANP or OBJP).
type ConstraintGroup struct {
	Name        string
	Constraints []Constraint
}

// IM4C is an Image4 Certificate — a non-X.509 cert format used by some
// peripheral firmware tickets (e.g. Yonkers/Savage). It carries the same
// constraint groups as the X.509 1.2.840.113635.100.6.1.15 extension,
// plus a raw public key and a signature over the body.
type IM4C struct {
	Version     int
	Constraints []ConstraintGroup
	PublicKey   []byte
	Signature   []byte
}

// parseIM4C parses the cert-chain bytes of an IM4M when they hold an IM4C
// rather than an X.509 chain. The input is the IM4M CertChain RawValue's
// inner bytes — i.e. one SEQUENCE { "IM4C", INT, SET{ CRTP, PUBK }, sig }.
func parseIM4C(data []byte) (*IM4C, error) {
	var body struct {
		Tag       string `asn1:"ia5"`
		Version   int
		Props     asn1.RawValue `asn1:"set"`
		Signature []byte
	}
	if _, err := asn1.Unmarshal(data, &body); err != nil {
		return nil, err
	}
	if body.Tag != "IM4C" {
		return nil, fmt.Errorf("not an IM4C: tag=%q", body.Tag)
	}

	im4c := &IM4C{
		Version:   body.Version,
		Signature: body.Signature,
	}

	rest := body.Props.Bytes
	for len(rest) > 0 {
		var entry asn1.RawValue
		next, err := asn1.Unmarshal(rest, &entry)
		if err != nil {
			break
		}
		rest = next
		if entry.Class != asn1.ClassPrivate {
			continue
		}
		switch entry.Tag {
		case tagCRTP:
			var crtp struct {
				Name string `asn1:"ia5"`
				Set  asn1.RawValue
			}
			if _, err := asn1.Unmarshal(entry.Bytes, &crtp); err == nil {
				im4c.Constraints = parseConstraintGroups(crtp.Set.Bytes)
			}
		case tagPUBK:
			// PUBK wraps an OCTET STRING directly (no SEQUENCE).
			var pk []byte
			if _, err := asn1.Unmarshal(entry.Bytes, &pk); err == nil {
				im4c.PublicKey = pk
			}
		}
	}

	return im4c, nil
}

// parseConstraintGroups walks a SET of priv-tagged groups (MANP, OBJP, ...).
// Used for both the X.509 extension value and the IM4C CRTP body.
func parseConstraintGroups(setBytes []byte) []ConstraintGroup {
	var groups []ConstraintGroup
	rest := setBytes
	for len(rest) > 0 {
		var entry asn1.RawValue
		next, err := asn1.Unmarshal(rest, &entry)
		if err != nil {
			break
		}
		rest = next
		if entry.Class != asn1.ClassPrivate {
			continue
		}
		var grp struct {
			Name string `asn1:"ia5"`
			Set  asn1.RawValue
		}
		if _, err := asn1.Unmarshal(entry.Bytes, &grp); err != nil {
			continue
		}
		groups = append(groups, ConstraintGroup{
			Name:        grp.Name,
			Constraints: parseConstraints(grp.Set.Bytes),
		})
	}
	return groups
}

// parseConstraints walks the inner SET of priv-tagged property constraints.
func parseConstraints(setBytes []byte) []Constraint {
	var out []Constraint
	rest := setBytes
	for len(rest) > 0 {
		var entry asn1.RawValue
		next, err := asn1.Unmarshal(rest, &entry)
		if err != nil {
			break
		}
		rest = next
		if entry.Class != asn1.ClassPrivate {
			continue
		}
		var prop struct {
			Name  string `asn1:"ia5"`
			Value asn1.RawValue
		}
		if _, err := asn1.Unmarshal(entry.Bytes, &prop); err != nil {
			continue
		}
		c := Constraint{Name: prop.Name}
		// Context-tagged NULL is a wildcard: [0] required-any, [1] optional-any.
		if prop.Value.Class == asn1.ClassContextSpecific {
			if prop.Value.Tag == 1 {
				c.Kind = ConstraintOptional
			} else {
				c.Kind = ConstraintRequired
			}
		} else {
			c.Kind = ConstraintPinned
			c.Value = ParsePropertyValueWithTag(prop.Value, entry.Tag)
		}
		out = append(out, c)
	}
	return out
}

// extractCertConstraints pulls the IMG4 constraint extension from a parsed X.509 cert.
func extractCertConstraints(cert *x509.Certificate) []ConstraintGroup {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(oidAppleImg4ManifestCertSpec) {
			continue
		}
		// The extension value is a SET wrapping the priv-tagged groups.
		var set asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &set); err != nil {
			return nil
		}
		return parseConstraintGroups(set.Bytes)
	}
	return nil
}

// constraintGroupsToMap flattens groups into a JSON-friendly map.
// Wildcards become "*" (required) or "?" (optional); pinned values pass through.
func constraintGroupsToMap(groups []ConstraintGroup) map[string]map[string]any {
	out := make(map[string]map[string]any, len(groups))
	for _, g := range groups {
		props := make(map[string]any, len(g.Constraints))
		for _, c := range g.Constraints {
			switch c.Kind {
			case ConstraintRequired:
				props[c.Name] = "*"
			case ConstraintOptional:
				props[c.Name] = "?"
			default:
				props[c.Name] = c.Value
			}
		}
		out[g.Name] = props
	}
	return out
}

// writeConstraints renders constraint groups into sb at the given base indent.
func writeConstraints(sb *strings.Builder, groups []ConstraintGroup, indent string) {
	for _, g := range groups {
		label := g.Name
		switch g.Name {
		case "MANP":
			label = "MANP (Manifest Properties)"
		case "OBJP":
			label = "OBJP (Object Properties)"
		}
		fmt.Fprintf(sb, "%s%s:\n", indent, colorSubField(label))
		for _, c := range g.Constraints {
			name := colorField(c.Name)
			if long, ok := PropertyFourCCs[c.Name]; ok && !strings.EqualFold(c.Name, long) {
				name = fmt.Sprintf("%s (%s)", name, colorLongName(long))
			}
			switch c.Kind {
			case ConstraintRequired:
				fmt.Fprintf(sb, "%s  %s: *\n", indent, name)
			case ConstraintOptional:
				fmt.Fprintf(sb, "%s  %s: * (optional)\n", indent, name)
			default:
				fmt.Fprintf(sb, "%s  %s: %s\n", indent, name, FormatPropertyValue(c.Value))
			}
		}
	}
}
