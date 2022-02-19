package certs

import (
	"encoding/asn1"
	"fmt"
	"strings"
)

var (
	OIDSubjectKeyId          asn1.ObjectIdentifier = []int{2, 5, 29, 14}
	OIDKeyUsage              asn1.ObjectIdentifier = []int{2, 5, 29, 15}
	OIDExtendedKeyUsage      asn1.ObjectIdentifier = []int{2, 5, 29, 37}
	OIDAuthorityKeyId        asn1.ObjectIdentifier = []int{2, 5, 29, 35}
	OIDBasicConstraints      asn1.ObjectIdentifier = []int{2, 5, 29, 19}
	OIDSubjectAltName        asn1.ObjectIdentifier = []int{2, 5, 29, 17}
	OIDCertificatePolicies   asn1.ObjectIdentifier = []int{2, 5, 29, 32}
	OIDNameConstraints       asn1.ObjectIdentifier = []int{2, 5, 29, 30}
	OIDCRLDistributionPoints asn1.ObjectIdentifier = []int{2, 5, 29, 31}
	OIDAuthorityInfoAccess   asn1.ObjectIdentifier = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	OIDCRLNumber             asn1.ObjectIdentifier = []int{2, 5, 29, 20}
)

var (
	OIDAppleCertificatePolicy   asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 5, 1}
	OIDAppleSoftwareSigningLeaf asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 22}
)

type KeyUsage int

const (
	KeyUsageDigitalSignature KeyUsage = 1 << iota
	KeyUsageContentCommitment
	KeyUsageKeyEncipherment
	KeyUsageDataEncipherment
	KeyUsageKeyAgreement
	KeyUsageCertSign
	KeyUsageCRLSign
	KeyUsageEncipherOnly
	KeyUsageDecipherOnly
)

func (ku KeyUsage) DigitalSignature() bool {
	return ku&KeyUsageDigitalSignature != 0
}
func (ku KeyUsage) ContentCommitment() bool {
	return ku&KeyUsageContentCommitment != 0
}
func (ku KeyUsage) KeyEncipherment() bool {
	return ku&KeyUsageKeyEncipherment != 0
}
func (ku KeyUsage) DataEncipherment() bool {
	return ku&KeyUsageDataEncipherment != 0
}
func (ku KeyUsage) KeyAgreement() bool {
	return ku&KeyUsageKeyAgreement != 0
}
func (ku KeyUsage) KeyCertSign() bool {
	return ku&KeyUsageCertSign != 0
}
func (ku KeyUsage) CRLSign() bool {
	return ku&KeyUsageCRLSign != 0
}
func (ku KeyUsage) EncipherOnly() bool {
	return ku&KeyUsageEncipherOnly != 0
}
func (ku KeyUsage) DecipherOnly() bool {
	return ku&KeyUsageDecipherOnly != 0
}
func (ku KeyUsage) String() string {
	var out []string
	if ku.DigitalSignature() {
		out = append(out, "DigitalSignature")
	}
	if ku.ContentCommitment() {
		out = append(out, "ContentCommitment")
	}
	if ku.KeyEncipherment() {
		out = append(out, "KeyEncipherment")
	}
	if ku.DataEncipherment() {
		out = append(out, "DataEncipherment")
	}
	if ku.KeyAgreement() {
		out = append(out, "KeyAgreement")
	}
	if ku.KeyCertSign() {
		out = append(out, "KeyCertSign")
	}
	if ku.CRLSign() {
		out = append(out, "CRLSign")
	}
	if ku.EncipherOnly() {
		out = append(out, "EncipherOnly")
	}
	if ku.DecipherOnly() {
		out = append(out, "DecipherOnly")
	}
	return strings.Join(out, ", ")
}

type ExtKeyUsage int

const (
	ExtKeyUsageAny ExtKeyUsage = iota
	ExtKeyUsageServerAuth
	ExtKeyUsageClientAuth
	ExtKeyUsageCodeSigning
	ExtKeyUsageEmailProtection
	ExtKeyUsageIPSECEndSystem
	ExtKeyUsageIPSECTunnel
	ExtKeyUsageIPSECUser
	ExtKeyUsageTimeStamping
	ExtKeyUsageOCSPSigning
	ExtKeyUsageMicrosoftServerGatedCrypto
	ExtKeyUsageNetscapeServerGatedCrypto
	ExtKeyUsageMicrosoftCommercialCodeSigning
	ExtKeyUsageMicrosoftKernelCodeSigning
)

func (ku ExtKeyUsage) String() string {
	switch ku {
	case ExtKeyUsageAny:
		return "Any"
	case ExtKeyUsageServerAuth:
		return "ServerAuth"
	case ExtKeyUsageClientAuth:
		return "ClientAuth"
	case ExtKeyUsageCodeSigning:
		return "CodeSigning"
	case ExtKeyUsageEmailProtection:
		return "EmailProtection"
	case ExtKeyUsageIPSECEndSystem:
		return "IPSECEndSystem"
	case ExtKeyUsageIPSECTunnel:
		return "IPSECTunnel"
	case ExtKeyUsageIPSECUser:
		return "IPSECUser"
	case ExtKeyUsageTimeStamping:
		return "TimeStamping"
	case ExtKeyUsageOCSPSigning:
		return "OCSPSigning"
	case ExtKeyUsageMicrosoftServerGatedCrypto:
		return "MicrosoftServerGatedCrypto"
	case ExtKeyUsageNetscapeServerGatedCrypto:
		return "NetscapeServerGatedCrypto"
	case ExtKeyUsageMicrosoftCommercialCodeSigning:
		return "MicrosoftCommercialCodeSigning"
	case ExtKeyUsageMicrosoftKernelCodeSigning:
		return "MicrosoftKernelCodeSigning"
	default:
		return "Unknown"
	}
}

func ReprData(dat []byte, tabs, width int) string {
	var out string
	var parts []string
	for _, id := range dat {
		parts = append(parts, fmt.Sprintf("%02x", id))
		if len(parts) == width {
			out += fmt.Sprintf("%s%s\n", strings.Repeat("\t", tabs), strings.Join(parts, ":")+":")
			parts = []string{}
		}
	}
	if len(parts) > 0 {
		out += strings.Repeat("\t", tabs) + strings.Join(parts, ":")
	}
	return out
}
