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
	OIDEmailAddress          asn1.ObjectIdentifier = []int{1, 2, 840, 113549, 1, 9, 1}
)

var (
	OIDAppleCertificatePolicy asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 5, 1}
	// LeafCertificate
	OIDIosDeveloperLeaf                    asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 2}
	OIDIosAppStoreApplicationLeaf          asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 3}
	OIDIosDistributionLeaf                 asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 4}
	OIDIosAppStoreVpnApplicationLeaf       asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 6}
	OID3rdPartyMacDeveloperApplicationLeaf asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 7}
	OID3rdPartyMacDeveloperInstallerLeaf   asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 8}
	OIDMacAppStoreApplicationLeaf          asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 9}
	OIDMacAppStoreInstallerLeaf            asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 10}
	OIDMacAppStoreReceiptLeaf              asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 11}
	OIDMacOsDevelopmentLeaf                asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 12}
	OIDDeveloperIdApplicationLeaf          asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 13}
	OIDDeveloperIdInstallerLeaf            asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 14}
	OIDItemAppleImg4Manifest               asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 15}
	OIDDeveloperIdKernelExtensionLeaf      asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 18}
	OIDTestFlightLeaf                      asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 25, 1}
	OIDInternalReleaseLeaf                 asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 25, 2}
	OIDDeveloperIdTicketLeaf               asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 30}
	OIDAppleSoftwareSigningLeaf            asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 22}
	OIDDeveloperIDDate                     asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 1, 33}
	// Intermediate CA
	OIDWorldwideDeveloperRelationsWdrIntermediateCA asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 2, 1}
	OIDDeveloperIdIntermediateCA                    asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 2, 6}
	//
	OIDItemAppleDeviceAttestationNonce               asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 8, 2}
	OIDItemAppleDeviceAttestationHardwareProperties  asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 8, 4}
	OIDItemAppleDeviceAttestationKeyUsageProperties  asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 8, 5}
	OIDItemAppleDeviceAttestationDeviceOSInformation asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 8, 7}
	//
	OIDCodeSigningEKU                   asn1.ObjectIdentifier = []int{1, 3, 6, 1, 5, 5, 7, 3, 3}
	OIDSafariDeveloperEKU               asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 4, 8}
	OID3rdPartyMacDeveloperInstallerEKU asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 4, 9}
	OIDDeveloperIDInstallerEKU          asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 4, 13}
	// APSWAuthCapabilities
	OIDGeneralCapabilities asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 59, 1}
	OIDAirPlayCapabilities asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 59, 2}
	OIDHomeKitCapabilities asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 59, 3}
	// AuthVersion
	OIDAuthVersion3  asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 36}    // v3 Capabilities Extension
	OIDAuthVersionSW asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 59, 1} // SW Auth General Capabilities Extension
	OIDAuthVersion4  asn1.ObjectIdentifier = []int{1, 2, 840, 113635, 100, 6, 71, 1} // v4 Properties extension
)

func LookupOID(oid asn1.ObjectIdentifier) string {
	switch {
	case oid.Equal(OIDAppleCertificatePolicy):
		return "Apple Certificate Policy"
	case oid.Equal(OIDIosDeveloperLeaf):
		return "iOS Developer (Leaf)"
	case oid.Equal(OIDIosAppStoreApplicationLeaf):
		return "iOS AppStore Application (Leaf)"
	case oid.Equal(OIDIosDistributionLeaf):
		return "iOS Distribution (Leaf)"
	case oid.Equal(OIDIosAppStoreVpnApplicationLeaf):
		return "iOS AppStore VPN Application (Leaf)"
	case oid.Equal(OID3rdPartyMacDeveloperApplicationLeaf):
		return "3rd Party Mac Developer Application (Leaf)"
	case oid.Equal(OID3rdPartyMacDeveloperInstallerLeaf):
		return "3rd Party Mac Developer Installer (Leaf)"
	case oid.Equal(OIDMacAppStoreApplicationLeaf):
		return "Mac AppStore Application (Leaf)"
	case oid.Equal(OIDMacAppStoreInstallerLeaf):
		return "Mac AppStore Installer (Leaf)"
	case oid.Equal(OIDMacAppStoreReceiptLeaf):
		return "Mac AppStore Receipt (Leaf)"
	case oid.Equal(OIDMacOsDevelopmentLeaf):
		return "macOS Development (Leaf)"
	case oid.Equal(OIDDeveloperIdApplicationLeaf):
		return "Developer ID Application (Leaf)"
	case oid.Equal(OIDDeveloperIdInstallerLeaf):
		return "Developer ID Installer (Leaf)"
	case oid.Equal(OIDDeveloperIdKernelExtensionLeaf):
		return "Developer ID Kernel Extension (Leaf)"
	case oid.Equal(OIDTestFlightLeaf):
		return "TestFlight (Leaf)"
	case oid.Equal(OIDInternalReleaseLeaf):
		return "Internal Release (Leaf)"
	case oid.Equal(OIDDeveloperIdTicketLeaf):
		return "Developer ID Ticket (Leaf)"
	case oid.Equal(OIDAppleSoftwareSigningLeaf):
		return "Apple Software Signing (Leaf)"
	case oid.Equal(OIDDeveloperIDDate):
		return "Developer ID Date"
	case oid.Equal(OIDWorldwideDeveloperRelationsWdrIntermediateCA):
		return "Worldwide Developer Relations Wdr Intermediate CA"
	case oid.Equal(OIDDeveloperIdIntermediateCA):
		return "Developer ID Intermediate CA"
	case oid.Equal(OIDCodeSigningEKU):
		return "CodeSigning EKU"
	case oid.Equal(OIDSafariDeveloperEKU):
		return "Safari Developer EKU"
	case oid.Equal(OID3rdPartyMacDeveloperInstallerEKU):
		return "3rd Party Mac Developer Installer EKU"
	case oid.Equal(OIDDeveloperIDInstallerEKU):
		return "Developer ID Installer EKU"
	case oid.Equal(OIDGeneralCapabilities):
		return "General Capabilities"
	case oid.Equal(OIDAirPlayCapabilities):
		return "AirPlay Capabilities"
	case oid.Equal(OIDHomeKitCapabilities):
		return "HomeKit Capabilities"
	case oid.Equal(OIDAuthVersion3):
		return "Auth Version3 "
	case oid.Equal(OIDAuthVersionSW):
		return "Auth Version SW"
	case oid.Equal(OIDAuthVersion4):
		return "Auth Version 4"
	default:
		return oid.String()
	}
}

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
