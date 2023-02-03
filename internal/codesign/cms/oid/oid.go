package oid

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
)

var (
	ContentTypeData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	ContentTypeSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	ContentTypeTSTInfo    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}

	AttributeAppleHashAgilityV1  = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 1}
	AttributeAppleHashAgilityV2  = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 2}
	AttributeAppleExpirationTime = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 9, 3}
	AttributeContentType         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	AttributeMessageDigest       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	AttributeSigningTime         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	AttributeTimeStampToken      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 14}

	PublicKeyAlgorithmRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	PublicKeyAlgorithmECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	DigestAlgorithmSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	DigestAlgorithmMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	DigestAlgorithmSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	DigestAlgorithmSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	DigestAlgorithmSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	SignatureAlgorithmMD2WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 2}
	SignatureAlgorithmMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	SignatureAlgorithmSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	SignatureAlgorithmSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	SignatureAlgorithmSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	SignatureAlgorithmSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	SignatureAlgorithmRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	SignatureAlgorithmDSAWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	SignatureAlgorithmDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	SignatureAlgorithmECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	SignatureAlgorithmECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	SignatureAlgorithmECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	SignatureAlgorithmECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	SignatureAlgorithmISOSHA1WithRSA  = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 29}

	ExtensionSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}
)

// DigestAlgorithmToCryptoHash maps digest OIDs to crypto.Hash values.
var DigestAlgorithmToCryptoHash = map[string]crypto.Hash{
	DigestAlgorithmSHA1.String():   crypto.SHA1,
	DigestAlgorithmMD5.String():    crypto.MD5,
	DigestAlgorithmSHA256.String(): crypto.SHA256,
	DigestAlgorithmSHA384.String(): crypto.SHA384,
	DigestAlgorithmSHA512.String(): crypto.SHA512,
}

// CryptoHashToDigestAlgorithm maps crypto.Hash values to digest OIDs.
var CryptoHashToDigestAlgorithm = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA1:   DigestAlgorithmSHA1,
	crypto.MD5:    DigestAlgorithmMD5,
	crypto.SHA256: DigestAlgorithmSHA256,
	crypto.SHA384: DigestAlgorithmSHA384,
	crypto.SHA512: DigestAlgorithmSHA512,
}

// X509SignatureAlgorithmToDigestAlgorithm maps x509.SignatureAlgorithm to
// digestAlgorithm OIDs.
var X509SignatureAlgorithmToDigestAlgorithm = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
	x509.SHA1WithRSA:     DigestAlgorithmSHA1,
	x509.MD5WithRSA:      DigestAlgorithmMD5,
	x509.SHA256WithRSA:   DigestAlgorithmSHA256,
	x509.SHA384WithRSA:   DigestAlgorithmSHA384,
	x509.SHA512WithRSA:   DigestAlgorithmSHA512,
	x509.ECDSAWithSHA1:   DigestAlgorithmSHA1,
	x509.ECDSAWithSHA256: DigestAlgorithmSHA256,
	x509.ECDSAWithSHA384: DigestAlgorithmSHA384,
	x509.ECDSAWithSHA512: DigestAlgorithmSHA512,
}

// X509SignatureAlgorithmToPublicKeyAlgorithm maps x509.SignatureAlgorithm to
// signatureAlgorithm OIDs.
var X509SignatureAlgorithmToPublicKeyAlgorithm = map[x509.SignatureAlgorithm]asn1.ObjectIdentifier{
	x509.SHA1WithRSA:     PublicKeyAlgorithmRSA,
	x509.MD5WithRSA:      PublicKeyAlgorithmRSA,
	x509.SHA256WithRSA:   PublicKeyAlgorithmRSA,
	x509.SHA384WithRSA:   PublicKeyAlgorithmRSA,
	x509.SHA512WithRSA:   PublicKeyAlgorithmRSA,
	x509.ECDSAWithSHA1:   PublicKeyAlgorithmECDSA,
	x509.ECDSAWithSHA256: PublicKeyAlgorithmECDSA,
	x509.ECDSAWithSHA384: PublicKeyAlgorithmECDSA,
	x509.ECDSAWithSHA512: PublicKeyAlgorithmECDSA,
}

// PublicKeyAndDigestAlgorithmToX509SignatureAlgorithm maps digest and signature
// OIDs to x509.SignatureAlgorithm values.
var PublicKeyAndDigestAlgorithmToX509SignatureAlgorithm = map[string]map[string]x509.SignatureAlgorithm{
	PublicKeyAlgorithmRSA.String(): {
		DigestAlgorithmSHA1.String():   x509.SHA1WithRSA,
		DigestAlgorithmMD5.String():    x509.MD5WithRSA,
		DigestAlgorithmSHA256.String(): x509.SHA256WithRSA,
		DigestAlgorithmSHA384.String(): x509.SHA384WithRSA,
		DigestAlgorithmSHA512.String(): x509.SHA512WithRSA,
	},
	PublicKeyAlgorithmECDSA.String(): {
		DigestAlgorithmSHA1.String():   x509.ECDSAWithSHA1,
		DigestAlgorithmSHA256.String(): x509.ECDSAWithSHA256,
		DigestAlgorithmSHA384.String(): x509.ECDSAWithSHA384,
		DigestAlgorithmSHA512.String(): x509.ECDSAWithSHA512,
	},
}

// SignatureAlgorithmToX509SignatureAlgorithm maps signature algorithm OIDs to
// x509.SignatureAlgorithm values.
var SignatureAlgorithmToX509SignatureAlgorithm = map[string]x509.SignatureAlgorithm{
	SignatureAlgorithmSHA1WithRSA.String():     x509.SHA1WithRSA,
	SignatureAlgorithmMD5WithRSA.String():      x509.MD5WithRSA,
	SignatureAlgorithmSHA256WithRSA.String():   x509.SHA256WithRSA,
	SignatureAlgorithmSHA384WithRSA.String():   x509.SHA384WithRSA,
	SignatureAlgorithmSHA512WithRSA.String():   x509.SHA512WithRSA,
	SignatureAlgorithmECDSAWithSHA1.String():   x509.ECDSAWithSHA1,
	SignatureAlgorithmECDSAWithSHA256.String(): x509.ECDSAWithSHA256,
	SignatureAlgorithmECDSAWithSHA384.String(): x509.ECDSAWithSHA384,
	SignatureAlgorithmECDSAWithSHA512.String(): x509.ECDSAWithSHA512,
	SignatureAlgorithmDSAWithSHA1.String():     x509.DSAWithSHA1,
}

// X509PublicKeyAndDigestAlgorithmToSignatureAlgorithm maps X509 public key and
// digest algorithms to to SignatureAlgorithm OIDs.
var X509PublicKeyAndDigestAlgorithmToSignatureAlgorithm = map[x509.PublicKeyAlgorithm]map[string]asn1.ObjectIdentifier{
	x509.RSA: {
		DigestAlgorithmSHA1.String():   SignatureAlgorithmSHA1WithRSA,
		DigestAlgorithmMD5.String():    SignatureAlgorithmMD5WithRSA,
		DigestAlgorithmSHA256.String(): SignatureAlgorithmSHA256WithRSA,
		DigestAlgorithmSHA384.String(): SignatureAlgorithmSHA384WithRSA,
		DigestAlgorithmSHA512.String(): SignatureAlgorithmSHA512WithRSA,
	},
	x509.ECDSA: {
		DigestAlgorithmSHA1.String():   SignatureAlgorithmECDSAWithSHA1,
		DigestAlgorithmSHA256.String(): SignatureAlgorithmECDSAWithSHA256,
		DigestAlgorithmSHA384.String(): SignatureAlgorithmECDSAWithSHA384,
		DigestAlgorithmSHA512.String(): SignatureAlgorithmECDSAWithSHA512,
	},
}
