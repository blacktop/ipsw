package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/codesign/cms/oid"
)

// CREDIT - https://github.com/github/smimesign/tree/main/ietf-cms

// AnySet is a helper for dealing with SET OF ANY types.
type AnySet struct {
	Elements []asn1.RawValue `asn1:"set"`
}

// NewAnySet creates a new AnySet.
func NewAnySet(elts ...asn1.RawValue) AnySet {
	return AnySet{elts}
}

// DecodeAnySet manually decodes a SET OF ANY type, since Go's parser can't
// handle them.
func DecodeAnySet(rv asn1.RawValue) (as AnySet, err error) {
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagSet {
		err = fmt.Errorf("bad class: expecting %d, got %d", asn1.ClassUniversal, rv.Class)
		return
	}

	der := rv.Bytes
	for len(der) > 0 {
		if der, err = asn1.Unmarshal(der, &rv); err != nil {
			return
		}

		as.Elements = append(as.Elements, rv)
	}

	return
}

// Encode manually encodes a SET OF ANY type, since Go's parser can't handle
// them.
func (as AnySet) Encode(dst *asn1.RawValue) (err error) {
	dst.Class = asn1.ClassUniversal
	dst.Tag = asn1.TagSet
	dst.IsCompound = true

	var der []byte
	for _, elt := range as.Elements {
		if der, err = asn1.Marshal(elt); err != nil {
			return
		}

		dst.Bytes = append(dst.Bytes, der...)
	}

	dst.FullBytes, err = asn1.Marshal(*dst)

	return
}

type Attribute struct {
	Type asn1.ObjectIdentifier
	// This should be a SET OF ANY, but Go's asn1 parser can't handle slices of
	// RawValues. Use value() to get an AnySet of the value.
	RawValue asn1.RawValue
}

type Attributes []Attribute

func (attrs Attributes) MarshaledForSigning() ([]byte, error) {
	seq, err := asn1.Marshal(struct {
		Attributes `asn1:"set"`
	}{attrs})
	if err != nil {
		return nil, err
	}

	// unwrap the outer SEQUENCE
	var raw asn1.RawValue
	if _, err = asn1.Unmarshal(seq, &raw); err != nil {
		return nil, err
	}

	return raw.Bytes, nil
}

type SignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        Attributes `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      Attributes `asn1:"set,optional,tag:1"`
}

func (si SignerInfo) Hash() (crypto.Hash, error) {
	algo := si.DigestAlgorithm.Algorithm.String()
	hash := oid.DigestAlgorithmToCryptoHash[algo]
	if hash == 0 || !hash.Available() {
		return 0, fmt.Errorf("unsupported digest algorithm: %s", algo)
	}
	return hash, nil
}

type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

func (eci EncapsulatedContentInfo) EContentValue() ([]byte, error) {
	if eci.EContent.Bytes == nil {
		return nil, nil
	}

	// The EContent is an `[0] EXPLICIT OCTET STRING`. EXPLICIT means that there
	// is another whole tag wrapping the OCTET STRING. When we decoded the
	// EContent into a asn1.RawValue we're just getting that outer tag, so the
	// EContent.Bytes is the encoded OCTET STRING, which is what we really want
	// the value of.
	var octets asn1.RawValue
	if rest, err := asn1.Unmarshal(eci.EContent.Bytes, &octets); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("unexpected trailing data after EContent: %x", rest)
	}
	if octets.Class != asn1.ClassUniversal || octets.Tag != asn1.TagOctetString {
		return nil, fmt.Errorf("unexpected EContent tag: %d; or class: %d", octets.Tag, octets.Class)
	}

	// While we already tried converting BER to DER, we didn't take constructed
	// types into account. Constructed string types, as opposed to primitive
	// types, can encode indefinite length strings by including a bunch of
	// sub-strings that are joined together to get the actual value. Gpgsm uses
	// a constructed OCTET STRING for the EContent, so we have to manually decode
	// it here.
	var value []byte
	if octets.IsCompound {
		rest := octets.Bytes
		for len(rest) > 0 {
			var err error
			if rest, err = asn1.Unmarshal(rest, &octets); err != nil {
				return nil, err
			}

			// Don't allow further constructed types.
			if octets.Class != asn1.ClassUniversal || octets.Tag != asn1.TagOctetString || octets.IsCompound {
				return nil, fmt.Errorf("unexpected EContent tag: %d; or class: %d", octets.Tag, octets.Class)
			}

			value = append(value, octets.Bytes...)
		}
	} else {
		value = octets.Bytes
	}

	return value, nil
}

type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     []asn1.RawValue `asn1:"optional,set,tag:0"`
	CRLs             []asn1.RawValue `asn1:"optional,set,tag:1"`
	SignerInfos      []SignerInfo    `asn1:"set"`
}

type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type AppleHashAgility struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

type CDHash struct {
	CDHashes [][]byte `plist:"cdhashes,omitempty" xml:"cdhashes,omitempty"`
}

func NewSignedData(data []byte) (*SignedData, error) {
	octets, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagOctetString,
		Bytes:      data,
		IsCompound: false,
	})
	if err != nil {
		return nil, err
	}

	return &SignedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: oid.ContentTypeData,
			EContent: asn1.RawValue{
				Class:      asn1.ClassContextSpecific,
				Tag:        0,
				Bytes:      octets,
				IsCompound: true,
			},
		},
		SignerInfos: []SignerInfo{},
	}, nil
}

func (sd *SignedData) Sign(chain []*x509.Certificate, privateKey any) error {
	var certPub []byte
	var cert *x509.Certificate

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return errors.New("private key does not implement crypto.Signer")
	}

	pub, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}

	for _, c := range chain {
		if err = sd.AddCertificate(c); err != nil {
			return err
		}

		if certPub, err = x509.MarshalPKIXPublicKey(c.PublicKey); err != nil {
			return err
		}

		if bytes.Equal(pub, certPub) {
			cert = c
		}
	}
	if cert == nil {
		return errors.New("no certificate found for public key")
	}

	sid, err := newIssuerAndSerialNumber(cert)
	if err != nil {
		return err
	}

	digestAlgorithmID := digestAlgorithmForPublicKey(pub)

	signatureAlgorithmOID, ok := oid.X509PublicKeyAndDigestAlgorithmToSignatureAlgorithm[cert.PublicKeyAlgorithm][digestAlgorithmID.Algorithm.String()]
	if !ok {
		return errors.New("unsupported certificate public key algorithm")
	}

	signatureAlgorithmID := pkix.AlgorithmIdentifier{Algorithm: signatureAlgorithmOID}

	si := SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlgorithmID,
		SignedAttrs:        nil,
		SignatureAlgorithm: signatureAlgorithmID,
		Signature:          nil,
		UnsignedAttrs:      nil,
	}

	// Get the message
	content, err := sd.EncapContentInfo.EContentValue()
	if err != nil {
		return err
	}
	if content == nil {
		return errors.New("already detached")
	}

	// Digest the message.
	hash, err := si.Hash()
	if err != nil {
		return err
	}
	md := hash.New()
	if _, err = md.Write(content); err != nil {
		return err
	}
	pldata, err := plist.MarshalIndent(CDHash{
		CDHashes: [][]byte{md.Sum(nil)[:20]},
	}, plist.XMLFormat, "\t")
	if err != nil {
		return err
	}

	// Build our SignedAttributes
	stAttr, err := NewAttribute(oid.AttributeSigningTime, time.Now().UTC())
	if err != nil {
		return err
	}
	mdAttr, err := NewAttribute(oid.AttributeMessageDigest, md.Sum(nil))
	if err != nil {
		return err
	}
	ctAttr, err := NewAttribute(oid.AttributeContentType, sd.EncapContentInfo.EContentType)
	if err != nil {
		return err
	}
	hvAttr, err := NewAttribute(oid.AttributeAppleHashAgilityV1, pldata)
	if err != nil {
		return err
	}
	hv2Attr, err := NewAttribute(oid.AttributeAppleHashAgilityV2, AppleHashAgility{
		Type: oid.DigestAlgorithmSHA256,
		Content: asn1.RawValue{
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagOctetString,
			Bytes:      md.Sum(nil),
			IsCompound: false,
		},
	})
	if err != nil {
		return err
	}

	// sort attributes to match required order in marshaled form
	si.SignedAttrs, err = sortAttributes(stAttr, mdAttr, ctAttr, hvAttr, hv2Attr)
	if err != nil {
		return err
	}

	// Signature is over the marshaled signed attributes
	sm, err := si.SignedAttrs.MarshaledForSigning()
	if err != nil {
		return err
	}
	smd := hash.New()
	if _, err := smd.Write(sm); err != nil {
		return err
	}
	if si.Signature, err = signer.Sign(rand.Reader, smd.Sum(nil), hash); err != nil {
		return err
	}

	sd.addDigestAlgorithm(si.DigestAlgorithm)

	sd.SignerInfos = append(sd.SignerInfos, si)

	return nil
}

func (sd *SignedData) addDigestAlgorithm(algo pkix.AlgorithmIdentifier) {
	for _, existing := range sd.DigestAlgorithms {
		if existing.Algorithm.Equal(algo.Algorithm) {
			return
		}
	}

	sd.DigestAlgorithms = append(sd.DigestAlgorithms, algo)
}

func (sd *SignedData) AddCertificate(cert *x509.Certificate) error {
	for _, c := range sd.Certificates {
		if bytes.Equal(c.Bytes, cert.Raw) {
			return nil
		}
	}
	var rv asn1.RawValue
	if _, err := asn1.Unmarshal(cert.Raw, &rv); err != nil {
		return err
	}
	sd.Certificates = append(sd.Certificates, rv)
	return nil
}

func (sd *SignedData) AddTimestamps(url, proxy string, insecure bool) error {
	var err error
	var attrs = make([]Attribute, len(sd.SignerInfos))

	for i := range attrs {
		if attrs[i], err = GetTimestamp(url, proxy, insecure, sd.SignerInfos[i]); err != nil {
			return err
		}
	}

	for i := range attrs {
		sd.SignerInfos[i].UnsignedAttrs = append(sd.SignerInfos[i].UnsignedAttrs, attrs[i])
	}

	return nil
}

func (sd *SignedData) Detached() {
	sd.EncapContentInfo.EContent = asn1.RawValue{}
}

func (sd *SignedData) ToDER() ([]byte, error) {
	der, err := asn1.Marshal(*sd)
	if err != nil {
		return nil, err
	}
	ci := ContentInfo{
		ContentType: oid.ContentTypeSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			Bytes:      der,
			IsCompound: true,
		},
	}
	return asn1.Marshal(ci)
}

func NewAttribute(typ asn1.ObjectIdentifier, val any) (attr Attribute, err error) {
	var der []byte
	if der, err = asn1.Marshal(val); err != nil {
		return
	}

	var rv asn1.RawValue
	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return
	}

	if err = NewAnySet(rv).Encode(&attr.RawValue); err != nil {
		return
	}

	attr.Type = typ

	return
}

func newIssuerAndSerialNumber(cert *x509.Certificate) (rv asn1.RawValue, err error) {
	sid := IssuerAndSerialNumber{
		SerialNumber: new(big.Int).Set(cert.SerialNumber),
	}
	if _, err = asn1.Unmarshal(cert.RawIssuer, &sid.Issuer); err != nil {
		return
	}
	var der []byte
	if der, err = asn1.Marshal(sid); err != nil {
		return
	}
	if _, err = asn1.Unmarshal(der, &rv); err != nil {
		return
	}
	return
}

func digestAlgorithmForPublicKey(pub crypto.PublicKey) pkix.AlgorithmIdentifier {
	if ecPub, ok := pub.(*ecdsa.PublicKey); ok {
		switch ecPub.Curve {
		case elliptic.P384():
			return pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA384}
		case elliptic.P521():
			return pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA512}
		}
	}
	return pkix.AlgorithmIdentifier{Algorithm: oid.DigestAlgorithmSHA256}
}

func sortAttributes(attrs ...Attribute) ([]Attribute, error) {
	// Sort attrs by their encoded values (including tag and
	// lengths) as specified in X690 Section 11.6 and implemented
	// in go >= 1.15's asn1.Marshal().
	sort.Slice(attrs, func(i, j int) bool {
		return bytes.Compare(
			attrs[i].RawValue.FullBytes,
			attrs[j].RawValue.FullBytes) < 0
	})

	return attrs, nil
}
