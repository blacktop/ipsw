package cms

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/blacktop/ipsw/internal/codesign/cms/oid"
	"github.com/blacktop/ipsw/internal/download"
)

type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type Request struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"tag:1,optional"`
}

type PKIFreeText []asn1.RawValue

type PKIStatusInfo struct {
	Status       int
	StatusString PKIFreeText    `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type Response struct {
	Status         PKIStatusInfo
	TimeStampToken ContentInfo `asn1:"optional"`
}

func GetTimestamp(url, proxy string, insecure bool, si SignerInfo) (Attribute, error) {
	hash, err := si.Hash()
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to get hash: %v", err)
	}

	mi, err := newMessageImprint(hash, bytes.NewReader(si.Signature))
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to create message imprint: %v", err)
	}

	nonce, err := rand.Int(rand.Reader, big.NewInt(1000))
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to generate nonce: %v", err)
	}

	reqDER, err := asn1.Marshal(Request{
		Version:        1,
		CertReq:        true,
		Nonce:          nonce,
		MessageImprint: mi,
	})
	if err != nil {
		return Attribute{}, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(reqDER))
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to create http POST request: %v", err)
	}
	req.Header.Add("Content-Type", "application/timestamp-query")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to do http POST request: %v", err)
	}
	defer resp.Body.Close()

	document, err := io.ReadAll(resp.Body)
	if err != nil {
		return Attribute{}, fmt.Errorf("failed to read http response body: %v", err)
	}

	var tsresp Response
	der, err := ber2Der(document)
	if err != nil {
		return Attribute{}, err
	}
	rest, err := asn1.Unmarshal(der, &tsresp)
	if err != nil {
		return Attribute{}, err
	}
	if len(rest) > 0 {
		return Attribute{}, fmt.Errorf("trailing data after timestamp response")
	}

	return NewAttribute(oid.AttributeTimeStampToken, tsresp.TimeStampToken)
}

func newMessageImprint(hash crypto.Hash, r io.Reader) (MessageImprint, error) {
	digestAlgorithm := oid.CryptoHashToDigestAlgorithm[hash]
	if len(digestAlgorithm) == 0 {
		return MessageImprint{}, fmt.Errorf("unsupported hash algorithm: %s", hash.String())
	}
	if !hash.Available() {
		return MessageImprint{}, fmt.Errorf("unsupported hash algorithm: %s", hash.String())
	}
	h := hash.New()
	if _, err := io.Copy(h, r); err != nil {
		return MessageImprint{}, err
	}
	return MessageImprint{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: digestAlgorithm},
		HashedMessage: h.Sum(nil),
	}, nil
}
