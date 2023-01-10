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

var encodeIndent = 0

type asn1Object interface {
	encodeTo(writer *bytes.Buffer) error
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func (s asn1Structured) encodeTo(out *bytes.Buffer) error {
	//fmt.Printf("%s--> tag: % X\n", strings.Repeat("| ", encodeIndent), s.tagBytes)
	encodeIndent++
	inner := new(bytes.Buffer)
	for _, obj := range s.content {
		err := obj.encodeTo(inner)
		if err != nil {
			return err
		}
	}
	encodeIndent--
	out.Write(s.tagBytes)
	encodeLength(out, inner.Len())
	out.Write(inner.Bytes())
	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	length   int
	content  []byte
}

func (p asn1Primitive) encodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, p.length); err != nil {
		return err
	}
	//fmt.Printf("%s--> tag: % X length: %d\n", strings.Repeat("| ", encodeIndent), p.tagBytes, p.length)
	//fmt.Printf("%s--> content length: %d\n", strings.Repeat("| ", encodeIndent), len(p.content))
	out.Write(p.content)

	return nil
}

func ber2Der(ber []byte) ([]byte, error) {
	out := new(bytes.Buffer)
	obj, _, err := readObject(ber, 0)
	if err != nil {
		return nil, err
	}
	obj.encodeTo(out)
	return out.Bytes(), nil
}

func marshalLongLength(out *bytes.Buffer, i int) (err error) {
	n := lengthLength(i)
	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}
	return nil
}

func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

func encodeLength(out *bytes.Buffer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		err = out.WriteByte(0x80 | byte(l))
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		err = out.WriteByte(byte(length))
		if err != nil {
			return
		}
	}
	return
}

func readObject(ber []byte, offset int) (asn1Object, int, error) {
	tagStart := offset
	b := ber[offset]
	offset++
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		tag = 0
		for ber[offset] >= 0x80 {
			tag = tag*128 + ber[offset] - 0x80
			offset++
		}
		tag = tag*128 + ber[offset] - 0x80
		offset++
	}
	tagEnd := offset

	kind := b & 0x20

	var length int
	l := ber[offset]
	offset++
	indefinite := false
	if l > 0x80 {
		numberOfBytes := (int)(l & 0x7F)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, 0, fmt.Errorf("BER tag length too long")
		}
		if numberOfBytes == 4 && (int)(ber[offset]) > 0x7F {
			return nil, 0, fmt.Errorf("BER tag length is negative")
		}
		if 0x0 == (int)(ber[offset]) {
			return nil, 0, fmt.Errorf("BER tag length has leading zero")
		}
		//fmt.Printf("--> (compute length) indicator byte: %x\n", l)
		//fmt.Printf("--> (compute length) length bytes: % X\n", ber[offset:offset+numberOfBytes])
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + (int)(ber[offset])
			offset++
		}
	} else if l == 0x80 {
		indefinite = true
	} else {
		length = (int)(l)
	}

	//fmt.Printf("--> length        : %d\n", length)
	contentEnd := offset + length
	if contentEnd > len(ber) {
		return nil, 0, fmt.Errorf("BER tag length is more than available data")
	}
	//fmt.Printf("--> content start : %d\n", offset)
	//fmt.Printf("--> content end   : %d\n", contentEnd)
	//fmt.Printf("--> content       : % X\n", ber[offset:contentEnd])
	var obj asn1Object
	if indefinite && kind == 0 {
		return nil, 0, fmt.Errorf("indefinite form tag must have constructed encoding")
	}
	if kind == 0 {
		obj = asn1Primitive{
			tagBytes: ber[tagStart:tagEnd],
			length:   length,
			content:  ber[offset:contentEnd],
		}
	} else {
		var subObjects []asn1Object
		for (offset < contentEnd) || indefinite {
			var subObj asn1Object
			var err error
			subObj, offset, err = readObject(ber, offset)
			if err != nil {
				return nil, 0, err
			}
			subObjects = append(subObjects, subObj)

			if indefinite {
				terminated, err := isIndefiniteTermination(ber, offset)
				if err != nil {
					return nil, 0, err
				}

				if terminated {
					break
				}
			}
		}
		obj = asn1Structured{
			tagBytes: ber[tagStart:tagEnd],
			content:  subObjects,
		}
	}

	// Apply indefinite form length with 0x0000 terminator.
	if indefinite {
		contentEnd = offset + 2
	}

	return obj, contentEnd, nil
}

func isIndefiniteTermination(ber []byte, offset int) (bool, error) {
	if len(ber)-offset < 2 {
		return false, fmt.Errorf("indefinite form tag is missing terminator")
	}
	return bytes.Index(ber[offset:], []byte{0x0, 0x0}) == 0, nil
}
