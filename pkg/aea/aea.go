package aea

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/cloudflare/circl/hpke"
)

//go:embed data/fcs-keys.gz
var keyData []byte

type fcsResponse struct {
	EncRequest string `json:"enc-request,omitempty"`
	WrappedKey string `json:"wrapped-key,omitempty"`
}

type Keys map[string][]byte

func getKeys() (Keys, error) {
	var keys Keys

	zr, err := gzip.NewReader(bytes.NewReader(keyData))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	if err := json.NewDecoder(zr).Decode(&keys); err != nil {
		return nil, fmt.Errorf("failed unmarshaling ipsw_db data: %w", err)
	}

	return keys, nil
}

type PrivateKey []byte

func (k PrivateKey) UnmarshalBinaryPrivateKey() ([]byte, error) {
	block, _ := pem.Decode(k)
	if block == nil {
		return nil, fmt.Errorf("failed to decode p8 key")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse p8 key: %v", err)
	}
	pkey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key must be of type ecdsa.PrivateKey")
	}
	return pkey.D.Bytes(), nil
}

type Metadata map[string][]byte

func (md Metadata) GetPrivateKey(data []byte, pemDB string, skipEmbedded bool) (map[string]PrivateKey, error) {
	out := make(map[string]PrivateKey)

	if len(data) > 0 {
		out["com.apple.wkms.fcs-key-url"] = PrivateKey(data)
		return out, nil
	}

	privKeyURL, ok := md["com.apple.wkms.fcs-key-url"]
	if !ok {
		return nil, fmt.Errorf("fcs-key-url key NOT found")
	}

	if !skipEmbedded {
		// check if keys are already loaded
		if keys, err := getKeys(); err == nil {
			u, err := url.Parse(string(privKeyURL))
			if err != nil {
				return nil, err
			}
			for k, v := range keys {
				if strings.EqualFold(k, path.Base(u.Path)) {
					out[k] = PrivateKey(v)
					return out, nil
				}
			}
		}
	}

	if pemDB != "" {
		pemData, err := os.ReadFile(pemDB)
		if err != nil {
			return nil, fmt.Errorf("failed to read pem DB JSON '%s': %w", pemDB, err)
		}
		var keys Keys
		if err := json.NewDecoder(bytes.NewReader(pemData)).Decode(&keys); err != nil {
			return nil, fmt.Errorf("failed unmarshaling ipsw_db data: %w", err)
		}
		u, err := url.Parse(string(privKeyURL))
		if err != nil {
			return nil, err
		}
		for k, v := range keys {
			if strings.EqualFold(k, path.Base(u.Path)) {
				out[k] = PrivateKey(v)
				return out, nil
			}
		}
	}

	resp, err := http.Get(string(privKeyURL))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to connect to fcs-key URL: %s", resp.Status)
	}

	privKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(string(privKeyURL))
	if err != nil {
		return nil, err
	}
	out[path.Base(u.Path)] = PrivateKey(privKey)

	return out, nil
}

func (md Metadata) DecryptFCS(pemData []byte, pemDB string) ([]byte, error) {
	ddata, ok := md["com.apple.wkms.fcs-response"]
	if !ok {
		return nil, fmt.Errorf("no 'com.apple.wkms.fcs-response' found in AEA metadata")
	}
	var fcsResp fcsResponse
	if err := json.Unmarshal(ddata, &fcsResp); err != nil {
		return nil, err
	}
	encRequestData, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(fcsResp.EncRequest)
	if err != nil {
		return nil, err
	}
	wrappedKeyData, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(fcsResp.WrappedKey)
	if err != nil {
		return nil, err
	}

	pkmap, err := md.GetPrivateKey(pemData, pemDB, false)
	if err != nil {
		return nil, err
	}
	var privKey []byte
	for _, pk := range pkmap {
		privKey, err = pk.UnmarshalBinaryPrivateKey()
		if err != nil {
			return nil, err
		}
	}

	// TODO: write my own HPKE implementation
	if len(privKey) > 32 {
		return nil, fmt.Errorf("private key must be 32 bytes")
	} else if len(privKey) < 32 {
		delta := 32 - len(privKey)
		// prepend zeros to make 32 bytes
		privKey = append(bytes.Repeat([]byte{0}, delta), privKey...)
	}

	kemID := hpke.KEM_P256_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES256GCM

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	recv, err := suite.NewReceiver(privateKey, nil)
	if err != nil {
		return nil, err
	}
	opener, err := recv.Setup(encRequestData)
	if err != nil {
		return nil, err
	}
	return opener.Open(wrappedKeyData, nil)
}

func Info(in string) (Metadata, error) {
	var metadata Metadata
	f, err := os.Open(in)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hdr Header
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return nil, err
	}

	if string(hdr.Magic[:]) != "AEA1" {
		return nil, fmt.Errorf("invalid AEA header: found '%s' expected 'AEA1'", string(hdr.Magic[:]))
	}

	metadata = make(map[string][]byte)
	mdr := io.NewSectionReader(f, int64(binary.Size(hdr)), int64(hdr.AuthDataLength))

	// parse key-value pairs
	for {
		var length uint32
		err := binary.Read(mdr, binary.LittleEndian, &length)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		keyval := make([]byte, length-uint32(binary.Size(length)))
		if _, err = mdr.Read(keyval); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		k, v, _ := bytes.Cut(keyval, []byte{0x00})
		metadata[string(k)] = v
	}

	return metadata, nil
}
