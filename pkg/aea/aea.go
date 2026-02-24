package aea

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
)

//go:embed data/fcs-keys.gz
var keyData []byte

type fcsResponse struct {
	EncRequest string `json:"enc-request,omitempty"`
	WrappedKey string `json:"wrapped-key,omitempty"`
}

type Keys map[string][]byte

func getKeys() (Keys, error) {
	keys := make(Keys)

	zr, err := gzip.NewReader(bytes.NewReader(keyData))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	if err := json.NewDecoder(zr).Decode(&keys); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return make(Keys), nil
		}
		return nil, fmt.Errorf("failed unmarshaling fcs-keys data: %w", err)
	}

	return keys, nil
}

func keyNameFromURL(privKeyURL []byte) (string, error) {
	u, err := url.Parse(string(privKeyURL))
	if err != nil {
		return "", err
	}
	return path.Base(u.Path), nil
}

func lookupPrivateKey(keys Keys, keyName string) (string, PrivateKey, bool) {
	for k, v := range keys {
		if strings.EqualFold(k, keyName) {
			return k, PrivateKey(v), true
		}
	}
	return "", nil, false
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

func (md Metadata) GetPrivateKey(data []byte, pemDB string, skipEmbedded bool, proxy string, insecure bool) (map[string]PrivateKey, error) {
	out := make(map[string]PrivateKey)

	if len(data) > 0 {
		out["com.apple.wkms.fcs-key-url"] = PrivateKey(data)
		return out, nil
	}

	privKeyURL, ok := md["com.apple.wkms.fcs-key-url"]
	if !ok {
		return nil, fmt.Errorf("fcs-key-url key NOT found")
	}
	keyName, err := keyNameFromURL(privKeyURL)
	if err != nil {
		return nil, err
	}

	if !skipEmbedded {
		// check if keys are already loaded
		if keys, err := getKeys(); err == nil {
			if len(keys) == 0 {
				log.Warn("embedded FCS keys DB is empty; falling back to PEM DB/online lookup")
			} else {
				if matchedKey, pk, found := lookupPrivateKey(keys, keyName); found {
					out[matchedKey] = pk
					return out, nil
				}
			}
		} else {
			log.WithError(err).Warn("failed to parse embedded FCS keys DB; falling back to PEM DB/online lookup")
		}
	}

	if pemDB != "" {
		pemData, err := os.ReadFile(pemDB)
		if err != nil {
			log.WithError(err).Warnf("failed to read PEM DB JSON '%s'; falling back to online lookup", pemDB)
		} else {
			var keys Keys
			if err := json.NewDecoder(bytes.NewReader(pemData)).Decode(&keys); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					log.Warnf("PEM DB JSON '%s' is empty/corrupt; falling back to online lookup", pemDB)
				} else {
					log.WithError(err).Warnf("failed to parse PEM DB JSON '%s'; falling back to online lookup", pemDB)
				}
			} else {
				if matchedKey, pk, found := lookupPrivateKey(keys, keyName); found {
					out[matchedKey] = pk
					return out, nil
				}
			}
		}
	}

	cli := &http.Client{
		Transport: &http.Transport{
			Proxy:           download.GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}
	req, err := http.NewRequest("GET", string(privKeyURL), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for fcs-key URL: %w", err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to fcs-key URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to connect to fcs-key URL: %s", resp.Status)
	}

	privKey, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	out[keyName] = PrivateKey(privKey)

	return out, nil
}

func (md Metadata) DecryptFCS(pemData []byte, pemDB string, proxy string, insecure bool) ([]byte, error) {
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

	pkmap, err := md.GetPrivateKey(pemData, pemDB, false, proxy, insecure)
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

	kemID := hpke.DHKEM(ecdh.P256())
	kdfID := hpke.HKDFSHA256()
	aeadID := hpke.AES256GCM()

	privateKey, err := kemID.NewPrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	recv, err := hpke.NewRecipient(encRequestData, privateKey, kdfID, aeadID, nil)
	if err != nil {
		return nil, err
	}
	return recv.Open(nil, wrappedKeyData)
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
