package aea

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/cloudflare/circl/hpke"
)

type Header struct {
	Magic   [4]byte // AEA1
	Version uint32
	Length  uint32
}

type fcsResponse struct {
	EncRequest string `json:"enc-request,omitempty"`
	WrappedKey string `json:"wrapped-key,omitempty"`
}

func Parse(in, out string, privKey []byte) (string, error) {
	metadata := make(map[string][]byte)

	data, err := os.ReadFile(in)
	if err != nil {
		return "", err
	}

	r := bytes.NewReader(data)

	var hdr Header
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return "", err
	}

	// parse key-value pairs
	for {
		var length uint32
		err := binary.Read(r, binary.LittleEndian, &length)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}

		keyval := make([]byte, length-uint32(binary.Size(length)))
		_, err = r.Read(keyval)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}

		k, v, _ := bytes.Cut(keyval, []byte{0x00})
		metadata[string(k)] = v // FIXME: don't parse DATA (past metadata)
	}

	if privKey == nil {
		privKeyURL, ok := metadata["com.apple.wkms.fcs-key-url"]
		if !ok {
			return "", fmt.Errorf("no private key URL found")
		}
		resp, err := http.Get(string(privKeyURL))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		privKey, err = io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
	}

	ddata, ok := metadata["com.apple.wkms.fcs-response"]
	if !ok {
		return "", fmt.Errorf("no fcs response found")
	}
	var fcsResp fcsResponse
	if err := json.Unmarshal(ddata, &fcsResp); err != nil {
		return "", err
	}
	encRequestData, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(fcsResp.EncRequest)
	if err != nil {
		return "", err
	}
	wrappedKeyData, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(fcsResp.WrappedKey)
	if err != nil {
		return "", err
	}

	kemID := hpke.KEM_P256_HKDF_SHA256
	kdfID := hpke.KDF_HKDF_SHA256
	aeadID := hpke.AEAD_AES256GCM

	suite := hpke.NewSuite(kemID, kdfID, aeadID)

	block, _ := pem.Decode(privKey)
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("createToken: failed to parse p8 key: %v", err)
	}
	pkey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("createToken: AuthKey must be of type ecdsa.PrivateKey")
	}
	privateKey, err := kemID.Scheme().UnmarshalBinaryPrivateKey(pkey.D.Bytes())
	if err != nil {
		return "", err
	}
	recv, err := suite.NewReceiver(privateKey, nil)
	if err != nil {
		return "", err
	}
	opener, err := recv.Setup(encRequestData)
	if err != nil {
		return "", err
	}
	wkey, err := opener.Open(wrappedKeyData, nil)
	if err != nil {
		return "", err
	}

	return utils.Aea(in, filepath.Join(out, filepath.Base(strings.TrimSuffix(in, filepath.Ext(in)))), base64.StdEncoding.EncodeToString(wkey))
}
