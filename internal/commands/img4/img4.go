package img4

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/img4"
	"github.com/blacktop/ipsw/pkg/lzfse"
	"github.com/pkg/errors"
)

func DecryptPayload(path, output string, iv, key []byte) error {
	var r io.Reader

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("unabled to open file %s: %v", path, err)
	}
	defer f.Close()

	i, err := img4.ParseIm4p(f)
	if err != nil {
		return errors.Wrap(err, "unabled to parse Im4p")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %v", err)
	}

	if len(i.Data) < aes.BlockSize {
		return fmt.Errorf("im4p data too short")
	}

	// CBC mode always works in whole blocks.
	if (len(i.Data) % aes.BlockSize) != 0 {
		return fmt.Errorf("im4p data is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	mode.CryptBlocks(i.Data, i.Data)

	if len(output) == 0 {
		output = path + ".dec"
	}

	of, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", output, err)
	}

	if bytes.Contains(i.Data[:4], []byte("bvx2")) {
		dat, err := lzfse.NewDecoder(i.Data).DecodeBuffer()
		if err != nil {
			return fmt.Errorf("failed to lzfse decompress %s: %v", path, err)
		}
		r = bytes.NewReader(dat)
	} else {
		r = bytes.NewReader(i.Data)
	}

	utils.Indent(log.Info, 2)(fmt.Sprintf("Decrypting file to %s", output))
	if _, err = io.Copy(of, r); err != nil {
		return fmt.Errorf("failed to decompress to file %s: %v", output, err)
	}

	return nil
}
