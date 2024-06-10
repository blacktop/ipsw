package aea

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
)

type Header struct {
	Magic   [4]byte // AEA1
	Version uint32
	Length  uint32
}

func Parse(in, out string) error {
	var keyval []byte

	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}

	r := bytes.NewReader(data)

	var hdr Header
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return err
	}

	metadata := make([]byte, hdr.Length-uint32(binary.Size(hdr)))
	if _, err := r.Read(metadata); err != nil {
		return err
	}
	mr := bytes.NewReader(metadata)

	// parse key-value pairs
	for {
		var length uint32
		err := binary.Read(mr, binary.LittleEndian, &length)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		keyval = make([]byte, length-uint32(binary.Size(length)))
		_, err = mr.Read(keyval)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		key, val, _ := bytes.Cut(keyval, []byte{0x00})
		// fmt.Printf("%s: %s\n", key, val)
		os.WriteFile(filepath.Join(out, string(key)), val, 0644)
	}

	edata, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	os.WriteFile(filepath.Join(out, "enc.data"), edata, 0644)

	// TODO: decrypt data

	// ivkey, err := os.ReadFile(filepath.Join(out, "KEY"))
	// if err != nil {
	// 	return err
	// }

	// eiv := ivkey[:aes.BlockSize]
	// ekey := ivkey[aes.BlockSize:]

	// block, err := aes.NewCipher(ekey)
	// if err != nil {
	// 	return fmt.Errorf("failed to create AES cipher: %v", err)
	// }

	// if len(edata) < aes.BlockSize {
	// 	return fmt.Errorf("im4p data too short")
	// }

	// // CBC mode always works in whole blocks.
	// if (len(edata) % aes.BlockSize) != 0 {
	// 	return fmt.Errorf("im4p data is not a multiple of the block size")
	// }

	// mode := cipher.NewCBCDecrypter(block, eiv)

	// mode.CryptBlocks(edata, edata)
	// os.WriteFile(filepath.Join(out, "dec.data"), edata, 0644)

	return nil
}
