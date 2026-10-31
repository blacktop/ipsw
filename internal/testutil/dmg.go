package testutil

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"

	"github.com/blacktop/go-apfs/pkg/disk/dmg"
	"github.com/blacktop/go-plist"
)

// WriteEncryptedDMG writes an encrcdsa v2 container holding plain and returns
// the 72-hex-character iPhone Wiki style key (AES-128 key + HMAC-SHA1 key)
// that decrypts it.
func WriteEncryptedDMG(t testing.TB, path string, plain []byte) string {
	t.Helper()
	const blocksize = 512
	padded := make([]byte, (len(plain)+blocksize-1)/blocksize*blocksize)
	copy(padded, plain)
	aesKey := bytes.Repeat([]byte{0x5a}, 16)
	hmacKey := bytes.Repeat([]byte{0xa5}, 20)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	hdr := dmg.EncryptionHeader{
		Version:        2,
		DataEncKeyBits: 128,
		HmacKeyBits:    160,
		Blocksize:      blocksize,
		Datasize:       uint64(len(plain)),
	}
	copy(hdr.Magic[:], dmg.EncryptedMagic)
	hdr.Dataoffset = uint64(binary.Size(hdr))
	var image bytes.Buffer
	if err := binary.Write(&image, binary.BigEndian, hdr); err != nil {
		t.Fatal(err)
	}
	encrypted := make([]byte, blocksize)
	for i := 0; i < len(padded)/blocksize; i++ {
		mac := hmac.New(sha1.New, hmacKey)
		if err := binary.Write(mac, binary.BigEndian, uint32(i)); err != nil {
			t.Fatal(err)
		}
		iv := mac.Sum(nil)[:aes.BlockSize]
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, padded[i*blocksize:(i+1)*blocksize])
		image.Write(encrypted)
	}
	if err := os.WriteFile(path, image.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(aesKey) + hex.EncodeToString(hmacKey)
}

// UDIFImage returns a zlib-compressed UDIF container whose single partition
// decodes to plain. len(plain) must be a multiple of 512.
func UDIFImage(t testing.TB, plain []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	// One mish block with one zlib chunk. The fields use sector units.
	blkx := make([]byte, 204+40)
	copy(blkx, "mish")
	binary.BigEndian.PutUint32(blkx[4:], 1)
	binary.BigEndian.PutUint64(blkx[16:], uint64(len(plain)/512))
	binary.BigEndian.PutUint32(blkx[32:], 1)
	binary.BigEndian.PutUint32(blkx[200:], 1)
	binary.BigEndian.PutUint32(blkx[204:], 0x80000005)
	binary.BigEndian.PutUint64(blkx[220:], uint64(len(plain)/512))
	binary.BigEndian.PutUint64(blkx[236:], uint64(compressed.Len()))
	p, err := plist.Marshal(map[string]any{"resource-fork": map[string]any{
		"blkx": []map[string]any{{"Name": "synthetic partition", "Data": blkx}},
	}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	footer := dmg.UDIFResourceFile{
		Signature: [4]byte{'k', 'o', 'l', 'y'}, Version: 4, HeaderSize: 512,
		DataForkLength: uint64(compressed.Len()), PlistOffset: uint64(compressed.Len()),
		PlistLength: uint64(len(p)), SectorCount: uint64(len(plain) / 512),
	}
	var image bytes.Buffer
	image.Write(compressed.Bytes())
	image.Write(p)
	if err := binary.Write(&image, binary.BigEndian, footer); err != nil {
		t.Fatal(err)
	}
	return image.Bytes()
}
