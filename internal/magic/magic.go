package magic

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blacktop/go-apfs/pkg/disk/dmg"
	"github.com/blacktop/go-apfs/pkg/disk/hfsplus"
	"github.com/blacktop/ipsw/pkg/bundle"
	"github.com/blacktop/ipsw/pkg/ftab"
	"github.com/blacktop/ipsw/pkg/img3"
	"github.com/blacktop/lzss"
)

type Magic uint32

const (
	Magic32    Magic = 0xfeedface
	Magic64    Magic = 0xfeedfacf
	MagicFatBE Magic = 0xcafebabe
	MagicFatLE Magic = 0xbebafeca
	MagicZip   Magic = 0x504b0304
	MagicYAA1  Magic = 0x31414159 // "YAA1"
	MagicAA01  Magic = 0x31304141 // "AA01"
	MagicAEA1  Magic = 0x41454131 // "AEA1"
	MagicPBZX        = 0x70627a78 // "pbzx"
)

func IsMachO(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	data := make([]byte, 4)
	if _, err := f.Read(data); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	return IsMachOData(data)
}

func IsMachOData(dat []byte) (bool, error) {
	var magic [4]byte
	if err := binary.Read(bytes.NewReader(dat), binary.LittleEndian, &magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	switch Magic(binary.LittleEndian.Uint32(magic[:])) {
	case Magic32, Magic64, MagicFatBE, MagicFatLE:
		return true, nil
	default:
		return false, nil
	}
}

func IsMachoOrImg4(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()

	var magic [4]byte
	if _, err = f.Read(magic[:]); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}

	switch Magic(binary.LittleEndian.Uint32(magic[:])) {
	case Magic32, Magic64, MagicFatBE, MagicFatLE:
		return true, nil
	default:
		f.Seek(0, io.SeekStart)
		if isIm4p, err := IsIm4p(filePath); isIm4p && err == nil {
			if strings.Contains(filePath, "kernelcache") {
				return false, fmt.Errorf("im4p file detected (run `ipsw kernel dec`)")
			}
			return false, fmt.Errorf("im4p file detected (run `ipsw img4 extract`)")
		}
		f.Seek(0, io.SeekStart)
		if isImg4, err := IsImg4(filePath); isImg4 && err == nil {
			if strings.Contains(filePath, "kernelcache") {
				return false, fmt.Errorf("img4 file detected (run `ipsw kernel dec --km`)")
			}
			return false, fmt.Errorf("img4 file detected")
		}
	}

	return false, fmt.Errorf("not a macho file")
}

type Asn1Header struct {
	Raw  asn1.RawContent
	Name string `asn1:"ia5"` // IM4P
}

func IsImg4(filePath string) (bool, error) {
	if filepath.Ext(filePath) == ".img4" {
		return true, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var hdr Asn1Header
	if _, err := asn1.Unmarshal(data, &hdr); err != nil {
		return false, fmt.Errorf("failed to ASN.1 parse header: %v", err)
	}

	if hdr.Name == "IMG4" {
		return true, nil
	}
	return false, nil
}

func IsIm4p(filePath string) (bool, error) {
	if filepath.Ext(filePath) == ".im4p" {
		return true, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var hdr Asn1Header
	if _, err := asn1.Unmarshal(data, &hdr); err != nil {
		return false, fmt.Errorf("failed to ASN.1 parse header: %v", err)
	}

	if hdr.Name == "IM4P" {
		return true, nil
	}
	return false, nil
}

func IsImg3(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	var hdr img3.Header
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return false, fmt.Errorf("failed to read bundle header: %w", err)
	}
	if string(hdr.Magic[:]) == img3.Magic {
		return true, nil
	}
	return false, nil
}

func IsBUND(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	var hdr bundle.Header
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return false, fmt.Errorf("failed to read bundle header: %w", err)
	}
	if string(hdr.Magic[:]) == bundle.Magic {
		return true, nil
	}
	slices.Reverse(hdr.Magic[:])

	if string(hdr.Magic[:]) == bundle.Magic {
		return true, nil
	}
	return false, nil
}

func IsZip(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	switch Magic(binary.BigEndian.Uint32(magic[:])) {
	case MagicZip:
		return true, nil
	default:
		return false, nil
	}
}
func IsZipData(r io.Reader) (bool, error) {
	magic := make([]byte, 4)
	if _, err := r.Read(magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	switch Magic(binary.BigEndian.Uint32(magic[:])) {
	case MagicZip:
		return true, nil
	default:
		return false, nil
	}
}

func IsDMG(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	var encHdr dmg.EncryptionHeader
	if err := binary.Read(f, binary.BigEndian, &encHdr); err != nil {
		return false, fmt.Errorf("failed to read DMG encryption header: %v", err)
	}
	if string(encHdr.Magic[:]) == dmg.EncryptedMagic {
		return true, nil
	}
	if _, err := f.Seek(int64(-binary.Size(dmg.UDIFResourceFile{})), io.SeekEnd); err != nil {
		return false, fmt.Errorf("failed to seek to DMG footer: %v", err)
	}
	var footer dmg.UDIFResourceFile
	if err := binary.Read(f, binary.BigEndian, &footer); err != nil {
		return false, fmt.Errorf("failed to read DMG footer: %v", err)
	}
	if footer.Signature.String() != "koly" {
		return false, nil
	}
	return true, nil
}

func IsEncryptedDMG(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	magic := make([]byte, 8)
	if _, err := f.Read(magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	if string(magic) == dmg.EncryptedMagic {
		return true, nil
	}
	return false, nil
}

func IsAPFS(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	if _, err := f.Seek(0x20, io.SeekStart); err != nil {
		return false, fmt.Errorf("failed to seek to APFS magic: %w", err)
	}
	magic := make([]byte, 4)
	if err := binary.Read(f, binary.BigEndian, &magic); err != nil {
		return false, fmt.Errorf("failed to read APFS magic: %w", err)
	}
	if string(magic) == "NXSB" {
		return true, nil
	}
	return false, nil
}

func IsHFSPlus(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	if _, err := f.Seek(1024, io.SeekStart); err != nil {
		return false, fmt.Errorf("failed to seek to HFS+ magic: %w", err)
	}
	var magic uint16
	if err := binary.Read(f, binary.BigEndian, &magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	if magic == uint16(hfsplus.HFSPlusSigWord) {
		return true, nil
	}
	return false, nil
}

func IsXar(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	if string(magic) == "xar!" {
		return true, nil
	}
	return false, nil
}

func IsPBZX(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	switch Magic(binary.BigEndian.Uint32(magic[:])) {
	case MagicPBZX:
		return true, nil
	default:
		return false, nil
	}
}

func IsPBZXData(r io.Reader) (bool, error) {
	magic := make([]byte, 4)
	if _, err := r.Read(magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	switch Magic(binary.BigEndian.Uint32(magic[:])) {
	case MagicPBZX:
		return true, nil
	default:
		return false, nil
	}
}

func IsFTAB(filename string) (bool, error) {
	f, err := os.Open(filename)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer f.Close()
	if _, err := f.Seek(32, io.SeekStart); err != nil {
		return false, fmt.Errorf("failed to seek to FTAB magic: %w", err)
	}
	var magic uint64
	if err := binary.Read(f, binary.LittleEndian, &magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	if magic == ftab.FtabMagic {
		return true, nil
	}
	return false, nil
}

func IsAA(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	switch Magic(binary.LittleEndian.Uint32(magic[:])) {
	case MagicYAA1, MagicAA01:
		return true, nil
	default:
		return false, nil
	}
}

func IsAEA(filePath string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer f.Close()
	magic := make([]byte, 4)
	if _, err := f.Read(magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	switch Magic(binary.BigEndian.Uint32(magic[:])) {
	case MagicAEA1:
		return true, nil
	default:
		return false, nil
	}
}

func IsAEAData(rc io.Reader) (bool, error) {
	magic := make([]byte, 4)
	if _, err := rc.Read(magic); err != nil {
		return false, fmt.Errorf("failed to read magic: %w", err)
	}
	switch Magic(binary.BigEndian.Uint32(magic[:])) {
	case MagicAEA1:
		return true, nil
	default:
		return false, nil
	}
}

func IsLZSS(data []byte) (bool, error) {
	if len(data) > 8 && string(data[:8]) == lzss.Magic {
		if len(data) < binary.Size(lzss.Header{}) {
			return true, fmt.Errorf("data too short to contain valid LZSS header")
		}
		return true, nil
	}
	return false, nil
}

func IsLZFSE(data []byte) (bool, error) {
	if len(data) > 4 &&
		(string(data[:4]) == "bvx2" ||
			string(data[:4]) == "bvxn" ||
			string(data[:4]) == "bvx1" ||
			string(data[:4]) == "bvx-") {
		return true, nil
	}
	return false, nil
}
