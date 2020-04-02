// +build linux,cgo darwin,cgo

package kernelcache

import (
	"archive/zip"
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/blacktop/go-macho"

	"github.com/apex/log"
	lzfse "github.com/blacktop/go-lzfse"
	"github.com/blacktop/go-plist"
	bkmcho "github.com/blacktop/ipsw/pkg/macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/lzss"
	"github.com/pkg/errors"
)

const (
	lzfseEncodeLSymbols       = 20
	lzfseEncodeMSymbols       = 20
	lzfseEncodeDSymbols       = 64
	lzfseEncodeLiteralSymbols = 256
	lzssPadding               = 0x16c
)

// Img4 Kernelcache object
type Img4 struct {
	IM4P    string
	Name    string
	Version string
	Data    []byte
}

// A LzssHeader represents the LZSS header
type LzssHeader struct {
	CompressionType  uint32 // 0x636f6d70 "comp"
	Signature        uint32 // 0x6c7a7373 "lzss"
	CheckSum         uint32 // Likely CRC32
	UncompressedSize uint32
	CompressedSize   uint32
	Padding          [lzssPadding]byte
}

// LzfseCompressedBlockHeaderV2 represents the lzfse header
type LzfseCompressedBlockHeaderV2 struct {
	Magic        uint32 // "bvx2"
	NumRawBytes  uint32
	PackedFields [3]uint64
	Freq         [2 * (lzfseEncodeLSymbols + lzfseEncodeMSymbols + lzfseEncodeDSymbols + lzfseEncodeLiteralSymbols)]uint8
}

// A CompressedCache represents an open compressed kernelcache file.
type CompressedCache struct {
	Magic  []byte
	Header interface{}
	Size   int
	Data   []byte
}

type PrelinkInfo struct {
	PrelinkInfoDictionary []CFBundle `plist:"_PrelinkInfoDictionary,omitempty"`
}

type CFBundle struct {
	Name                  string `plist:"CFBundleName,omitempty"`
	ID                    string `plist:"CFBundleIdentifier,omitempty"`
	InfoDictionaryVersion string `plist:"CFBundleInfoDictionaryVersion,omitempty"`
	CompatibleVersion     string `plist:"OSBundleCompatibleVersion,omitempty"`
	Version               string `plist:"CFBundleVersion,omitempty"`
	Required              string `plist:"OSBundleRequired,omitempty"`
	Executable            string `plist:"CFBundleExecutable,omitempty"`
	OSKernelResource      bool   `plist:"OSKernelResource,omitempty"`
	GetInfoString         string `plist:"CFBundleGetInfoString,omitempty"`
	AllowUserLoad         bool   `plist:"OSBundleAllowUserLoad,omitempty"`
	Signature             string `plist:"CFBundleSignature,omitempty"`
	PackageType           string `plist:"CFBundlePackageType,omitempty"`
	DevelopmentRegion     string `plist:"CFBundleDevelopmentRegion,omitempty"`
	ShortVersionString    string `plist:"CFBundleShortVersionString,omitempty"`
	ExecutableLoadAddr    uint64 `plist:"_PrelinkExecutableLoadAddr"`
}

func (pi *PrelinkInfo) ForeachBundle(visitor func(b * CFBundle) error) {
	for _, bundle := range pi.PrelinkInfoDictionary {
		bnd := bundle
		if visitor(&bnd) != nil {
			return
		}
	}
}

func (kc * KernelCache) KextWithName(name string) (*bkmcho.File, error) {
	plkDict, err := kc.PrelinkInfoDict()
	if err != nil {
		return nil, err
	}

	var textBase uint64
	plkDict.ForeachBundle(func(b * CFBundle) error {
		if b.ID == name {
			textBase = b.ExecutableLoadAddr
			return io.EOF
		}
		return nil
	})

	if textBase == 0 {
		return nil, fmt.Errorf("Couldn't find %s in LinkEdit Plist", name)
	}

	var kext *bkmcho.File
	kc.ForeachMachO(func(m * bkmcho.File, offset int64) error {
		textSegment, err := m.SegmentByName("__TEXT")
		if err != nil {
			return nil // continue
		}

		if textSegment.Addr != textBase {
			return nil // continue
		}

		kext = m
		return io.EOF
	})

	if kext == nil {
		return nil, fmt.Errorf("Couldn't find %s")
	}

	return kext, nil
}

type addressOffsetPair struct {
	address	uint64
	offset	uint64
}

type prelinkOffsets struct {
	prelinkText		addressOffsetPair
	prelinkTextExec		addressOffsetPair
	prelinkData		addressOffsetPair
	prelinkDataConst	addressOffsetPair
	prelinkLinkEdit		addressOffsetPair
	prelinkInfo		addressOffsetPair
}

func addressOffsetPairForSegment(seg * bkmcho.Segment) addressOffsetPair {
	return addressOffsetPair{
		address: seg.Addr,
		offset: seg.Offset,
	}
}

type KernelCache struct {
	r *os.File
	plkOffsets * prelinkOffsets
	plkDict * PrelinkInfo
}

func (k * KernelCache) Close() {
	k.r.Close()
}

func (k * KernelCache) Reader() *os.File {
	return k.r
}

func NewKernelCache(cache string) (*KernelCache, error) {
	kc := &KernelCache{}
	
	f, err := os.Open(cache)
	if err != nil {
		return nil, err
	}

	kc.r = f

	return kc, nil
}

func (kc * KernelCache) PrelinkOffsets() (*prelinkOffsets, error) {
	if kc.plkOffsets != nil {
		return kc.plkOffsets, nil
	}

	ra := io.NewSectionReader(kc.r, 0, 1<<63-1)
	kernelMachO, err := bkmcho.NewFile(ra)
	if err != nil {
		return nil, err
	}

	var offsets prelinkOffsets

	for _, seg := range kernelMachO.Segments() {
		var pair *addressOffsetPair

		switch seg.Name {
		case "__PRELINK_TEXT":
			pair = &offsets.prelinkText
		case "__PRELINK_INFO":
			pair = &offsets.prelinkInfo
		case "__PLK_TEXT_EXEC":
			pair = &offsets.prelinkTextExec
		case "__PRELINK_DATA":
			pair = &offsets.prelinkData
		case "__PLK_DATA_CONST":
			pair = &offsets.prelinkDataConst
		case "__PLK_LINKEDIT":
			pair = &offsets.prelinkLinkEdit
		}

		if nil != pair {
			*pair = addressOffsetPairForSegment(seg)
		}
	}

	kc.plkOffsets = &offsets

	return &offsets, nil
}

func (kc * KernelCache) PrelinkInfoDict() (*PrelinkInfo, error) {
	if kc.plkDict != nil {
		return kc.plkDict, nil
	}

	ra := io.NewSectionReader(kc.r, 0, 1<<63-1)
	kernelMachO, err := bkmcho.NewFile(ra)
	if err != nil {
		return nil, err
	}

	sect, err := kernelMachO.SectionByName("__PRELINK_INFO", "__info")
	if err != nil {
		return nil, err
	}

	f := sect.Open()

	data := make([]byte, sect.Size)
	_, err = f.Read(data)
	if err != nil {
		return nil, err
	}

	var prelink PrelinkInfo
	decoder := plist.NewDecoder(bytes.NewReader(bytes.Trim([]byte(data), "\x00")))
	err = decoder.Decode(&prelink)
	if err != nil {
		return nil, err
	}

	kc.plkDict = &prelink

	return &prelink, nil
}

// SlideOffset slides an offset from a segment of the given its name and address.  Slide must be added
// to each segment of a kext because without it, their offsets won't be accurate.
func (offsets * prelinkOffsets) SlideOffset(segname string, addr uint64) uint64 {
	pair := &addressOffsetPair{}

	switch segname {
	case "__TEXT":
		pair = &offsets.prelinkText
	case "__TEXT_EXEC":
		pair = &offsets.prelinkTextExec
	case "__DATA":
		pair = &offsets.prelinkData
	case "__DATA_CONST":
		pair = &offsets.prelinkDataConst
	}

	return pair.offset - pair.address + addr
}

func (kc * KernelCache) ForeachMachO(visitor func(*bkmcho.File, int64) error) error {
	for {
		var magic uint32
		err := binary.Read(kc.r, binary.LittleEndian, &magic)
		if err != nil {
			return err
		}

		if magic != 0xfeedfacf {
			continue
		}

		seek, err := kc.r.Seek(0, io.SeekCurrent)
		if err != nil {
			return err
		}

		r2 := io.NewSectionReader(kc.r, seek - 4, 1<<63-1)
		m, err := bkmcho.NewFile(r2)

		if _, err2 := kc.r.Seek(seek + 32, io.SeekStart); err2 != nil {
			return err2
		}

		if err == nil {
			err = visitor(m, seek - 4)
			if err != nil {
				return err
			}
		}
	}
}

// ParseImg4Data parses a img4 data containing a compressed kernelcache.
func ParseImg4Data(data []byte) (*CompressedCache, error) {
	utils.Indent(log.Info, 2)("Parsing Kernelcache IMG4")

	// NOTE: openssl asn1parse -i -inform DER -in kernelcache.iphone10 | less (to get offset)
	//       openssl asn1parse -i -inform DER -in kernelcache.iphone10 -strparse OFFSET -noout -out lzfse.bin
	var i Img4
	if _, err := asn1.Unmarshal(data, &i); err != nil {
		return nil, errors.Wrap(err, "failed to ASN.1 parse Kernelcache")
	}

	cc := CompressedCache{
		Magic: make([]byte, 4),
		Size:  len(i.Data),
		Data:  i.Data,
	}

	// Read file header magic.
	if err := binary.Read(bytes.NewBuffer(i.Data[:4]), binary.BigEndian, &cc.Magic); err != nil {
		return nil, err
	}

	return &cc, nil
}

// Extract extracts and decompresses a lernelcache from ipsw
func Extract(ipsw string) error {
	log.Info("Extracting Kernelcache from IPSW")
	kcaches, err := utils.Unzip(ipsw, "", func(f *zip.File) bool {
		if strings.Contains(f.Name, "kernelcache") {
			return true
		}
		return false
	})
	if err != nil {
		return errors.Wrap(err, "failed extract kernelcache from ipsw")
	}
	i, err := info.Parse(ipsw)
	if err != nil {
		return errors.Wrap(err, "failed to parse ipsw info")
	}
	for _, kcache := range kcaches {
		content, err := ioutil.ReadFile(kcache)
		if err != nil {
			return errors.Wrap(err, "failed to read Kernelcache")
		}

		kc, err := ParseImg4Data(content)
		if err != nil {
			return errors.Wrap(err, "failed parse compressed kernelcache")
		}

		dec, err := DecompressData(kc)
		if err != nil {
			return errors.Wrap(err, "failed to decompress kernelcache")
		}
		for _, folder := range i.GetKernelCacheFolders(kcache) {
			os.Mkdir(folder, os.ModePerm)
			fname := filepath.Join(folder, "kernelcache."+strings.ToLower(i.Plists.GetOSType()))
			err = ioutil.WriteFile(fname, dec, 0644)
			if err != nil {
				return errors.Wrap(err, "failed to decompress kernelcache")
			}
			utils.Indent(log.Info, 2)("Created " + fname)
			os.Remove(kcache)
		}
	}

	return nil
}

// Decompress decompresses a compressed kernelcache
func Decompress(kcache string) error {
	content, err := ioutil.ReadFile(kcache)
	if err != nil {
		return errors.Wrap(err, "failed to read Kernelcache")
	}

	kc, err := ParseImg4Data(content)
	if err != nil {
		return errors.Wrap(err, "failed parse compressed kernelcache")
	}
	// defer os.Remove(kcache)

	utils.Indent(log.Info, 2)("Decompressing Kernelcache")
	dec, err := DecompressData(kc)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}

	err = ioutil.WriteFile(kcache+".decompressed", dec, 0644)
	if err != nil {
		return errors.Wrap(err, "failed to decompress kernelcache")
	}
	utils.Indent(log.Info, 2)("Created " + kcache + ".decompressed")
	return nil
}

// DecompressData decompresses compressed kernelcache []byte data
func DecompressData(cc *CompressedCache) ([]byte, error) {
	utils.Indent(log.Info, 2)("Decompressing Kernelcache")

	if bytes.Contains(cc.Magic, []byte("bvx2")) { // LZFSE
		utils.Indent(log.Info, 2)("Kernelcache is LZFSE compressed")
		lzfseHeader := LzfseCompressedBlockHeaderV2{}
		// Read entire file header.
		if err := binary.Read(bytes.NewBuffer(cc.Data[:1000]), binary.BigEndian, &lzfseHeader); err != nil {
			return nil, err
		}
		cc.Header = lzfseHeader

		decData := lzfse.DecodeBuffer(cc.Data)

		fat, err := macho.NewFatFile(bytes.NewReader(decData))
		if errors.Is(err, macho.ErrNotFat) {
			return decData, nil
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to parse fat mach-o")
		}
		defer fat.Close()

		// Sanity check
		if len(fat.Arches) > 1 {
			return nil, errors.New("found more than 1 mach-o fat file")
		}

		// Essentially: lipo -thin arm64e
		return decData[fat.Arches[0].Offset:], nil

	} else if bytes.Contains(cc.Magic, []byte("comp")) { // LZSS
		utils.Indent(log.Debug, 1)("kernelcache is LZSS compressed")
		buffer := bytes.NewBuffer(cc.Data)
		lzssHeader := LzssHeader{}
		// Read entire file header.
		if err := binary.Read(buffer, binary.BigEndian, &lzssHeader); err != nil {
			return nil, err
		}

		msg := fmt.Sprintf("compressed size: %d, uncompressed: %d. checkSum: 0x%x",
			lzssHeader.CompressedSize,
			lzssHeader.UncompressedSize,
			lzssHeader.CheckSum,
		)
		utils.Indent(log.Debug, 1)(msg)

		cc.Header = lzssHeader

		if int(lzssHeader.CompressedSize) > cc.Size {
			return nil, fmt.Errorf("compressed_size: %d is greater than file_size: %d", cc.Size, lzssHeader.CompressedSize)
		}

		// Read compressed file data.
		cc.Data = buffer.Next(int(lzssHeader.CompressedSize))
		dec := lzss.Decompress(cc.Data)
		return dec[:lzssHeader.UncompressedSize], nil
	}

	return []byte{}, errors.New("unsupported compression")
}

// RemoteParse parses plist files in a remote ipsw file
func RemoteParse(zr *zip.Reader) error {

	ipsw, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return err
	}

	for _, f := range zr.File {
		if strings.Contains(f.Name, "kernelcache.") {
			for _, folder := range ipsw.GetKernelCacheFolders(f.Name) {
				fname := filepath.Join(folder, "kernelcache."+strings.ToLower(ipsw.Plists.GetOSType()))
				if _, err := os.Stat(fname); os.IsNotExist(err) {
					kdata := make([]byte, f.UncompressedSize64)
					rc, err := f.Open()
					if err != nil {
						return errors.Wrapf(err, "failed to open file in zip: %s", f.Name)
					}
					io.ReadFull(rc, kdata)
					rc.Close()

					kcomp, err := ParseImg4Data(kdata)
					if err != nil {
						return errors.Wrap(err, "failed parse compressed kernelcache")
					}

					dec, err := DecompressData(kcomp)
					if err != nil {
						return errors.Wrap(err, "failed to decompress kernelcache")
					}

					os.Mkdir(folder, os.ModePerm)
					err = ioutil.WriteFile(fname, dec, 0644)
					if err != nil {
						return errors.Wrap(err, "failed to decompress kernelcache")
					}
				} else {
					log.Warnf("kernelcache already exists: %s", fname)
				}
			}
		}
	}

	return nil
}
