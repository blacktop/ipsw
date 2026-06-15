package iboot

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/disass"
	"github.com/blacktop/lzfse-cgo"
)

const MinStringLength = 2

const (
	legacyCopyrightOffset  = int64(0x200)
	releaseOffsetDelta     = int64(0x40)
	versionOffsetDelta     = int64(0x80)
	baseAddressOffsetDelta = int64(0x100)
)

var (
	lzfseStart       = []byte{0x62, 0x76, 0x78, 0x32} // bvx2
	lzfseEnd         = []byte{0x62, 0x76, 0x78, 0x24} // bvx$
	metadataPrefixes = []string{"iBoot", "SecureROM", "AVPBooter"}
	prologs          = [][]byte{
		{0x7F, 0x23, 0x03, 0xD5}, // PACIBSP
		{0xBD, 0xA9},             //
		{0xBF, 0xA9},             //
	}
)

type metadata struct {
	offset    int64
	copyright string
	release   string
	version   string
}

type IBoot struct {
	Version     string
	Release     string
	Copyright   string
	BaseAddress uint64
	Strings     map[string]map[int64]string
	Files       map[string][]byte
}

func (i *IBoot) String() string {
	return fmt.Sprintf("%s %s (%s)", i.Version, i.Release, i.Copyright)
}

func Parse(data []byte) (*IBoot, error) {
	iboot := &IBoot{
		Strings: make(map[string]map[int64]string),
	}
	// check for compressed data
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short to be iboot")
	}
	// check for lzfse
	if bytes.Equal(data[:4], lzfseStart) {
		data = lzfse.DecodeBuffer(data)
	}
	r := bytes.NewReader(data)

	meta, err := findMetadata(data)
	if err != nil {
		return nil, err
	}
	iboot.Copyright = meta.copyright
	iboot.Release = meta.release
	iboot.Version = meta.version

	baseAddressOffset := meta.offset + baseAddressOffsetDelta
	if _, err := r.Seek(baseAddressOffset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to base address: %v", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &iboot.BaseAddress); err != nil {
		return nil, fmt.Errorf("failed to read base address: %v", err)
	}
	if iboot.BaseAddress == 0 {
		baseAddress, err := getBaseAddress(r)
		if err != nil {
			log.WithError(err).Debug("failed to get iBoot base address")
		} else {
			iboot.BaseAddress = baseAddress
		}
	}

	// extract strings
	if idx := bytes.Index(data, []byte("darwinos-ramdisk")); idx > 0 {
		if _, err := r.Seek(int64(idx), io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek to darwinos-ramdisk: %v", err)
		}
	}
	strs, err := dumpStrings(r, MinStringLength)
	if err != nil {
		return nil, fmt.Errorf("failed to dump strings: %v", err)
	}
	iboot.Strings["iboot"] = strs

	// extract files
	iboot.Files = make(map[string][]byte)
	found := 0
	var name string

	for {
		start := bytes.Index(data, lzfseStart)
		if start < 0 {
			break
		}
		// The end marker must follow the start marker: search from start so a
		// stray "bvx$" earlier in the buffer can't yield end < start (which
		// would panic slicing data[start:end+4]).
		rel := bytes.Index(data[start:], lzfseEnd)
		if rel < 0 {
			break
		}
		end := start + rel

		decomp := lzfse.DecodeBuffer(data[start : end+len(lzfseEnd)])

		strs, err := dumpStrings(bytes.NewReader(decomp), MinStringLength)
		if err != nil {
			return nil, fmt.Errorf("failed to dump strings: %v", err)
		}
		// check for known files
		name = fmt.Sprintf("iboot_blob%02d.bin", found)
		if idx := bytes.Index(decomp, []byte("AppleSMCFirmware")); idx > 0 {
			name = "AppleSMCFirmware.bin"
		}
		if idx := bytes.Index(decomp, []byte("AppleStorageProcessorANS2")); idx > 0 {
			name = "AppleStorageProcessorANS2.bin"
		}
		if idx := bytes.Index(decomp, []byte("RTKit")); idx > 0 {
			name = "RTKit.bin"
		}

		iboot.Files[name] = decomp
		iboot.Strings[name] = strs

		found++
		data = data[end+len(lzfseEnd):]
	}

	return iboot, nil
}

func findMetadata(data []byte) (*metadata, error) {
	if meta, ok := readMetadataAt(data, legacyCopyrightOffset, false); ok {
		return meta, nil
	}

	for _, prefix := range metadataPrefixes {
		searchFrom := 0
		for searchFrom < len(data) {
			idx := bytes.Index(data[searchFrom:], []byte(prefix))
			if idx < 0 {
				break
			}
			offset := searchFrom + idx
			if meta, ok := readMetadataAt(data, int64(offset), true); ok {
				return meta, nil
			}
			searchFrom = offset + len(prefix)
		}
	}

	return nil, fmt.Errorf("iBoot potentially encrypted")
}

func readMetadataAt(data []byte, offset int64, requireCompleteMetadata bool) (*metadata, bool) {
	copyright, err := readCStringAt(data, offset)
	if err != nil || !isIBootMetadataString(copyright, requireCompleteMetadata) {
		return nil, false
	}
	release, err := readCStringAt(data, offset+releaseOffsetDelta)
	if err != nil || (requireCompleteMetadata && release == "") {
		return nil, false
	}
	version, err := readCStringAt(data, offset+versionOffsetDelta)
	if err != nil || (requireCompleteMetadata && version == "") {
		return nil, false
	}

	return &metadata{
		offset:    offset,
		copyright: copyright,
		release:   release,
		version:   version,
	}, true
}

func readCStringAt(data []byte, offset int64) (string, error) {
	if offset < 0 || offset >= int64(len(data)) {
		return "", fmt.Errorf("offset %#x is outside data", offset)
	}
	return utils.ReadCString(bytes.NewReader(data[offset:]))
}

func isIBootMetadataString(s string, requireCompleteMetadata bool) bool {
	if !hasKnownMetadataPrefix(s) {
		return false
	}
	return !requireCompleteMetadata || strings.Contains(s, "Copyright") || strings.Contains(s, "Apple")
}

func hasKnownMetadataPrefix(s string) bool {
	for _, prefix := range metadataPrefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func getBaseAddress(r *bytes.Reader) (uint64, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("failed to seek to base address: %v", err)
	}

	var startAddr uint64 = 0
	var instrValue uint32
	var decoder disassemble.Decoder

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, fmt.Errorf("failed to read instruction @ %#x: %v", startAddr, err)
		}

		var instruction disassemble.Inst
		if err := decoder.DecomposeInto(startAddr, instrValue, &instruction); err != nil {
			return 0, fmt.Errorf("failed to decompose instruction @ %#x: %v", startAddr, err)
		}

		if disass.IsLoadLiteral(&instruction) {
			if _, err := r.Seek(int64(instruction.Operands[1].Immediate), io.SeekStart); err != nil {
				return 0, fmt.Errorf("failed to seek to base address: %v", err)
			}
			var baseAddr uint64
			if err := binary.Read(r, binary.LittleEndian, &baseAddr); err != nil {
				return 0, fmt.Errorf("failed to read base address: %v", err)
			}
			return baseAddr, nil
		}

		// fmt.Printf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instruction)

		startAddr += uint64(binary.Size(uint32(0)))
	}

	return 0, fmt.Errorf("failed to find base address")
}

func dumpStrings(r *bytes.Reader, minLen int) (map[int64]string, error) {
	originalOffset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, fmt.Errorf("failed to get current offset: %w", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	strs := make(map[int64]string)
	var currentString strings.Builder
	startOffset := int64(-1)

	for byteOffset := 0; byteOffset < len(data); {
		runeValue, runeSize := utf8.DecodeRune(data[byteOffset:])

		// Check if the rune is valid and is a Latin letter, a digit, common ASCII punctuation/space, or a Symbol
		isAllowed := unicode.Is(unicode.Latin, runeValue) || unicode.IsDigit(runeValue) || isAsciiPunctOrSpace(runeValue) || unicode.IsSymbol(runeValue)

		if runeValue != utf8.RuneError && isAllowed {
			if startOffset == -1 {
				// Mark start when the first printable rune is found
				startOffset = originalOffset + int64(byteOffset)
			}
			currentString.WriteRune(runeValue)
		} else {
			// Invalid rune or non-allowed rune encountered
			if startOffset != -1 { // Check if we were building a string
				s := currentString.String()
				// Check rune count against minLen and exclude specific patterns
				if utf8.RuneCountInString(s) >= minLen && !strings.Contains(s, "bvx$bvx2") && !strings.Contains(s, "`") {
					strs[startOffset] = s
				}
				currentString.Reset()
				startOffset = -1
			}
		}
		byteOffset += runeSize
	}

	// Handle case where the data ends with a printable string
	if startOffset != -1 {
		s := currentString.String()
		if utf8.RuneCountInString(s) >= minLen && !strings.Contains(s, "bvx$bvx2") && !strings.Contains(s, "`") {
			strs[startOffset] = s
		}
	}

	return strs, nil
}

// isAsciiPunctOrSpace checks if a rune is common ASCII punctuation or a space.
func isAsciiPunctOrSpace(r rune) bool {
	switch r {
	case ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
		':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~':
		return true
	default:
		return false
	}
}
