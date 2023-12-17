package magic

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/blacktop/ipsw/pkg/img4"
)

type Magic uint32

const (
	Magic32    Magic = 0xfeedface
	Magic64    Magic = 0xfeedfacf
	MagicFatBE Magic = 0xcafebabe
	MagicFatLE Magic = 0xbebafeca
)

func IsMachO(filePath string) (bool, error) {
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
		return false, fmt.Errorf("not a macho file")
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
		if _, err := img4.ParseIm4p(f); err == nil {
			if strings.Contains(filePath, "kernelcache") {
				return false, fmt.Errorf("im4p file detected (run `ipsw kernel dec`)")
			}
			return false, fmt.Errorf("im4p file detected (run `ipsw img4 extract`)")
		}
		f.Seek(0, io.SeekStart)
		if _, err := img4.ParseImg4(f); err == nil {
			if strings.Contains(filePath, "kernelcache") {
				return false, fmt.Errorf("img4 file detected (run `ipsw kernel dec --km`)")
			}
			return false, fmt.Errorf("img4 file detected")
		}
	}

	return false, fmt.Errorf("not a macho file")
}
