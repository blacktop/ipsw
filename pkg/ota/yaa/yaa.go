package yaa

//go:generate go tool stringer -type=entryType,yopType -trimprefix=Patch_ -output yaa_string.go

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/bom"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/dustin/go-humanize"
)

const (
	MagicYAA1 = 0x31414159 // "YAA1"
	MagicAA01 = 0x31304141 // "AA01"
)

var (
	ErrInvalidMagic    = fmt.Errorf("invalid magic")
	ErrPostBomNotFound = fmt.Errorf("post.bom not found")
)

type entryType byte

const (
	BlockSpecial     entryType = 'B'
	CharacterSpecial entryType = 'C'
	Directory        entryType = 'D'
	RegularFile      entryType = 'F'
	SymbolicLink     entryType = 'L'
	Metadata         entryType = 'M'
	Fifo             entryType = 'P'
	Socket           entryType = 'S'
)

type yopType byte

const (
	YOP_COPY      yopType = 'C'
	YOP_EXTRACT   yopType = 'E'
	YOP_MANIFEST  yopType = 'M'
	YOP_PATCH     yopType = 'P'
	YOP_REMOVE    yopType = 'R'
	YOP_DST_FIXUP yopType = 'O' // fixup regular file metadata (add additional fields)
)

// Entry is a YAA entry type
type Entry struct {
	Type  entryType   // entry type
	Path  string      // entry path
	Link  string      // link path
	Uid   uint16      // user id
	Gid   uint16      // group id
	Mod   fs.FileMode // access mode
	Flag  uint32      // BSD flags
	Mtm   time.Time   // modification time
	Btm   time.Time   // backup time
	Ctm   time.Time   // creation time
	Size  uint64      // file data size
	Data  uint64      // file contents
	Index uint64      // entry index in input archive
	ESize uint64      // entry size in input archive
	Aft   uint32
	Afr   uint32
	Hlc   uint32
	Hlo   uint32
	Fli   uint32
	Yop   yopType // operation ?
	Yec   uint32  // file data error correcting codes
	Sh2   [32]byte
	Label string
	Xat   uint32 // extended attributes

	r          *io.ReadSeeker
	fileOffset int64
}

func (e *Entry) String() string {
	switch e.Type {
	case Metadata:
		switch e.Yop {
		case YOP_COPY:
			return fmt.Sprintf("[%s    ] %s: %s", e.Type, e.Yop, e.Path)
		case YOP_EXTRACT:
			return fmt.Sprintf("[%s    ] %s: '%s' size: %#x (%s), index: %#x (%s), in_size: %#x (%s)", e.Type, e.Yop, e.Label, e.Size, humanize.Bytes(uint64(e.Size)), e.Index, humanize.Bytes(uint64(e.Index)), e.ESize, humanize.Bytes(uint64(e.ESize)))
		case YOP_MANIFEST:
			return fmt.Sprintf("[%s    ] %s: size: %#x (%s)", e.Type, e.Yop, e.Size, humanize.Bytes(uint64(e.Size)))
		case YOP_PATCH:
			return fmt.Sprintf("[%s    ] %s: %s", e.Type, e.Yop, e.Path)
		case YOP_REMOVE:
			return fmt.Sprintf("[%s    ] %s: %s", e.Type, e.Yop, e.Path)
		case YOP_DST_FIXUP:
			return fmt.Sprintf("[%s    ] %s: '%s' size: %#x (%s), index: %#x, in_size: %#x (%s)", e.Type, e.Yop, e.Label, e.Size, humanize.Bytes(uint64(e.Size)), e.Index, e.ESize, humanize.Bytes(uint64(e.ESize)))
		default:
			return fmt.Sprintf("[%s    ] YOP_UNK: '%c'", e.Type, e.Yop)
		}
	case Directory:
		if e.Path == "" {
			e.Path = "."
		}
		return fmt.Sprintf("[%s   ] %s uid: %d gid: %d flag: %d '%s'",
			e.Type,
			unixModeToFileMode(uint32(e.Mod)),
			e.Uid,
			e.Gid,
			e.Flag,
			e.Path)
	case RegularFile:
		var sh2 string
		if e.Sh2 != [32]byte{} {
			sh2 = fmt.Sprintf(" sha256: %s", hex.EncodeToString(e.Sh2[:]))
		}
		return fmt.Sprintf("[%s ] %s uid: %d gid: %d flag: %d size: %s hlc: %d hlo: %d aft: %d afr: %d%s '%s'",
			e.Type,
			unixModeToFileMode(uint32(e.Mod)),
			e.Uid,
			e.Gid,
			e.Flag,
			humanize.Bytes(uint64(e.Size)),
			e.Hlc,
			e.Hlo,
			e.Aft,
			e.Afr,
			sh2,
			e.Path)
	case SymbolicLink:
		return fmt.Sprintf("[%s] %s uid: %d gid: %d flag: %d '%s' -> '%s'",
			e.Type,
			unixModeToFileMode(uint32(e.Mod)),
			e.Uid,
			e.Gid,
			e.Flag,
			e.Path,
			e.Link)
	default:
		return fmt.Sprintf("%s: %s", e.Type, e.Path)
	}
}

func (e *Entry) IsDir() bool {
	return e.Type == Directory
}

func (e *Entry) Read(out []byte) (int, error) {
	if e.r == nil {
		return 0, fmt.Errorf("yaa entry reader is nil")
	}
	if _, err := (*e.r).Seek(e.fileOffset, io.SeekStart); err != nil {
		return 0, fmt.Errorf("failed to seek to file offset: %w", err)
	}
	if uint64(len(out)) > e.Size {
		out = out[:e.Size]
	}
	return (*e.r).Read(out)
}

func DecodeEntry(r *bytes.Reader) (*Entry, error) {
	entry := &Entry{}
	field := make([]byte, 4)

	for {
		// Read Archive field
		err := binary.Read(r, binary.BigEndian, &field)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read YAA header field: %w", err)
		}

		switch string(field[:3]) {
		case "TYP": // entry type (always included)
			switch field[3] {
			case '1':
				var etype byte
				if etype, err = r.ReadByte(); err != nil {
					return nil, fmt.Errorf("failed to read TYP1 field: %w", err)
				}
				entry.Type = entryType(etype)
			default:
				return nil, fmt.Errorf("found unknown TYP field: %s", string(field))
			}
		case "PAT": // entry path (always included for filesystem objects)
			switch field[3] {
			case 'P':
				var pathLength uint16
				if err := binary.Read(r, binary.LittleEndian, &pathLength); err != nil {
					return nil, fmt.Errorf("failed to read PATP field: %w", err)
				}
				path := make([]byte, int(pathLength))
				if err := binary.Read(r, binary.LittleEndian, &path); err != nil {
					return nil, fmt.Errorf("failed to read PATP path: %w", err)
				}
				entry.Path = string(path)
			default:
				return nil, fmt.Errorf("found unknown PAT field: %s", string(field))
			}
		case "LNK": // link path (always included for symbolic links)
			switch field[3] {
			case 'P':
				var pathLength uint16
				if err := binary.Read(r, binary.LittleEndian, &pathLength); err != nil {
					return nil, fmt.Errorf("failed to read LNKP field: %w", err)
				}
				path := make([]byte, int(pathLength))
				if err := binary.Read(r, binary.LittleEndian, &path); err != nil {
					return nil, fmt.Errorf("failed to read LNKP path: %w", err)
				}
				entry.Link = string(path)
			default:
				return nil, fmt.Errorf("found unknown LNK field: %s", string(field))
			}
		case "DEV": // device id (always included for block/character devices)
			return nil, fmt.Errorf("found unsupported DEV field: %s", string(field))
		case "UID": // user id
			switch field[3] {
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read UID1 field: %w", err)
				}
				entry.Uid = uint16(dat)
			case '2':
				if err := binary.Read(r, binary.LittleEndian, &entry.Uid); err != nil {
					return nil, fmt.Errorf("failed to read UID2 field: %w", err)
				}
			default:
				return nil, fmt.Errorf("found unknown UID field: %s", string(field))
			}
		case "GID": // group id
			switch field[3] {
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read GID1 field: %w", err)
				}
				entry.Gid = uint16(dat)
			case '2':
				if err := binary.Read(r, binary.LittleEndian, &entry.Gid); err != nil {
					return nil, fmt.Errorf("failed to read GID2 field: %w", err)
				}
			default:
				return nil, fmt.Errorf("found unknown UID field: %s", string(field))
			}
		case "MOD": // access mode
			switch field[3] {
			case '2':
				var mod uint16
				if err := binary.Read(r, binary.LittleEndian, &mod); err != nil {
					return nil, fmt.Errorf("failed to read MOD2 field: %w", err)
				}
				entry.Mod = fs.FileMode(mod)
			default:
				return nil, fmt.Errorf("found unknown MOD field: %s", string(field))
			}
		case "FLG": // BSD flags
			switch field[3] {
			case '1':
				flag, err := r.ReadByte()
				if err != nil {
					return nil, fmt.Errorf("failed to read FLG1 field: %w", err)
				}
				entry.Flag = uint32(flag)
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Flag); err != nil {
					return nil, fmt.Errorf("failed to read FLG4 field: %w", err)
				}
			default:
				return nil, fmt.Errorf("found unknown FLG field: %s", string(field))
			}
		case "MTM": // modification time
			switch field[3] {
			case 'T':
				var secs int64
				var nsecs int32
				if err := binary.Read(r, binary.LittleEndian, &secs); err != nil {
					return nil, fmt.Errorf("failed to read MTMT field: %w", err)
				}
				if err := binary.Read(r, binary.LittleEndian, &nsecs); err != nil {
					return nil, fmt.Errorf("failed to read MTMT nsecs: %w", err)
				}
				entry.Mtm = time.Unix(secs, int64(nsecs))
			case 'S':
				var secs int64
				if err := binary.Read(r, binary.LittleEndian, &secs); err != nil {
					return nil, fmt.Errorf("failed to read MTMS field: %w", err)
				}
				entry.Mtm = time.Unix(secs, 0)
			default:
				return nil, fmt.Errorf("found unknown MTM field: %s", string(field))
			}
		case "BTM": // backup time
			switch field[3] {
			case 'T':
				var secs int64
				var nsecs int32
				if err := binary.Read(r, binary.LittleEndian, &secs); err != nil {
					return nil, fmt.Errorf("failed to read BTMT field: %w", err)
				}
				if err := binary.Read(r, binary.LittleEndian, &nsecs); err != nil {
					return nil, fmt.Errorf("failed to read BTMT nsecs: %w", err)
				}
				entry.Btm = time.Unix(secs, int64(nsecs))
			case 'S':
				var secs int64
				if err := binary.Read(r, binary.LittleEndian, &secs); err != nil {
					return nil, fmt.Errorf("failed to read BTMS field: %w", err)
				}
				entry.Btm = time.Unix(secs, 0)
			default:
				return nil, fmt.Errorf("found unknown BTM field: %s", string(field))
			}
		case "CTM": // creation time
			switch field[3] {
			case 'T':
				var secs int64
				var nsecs int32
				if err := binary.Read(r, binary.LittleEndian, &secs); err != nil {
					return nil, fmt.Errorf("failed to read CTMT field: %w", err)
				}
				if err := binary.Read(r, binary.LittleEndian, &nsecs); err != nil {
					return nil, fmt.Errorf("failed to read CTMT nsecs: %w", err)
				}
				entry.Ctm = time.Unix(secs, int64(nsecs))
			case 'S':
				var secs int64
				if err := binary.Read(r, binary.LittleEndian, &secs); err != nil {
					return nil, fmt.Errorf("failed to read CTMS field: %w", err)
				}
				entry.Ctm = time.Unix(secs, 0)
			default:
				return nil, fmt.Errorf("found unknown CTM field: %s", string(field))
			}
		case "DAT": // file contents
			switch field[3] {
			case 'C':
				var dat uint64
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read DATC field: %w", err)
				}
				entry.Size = dat
			case 'B':
				var dat uint32
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read DATB field: %w", err)
				}
				entry.Size = uint64(dat)
			case 'A':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read DATA field: %w", err)
				}
				entry.Size = uint64(dat)
			default:
				return nil, fmt.Errorf("found unknown DAT field: %s", string(field))
			}
		case "XAT": // extended attributes
			switch field[3] {
			case 'B':
				if err := binary.Read(r, binary.LittleEndian, &entry.Xat); err != nil {
					return nil, fmt.Errorf("failed to read XATB field: %w", err)
				}
			case 'A':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read XATA field: %w", err)
				}
				entry.Xat = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown XAT field: %s", string(field))
			}
		case "IDX": // entry index in input archive
			switch field[3] {
			case '8':
				if err := binary.Read(r, binary.LittleEndian, &entry.ESize); err != nil {
					return nil, fmt.Errorf("failed to read IDX8 field: %w", err)
				}
			case '4':
				var dat uint32
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read IDX4 field: %w", err)
				}
				entry.Index = uint64(dat)
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read IDX2 field: %w", err)
				}
				entry.Index = uint64(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read IDX1 field: %w", err)
				}
				entry.Index = uint64(dat)
			default:
				return nil, fmt.Errorf("found unknown IDX field: %s", string(field))
			}
		case "IDZ": // entry size in input archive
			switch field[3] {
			case '8':
				if err := binary.Read(r, binary.LittleEndian, &entry.ESize); err != nil {
					return nil, fmt.Errorf("failed to read IDZ8 field: %w", err)
				}
			case '4':
				var dat uint32
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read IDZ4 field: %w", err)
				}
				entry.ESize = uint64(dat)
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read IDZ2 field: %w", err)
				}
				entry.ESize = uint64(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read IDZ1 field: %w", err)
				}
				entry.ESize = uint64(dat)
			default:
				return nil, fmt.Errorf("found unknown IDZ field: %s", string(field))
			}
		case "SIZ": // file data size
			switch field[3] {
			case '8':
				var dat uint64
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read SIZ8 field: %w", err)
				}
				entry.Size = dat
			case '4':
				var dat uint32
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read SIZ4 field: %w", err)
				}
				entry.Size = uint64(dat)
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read SIZ2 field: %w", err)
				}
				entry.Size = uint64(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read SIZ1 field: %w", err)
				}
				entry.Size = uint64(dat)
			default:
				return nil, fmt.Errorf("found unknown SIZ field: %s", string(field))
			}
		case "AFR":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Afr); err != nil {
					return nil, fmt.Errorf("failed to read AFR4 field: %w", err)
				}
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read AFR2 field: %w", err)
				}
				entry.Afr = uint32(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read AFR1 field: %w", err)
				}
				entry.Afr = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown AFR field: %s", string(field))
			}
		case "AFT":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Aft); err != nil {
					return nil, fmt.Errorf("failed to read AFT4 field: %w", err)
				}
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read AFT2 field: %w", err)
				}
				entry.Aft = uint32(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read AFT1 field: %w", err)
				}
				entry.Aft = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown AFR field: %s", string(field))
			}
		case "HLC":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Hlc); err != nil {
					return nil, fmt.Errorf("failed to read HLC4 field: %w", err)
				}
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read HLC2 field: %w", err)
				}
				entry.Hlc = uint32(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read HLC1 field: %w", err)
				}
				entry.Hlc = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown AFR field: %s", string(field))
			}
		case "HLO":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Hlo); err != nil {
					return nil, fmt.Errorf("failed to read HLO4 field: %w", err)
				}
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read HLO2 field: %w", err)
				}
				entry.Hlo = uint32(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read HLO1 field: %w", err)
				}
				entry.Hlo = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown AFR field: %s", string(field))
			}
		case "FLI":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Fli); err != nil {
					return nil, fmt.Errorf("failed to read FLI4 field: %w", err)
				}
			default:
				return nil, fmt.Errorf("found unknown FLI field: %s", string(field))
			}
		case "YOP": // patch
			switch field[3] {
			case '1':
				var ptype byte
				if ptype, err = r.ReadByte(); err != nil {
					return nil, fmt.Errorf("failed to read YOP1 field: %w", err)
				}
				entry.Yop = yopType(ptype)
			default:
				return nil, fmt.Errorf("found unknown YOP field: %s", string(field))
			}
		case "YEC": // file data error correcting codes size
			switch field[3] {
			case 'B':
				if err := binary.Read(r, binary.LittleEndian, &entry.Yec); err != nil {
					return nil, fmt.Errorf("failed to read YECB field: %w", err)
				}
			case 'A':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read YECA field: %w", err)
				}
				entry.Yec = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown YEC field: %s", string(field))
			}
		case "SH2": // SHA2-256 digest
			switch field[3] {
			case 'H':
				if err := binary.Read(r, binary.LittleEndian, &entry.Sh2); err != nil {
					return nil, fmt.Errorf("failed to read SH2H field: %w", err)
				}
			default:
				return nil, fmt.Errorf("found unknown SH2 field: %s", string(field))
			}
		case "LBL": // label
			switch field[3] {
			case 'P':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, fmt.Errorf("failed to read LBLP field: %w", err)
				}
				label := make([]byte, dat)
				if err := binary.Read(r, binary.LittleEndian, &label); err != nil {
					return nil, fmt.Errorf("failed to read LBLP label: %w", err)
				}
				entry.Label = string(label)
			default:
				return nil, fmt.Errorf("found unknown LBL field: %s", string(field))
			}
		default:
			return nil, fmt.Errorf("found unknown YAA header field: %s", string(field))
		}
	}

	return entry, nil
}

type YAA struct {
	Entries []*Entry
	sr      io.ReadSeeker
	seen    map[string]int // track seen entries across recursive calls
}

func (y *YAA) ReadAt(p []byte, off int64) (n int, err error) {
	y.sr.Seek(off, io.SeekStart)
	return y.sr.Read(p)
}

func (y *YAA) PostBOM() ([]fs.FileInfo, error) {
	for _, ent := range y.Entries {
		if strings.EqualFold(filepath.Base(ent.Path), "post.bom") && ent.Size > 0 {
			bdata := make([]byte, ent.Size)
			if _, err := ent.Read(bdata); err != nil {
				return nil, fmt.Errorf("init: failed to read BOM data: %v", err)
			}
			bom, err := bom.New(bytes.NewReader(bdata))
			if err != nil {
				return nil, fmt.Errorf("init: failed to parse BOM: %v", err)
			}
			return bom.GetPaths()
		}
	}
	return nil, ErrPostBomNotFound
}

func (y *YAA) FileSize() uint64 {
	var total uint64
	for _, ent := range y.Entries {
		if ent.Type == RegularFile {
			total += ent.Size
		}
	}
	return total
}

func (y *YAA) Parse(r io.ReadSeeker) error {
	if y.sr == nil {
		y.sr = r
	}
	if y.seen == nil {
		y.seen = make(map[string]int)
	}

	var magic uint32
	var headerSize uint16

	for {
		var ent *Entry
		err := binary.Read(r, binary.LittleEndian, &magic)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("YAA.Parse: failed to read magic: %w", err)
		}

		if magic != MagicYAA1 && magic != MagicAA01 {
			return ErrInvalidMagic
		}
		if err := binary.Read(r, binary.LittleEndian, &headerSize); err != nil {
			return fmt.Errorf("YAA.Parse: failed to read header size: %w", err)
		}
		if headerSize <= 5 {
			return fmt.Errorf("YAA.Parse: invalid header size: %d", headerSize)
		}

		header := make([]byte, headerSize-uint16(binary.Size(magic))-uint16(binary.Size(headerSize)))
		if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
			return fmt.Errorf("YAA.Parse: failed to read header: %w", err)
		}

		ent, err = DecodeEntry(bytes.NewReader(header))
		if err != nil {
			return fmt.Errorf("YAA.Parse: failed to decode AA entry: %v", err)
		}
		log.Debug(ent.String())

		if ent.Type == Metadata {
			ent.fileOffset, _ = r.Seek(0, io.SeekCurrent)
			ent.r = &r
			switch ent.Yop {
			case YOP_MANIFEST:
				if _, err := r.Seek(int64(ent.Size), io.SeekCurrent); err != nil {
					return fmt.Errorf("YAA.Parse: failed to seek to next entry: %w", err)
				}
			case YOP_EXTRACT, YOP_DST_FIXUP:
				data := make([]byte, ent.Size)
				if _, err := io.ReadFull(r, data); err != nil {
					return fmt.Errorf("YAA.Parse: failed to read aa pbzx patch data: %w", err)
				}
				var pbuf bytes.Buffer
				if err := pbzx.Extract(context.Background(), bytes.NewReader(data), &pbuf, runtime.NumCPU()); err != nil {
					return fmt.Errorf("YAA.Parse: failed to extract aa pbzx patch data: %w", err)
				}

				if err := y.Parse(bytes.NewReader(pbuf.Bytes())); err != nil {
					return fmt.Errorf("YAA.Parse: failed to parse aa patch: %w", err)
				}
			default:
				log.Warnf("YAA.Parse: unsupported YOP operation: %s (let author know)", ent.Yop)
			}
		}

		if ent.Type == RegularFile {
			ent.fileOffset, _ = r.Seek(0, io.SeekCurrent)
			ent.r = &r
			// skip file data
			if _, err := r.Seek(int64(ent.Size), io.SeekCurrent); err != nil {
				return fmt.Errorf("YAA.Parse: failed to seek to next entry: %w", err)
			}
			if ent.Yec > 0 {
				// skip ECC data
				if _, err := r.Seek(int64(ent.Yec), io.SeekCurrent); err != nil {
					return fmt.Errorf("YAA.Parse: failed to seek to next entry: %w", err)
				}
			}
		}

		if ent.Xat > 0 {
			// skip extended attributes
			if _, err := r.Seek(int64(ent.Xat), io.SeekCurrent); err != nil {
				return fmt.Errorf("YAA.Parse: failed to seek to next entry: %w", err)
			}
		}

		if idx, ok := y.seen[ent.Path]; ok {
			y.Entries[idx-1].Uid = ent.Uid
			y.Entries[idx-1].Gid = ent.Gid
			y.Entries[idx-1].Mod = ent.Mod
			y.Entries[idx-1].Flag = ent.Flag
			y.Entries[idx-1].Mtm = ent.Mtm
			y.Entries[idx-1].Btm = ent.Btm
			y.Entries[idx-1].Ctm = ent.Ctm
			copy(y.Entries[idx-1].Sh2[:], ent.Sh2[:])
		} else {
			y.Entries = append(y.Entries, ent)
			// add to seen
			if len(ent.Path) > 0 {
				y.seen[ent.Path] = len(y.Entries)
			}
		}
	}

	return nil
}

const (
	// Unix constants. The specification doesn't mention them,
	// but these seem to be the values agreed on by tools.
	s_IFMT   = 0xf000
	s_IFSOCK = 0xc000
	s_IFLNK  = 0xa000
	s_IFREG  = 0x8000
	s_IFBLK  = 0x6000
	s_IFDIR  = 0x4000
	s_IFCHR  = 0x2000
	s_IFIFO  = 0x1000
	s_ISUID  = 0x800
	s_ISGID  = 0x400
	s_ISVTX  = 0x200

	msdosDir      = 0x10
	msdosReadOnly = 0x01
)

func unixModeToFileMode(m uint32) fs.FileMode {
	mode := fs.FileMode(m & 0777)
	switch m & s_IFMT {
	case s_IFBLK:
		mode |= fs.ModeDevice
	case s_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case s_IFDIR:
		mode |= fs.ModeDir
	case s_IFIFO:
		mode |= fs.ModeNamedPipe
	case s_IFLNK:
		mode |= fs.ModeSymlink
	case s_IFREG:
		// nothing to do
	case s_IFSOCK:
		mode |= fs.ModeSocket
	}
	if m&s_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if m&s_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if m&s_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}
