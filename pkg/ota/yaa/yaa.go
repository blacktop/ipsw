package yaa

//go:generate stringer -type=entryType,patchType -trimprefix=Patch_ -output yaa_string.go

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/dustin/go-humanize"
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

type patchType byte

const (
	Patch_C        patchType = 'C'
	Patch_Entry    patchType = 'E'
	Patch_Metadata patchType = 'M'
	Patch_P        patchType = 'P'
	Patch_R        patchType = 'R'
	Patch_O        patchType = 'O'
)

// Entry is a YAA entry type
type Entry struct {
	Type      entryType   // entry type
	Path      string      // entry path
	Link      string      // link path
	Uid       uint16      // user id
	Gid       uint16      // group id
	Mod       fs.FileMode // access mode
	Flag      uint32      // BSD flags
	Mtm       time.Time   // modification time
	Btm       time.Time   // backup time
	Ctm       time.Time   // creation time
	Size      uint32      // file data size
	Index     uint64      // entry index in input archive
	ESize     uint64      // entry size in input archive
	Aft       uint32
	Afr       uint32
	Hlc       uint32
	Hlo       uint32
	Fli       uint32
	PatchType patchType
	Label     string
}

func (e *Entry) String() string {
	switch e.Type {
	case Metadata:
		switch e.PatchType {
		case Patch_C:
			return fmt.Sprintf("[%s    ] %s: %s", e.Type, e.PatchType, e.Path)
		case Patch_Entry:
			return fmt.Sprintf("[%s    ] %s: '%s' size: %#x (%s), index: %#x, in_size: %#x (%s)", e.Type, e.PatchType, e.Label, e.Size, humanize.Bytes(uint64(e.Size)), e.Index, e.ESize, humanize.Bytes(uint64(e.ESize)))
		case Patch_Metadata:
			return fmt.Sprintf("[%s    ] %s: size: %d", e.Type, e.PatchType, e.Size)
		case Patch_P:
			return fmt.Sprintf("[%s    ] %s: %s", e.Type, e.PatchType, e.Path)
		case Patch_R:
			return fmt.Sprintf("[%s    ] %s: %s", e.Type, e.PatchType, e.Path)
		case Patch_O:
			return fmt.Sprintf("[%s    ] %s: '%s' size: %#x (%s), index: %#x, in_size: %#x (%s)", e.Type, e.PatchType, e.Label, e.Size, humanize.Bytes(uint64(e.Size)), e.Index, e.ESize, humanize.Bytes(uint64(e.ESize)))
		default:
			return fmt.Sprintf("[%s    ] YOP_UNK: '%c'", e.Type, e.PatchType)
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
		return fmt.Sprintf("[%s ] %s size: %s uid: %d gid: %d flag: %d hlc: %d hlo: %d aft: %d afr: %d '%s'",
			e.Type,
			unixModeToFileMode(uint32(e.Mod)),
			humanize.Bytes(uint64(e.Size)),
			e.Uid,
			e.Gid,
			e.Flag,
			e.Hlc,
			e.Hlo,
			e.Aft,
			e.Afr,
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

func Decode(r *bytes.Reader) (*Entry, error) {

	entry := &Entry{}
	field := make([]byte, 4)

	for {
		// Read Archive field
		err := binary.Read(r, binary.BigEndian, &field)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		switch string(field[:3]) {
		case "TYP": // entry type (always included)
			switch field[3] {
			case '1':
				var etype byte
				if etype, err = r.ReadByte(); err != nil {
					return nil, err
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
					return nil, err
				}
				path := make([]byte, int(pathLength))
				if err := binary.Read(r, binary.LittleEndian, &path); err != nil {
					return nil, err
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
					return nil, err
				}
				path := make([]byte, int(pathLength))
				if err := binary.Read(r, binary.LittleEndian, &path); err != nil {
					return nil, err
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
					return nil, err
				}
				entry.Uid = uint16(dat)
			case '2':
				if err := binary.Read(r, binary.LittleEndian, &entry.Uid); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("found unknown UID field: %s", string(field))
			}
		case "GID": // group id
			switch field[3] {
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Gid = uint16(dat)
			case '2':
				if err := binary.Read(r, binary.LittleEndian, &entry.Gid); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("found unknown UID field: %s", string(field))
			}
		case "MOD": // access mode
			switch field[3] {
			case '2':
				var mod uint16
				if err := binary.Read(r, binary.LittleEndian, &mod); err != nil {
					return nil, err
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
					return nil, err
				}
				entry.Flag = uint32(flag)
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Flag); err != nil {
					return nil, err
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
					return nil, err
				}
				if err := binary.Read(r, binary.LittleEndian, &nsecs); err != nil {
					return nil, err
				}
				entry.Mtm = time.Unix(secs, int64(nsecs))
			case 'S':
				var secs int64
				if err := binary.Read(r, binary.LittleEndian, &secs); err != nil {
					return nil, err
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
					return nil, err
				}
				if err := binary.Read(r, binary.LittleEndian, &nsecs); err != nil {
					return nil, err
				}
				entry.Btm = time.Unix(secs, int64(nsecs))
			case 'S':
				var secs int64
				if err := binary.Read(r, binary.LittleEndian, &secs); err != nil {
					return nil, err
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
					return nil, err
				}
				if err := binary.Read(r, binary.LittleEndian, &nsecs); err != nil {
					return nil, err
				}
				entry.Ctm = time.Unix(secs, int64(nsecs))
			case 'S':
				var secs int64
				if err := binary.Read(r, binary.LittleEndian, &secs); err != nil {
					return nil, err
				}
				entry.Ctm = time.Unix(secs, 0)
			default:
				return nil, fmt.Errorf("found unknown CTM field: %s", string(field))
			}
		case "DAT": // file contents
			switch field[3] {
			case 'B':
				if err := binary.Read(r, binary.LittleEndian, &entry.Size); err != nil {
					return nil, err
				}
			case 'A':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Size = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown DAT field: %s", string(field))
			}
		case "IDX": // entry index in input archive
			switch field[3] {
			case '8':
				if err := binary.Read(r, binary.LittleEndian, &entry.ESize); err != nil {
					return nil, err
				}
			case '4':
				var dat uint32
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Index = uint64(dat)
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Index = uint64(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Index = uint64(dat)
			default:
				return nil, fmt.Errorf("found unknown IDX field: %s", string(field))
			}
		case "IDZ": // entry size in input archive
			switch field[3] {
			case '8':
				if err := binary.Read(r, binary.LittleEndian, &entry.ESize); err != nil {
					return nil, err
				}
			case '4':
				var dat uint32
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.ESize = uint64(dat)
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.ESize = uint64(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.ESize = uint64(dat)
			default:
				return nil, fmt.Errorf("found unknown IDZ field: %s", string(field))
			}
		case "SIZ": // file data size
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Size); err != nil {
					return nil, err
				}
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Size = uint32(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Size = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown SIZ field: %s", string(field))
			}
		case "AFR":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Afr); err != nil {
					return nil, err
				}
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Afr = uint32(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Afr = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown AFR field: %s", string(field))
			}
		case "AFT":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Aft); err != nil {
					return nil, err
				}
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Aft = uint32(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Aft = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown AFR field: %s", string(field))
			}
		case "HLC":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Hlc); err != nil {
					return nil, err
				}
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Hlc = uint32(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Hlc = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown AFR field: %s", string(field))
			}
		case "HLO":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Hlo); err != nil {
					return nil, err
				}
			case '2':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Hlo = uint32(dat)
			case '1':
				var dat byte
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				entry.Hlo = uint32(dat)
			default:
				return nil, fmt.Errorf("found unknown AFR field: %s", string(field))
			}
		case "FLI":
			switch field[3] {
			case '4':
				if err := binary.Read(r, binary.LittleEndian, &entry.Fli); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("found unknown FLI field: %s", string(field))
			}
		case "YOP": // patch
			switch field[3] {
			case '1':
				var ptype byte
				if ptype, err = r.ReadByte(); err != nil {
					return nil, err
				}
				entry.PatchType = patchType(ptype)
			default:
				return nil, fmt.Errorf("found unknown YOP field: %s", string(field))
			}
		case "LBL": // label
			switch field[3] {
			case 'P':
				var dat uint16
				if err := binary.Read(r, binary.LittleEndian, &dat); err != nil {
					return nil, err
				}
				label := make([]byte, dat)
				if err := binary.Read(r, binary.LittleEndian, &label); err != nil {
					return nil, err
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
