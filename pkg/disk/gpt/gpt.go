package gpt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"unicode/utf16"
)

const (
	Signature  = "EFI PART"
	SectorSize = 0x200
)

const (
	HFSPlus            = "48465300-0000-11AA-AA11-00306543ECAC"
	Apple_APFS         = "7C3457EF-0000-11AA-AA11-00306543ECAC"
	Apple_UFS          = "55465300-0000-11AA-AA11-00306543ECAC"
	ZFS                = "6A898CC3-1DD2-11B2-99A6-080020736631"
	Apple_RAID         = "52414944-0000-11AA-AA11-00306543ECAC"
	Apple_RAID_offline = "52414944-5F4F-11AA-AA11-00306543ECAC"
	Apple_Recovery_HD  = "426F6F74-0000-11AA-AA11-00306543ECAC"
	Apple_Label        = "4C616265-6C00-11AA-AA11-00306543ECAC"
	AppleTV_Recovery   = "5265636F-7665-11AA-AA11-00306543ECAC"
	HFSPlus_FileVault  = "53746F72-6167-11AA-AA11-00306543ECAC"
)

var Apfs = [...]byte{0xEF, 0x57, 0x34, 0x7C, 0x00, 0x00, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC}

type guid [16]byte

func (u guid) String() string {
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		u[3], u[2], u[1], u[0],
		u[5], u[4],
		u[7], u[6],
		u[8], u[9],
		u[10], u[11], u[12], u[13], u[14], u[15],
	)
}

type magic [8]byte

// Header is a GPT header object
type Header struct {
	Signature       magic
	Revision        uint32
	HeaderSize      uint32
	CRC32           uint32
	Reserved        uint32
	HeaderStartLBA  uint64
	BackupLBA       uint64
	FirstUsableLBA  uint64
	LastUsableLBA   uint64
	DiskGUID        guid
	EntriesStart    uint64
	EntriesCount    uint32
	EntriesSize     uint32
	PartitionsCRC32 uint32
	Padding         [420]byte
}

func (h Header) String() string {
	return fmt.Sprintf(
		"Signature:       %s\n"+
			"Revision:        %#x\n"+
			"HeaderSize:      %d\n"+
			"CRC32:           %#x\n"+
			"HeaderStartLBA:  %d\n"+
			"BackupLBA:       %d\n"+
			"FirstUsableLBA:  %d\n"+
			"LastUsableLBA:   %d\n"+
			"DiskGUID:        %s\n"+
			"EntriesStart:    %d\n"+
			"EntriesCount:    %d\n"+
			"EntriesSize:     %d\n"+
			"PartitionsCRC32: %#x\n",
		h.Signature,
		h.Revision,
		h.HeaderSize,
		h.CRC32,
		h.HeaderStartLBA,
		h.BackupLBA,
		h.FirstUsableLBA,
		h.LastUsableLBA,
		h.DiskGUID,
		h.EntriesStart,
		h.EntriesCount,
		h.EntriesSize,
		h.PartitionsCRC32,
	)
}

// CalulateCRC calculates the header's CRC32 hash
func (h Header) CalulateCRC() uint32 {
	buf := &bytes.Buffer{}
	h.CRC32 = 0
	binary.Write(buf, binary.LittleEndian, h)
	return crc32.ChecksumIEEE(buf.Bytes()[:h.HeaderSize])
}

// Verify verifies the header
func (h Header) Verify() error {
	if h.EntriesSize != 128 {
		return fmt.Errorf("unsupported GPT format, must be 128 byte")
	}

	if SectorSize-len(h.Padding) != int(h.HeaderSize) {
		return fmt.Errorf("invalid header size")
	}

	if string(h.Signature[:]) != Signature {
		return fmt.Errorf("invalid GPT signature: %s", h.Signature)
	}

	return nil
}

// Partition is a GPT partition object
type Partition struct {
	Type               guid
	ID                 guid
	StartingLBA        uint64
	EndingLBA          uint64
	Attributes         uint64
	PartitionNameUTF16 [72]uint8
}

// LookupType returns the string name for a given partition type if known otherwise it will return the GUID
func (p Partition) LookupType() string {
	switch p.Type.String() {
	case HFSPlus:
		return "HFSPlus"
	case Apple_APFS:
		return "Apple_APFS"
	case Apple_UFS:
		return "Apple_UFS"
	case ZFS:
		return "ZFS"
	case Apple_RAID:
		return "Apple_RAID"
	case Apple_RAID_offline:
		return "Apple_RAID_offline"
	case Apple_Recovery_HD:
		return "Apple_Recovery_HD"
	case Apple_Label:
		return "Apple_Label"
	case AppleTV_Recovery:
		return "AppleTV_Recovery"
	case HFSPlus_FileVault:
		return "HFSPlus_FileVault"
	default:
		return p.Type.String()
	}
}

func (p Partition) String() string {
	return fmt.Sprintf(
		"Name:        %s\n"+
			"Type:        %s\n"+
			"ID:          %s\n"+
			"StartingLBA: %d\n"+
			"EndingLBA:   %d\n"+
			"Attributes: %#x\n",
		p.Name(),
		p.LookupType(),
		p.ID,
		p.StartingLBA,
		p.EndingLBA,
		p.Attributes,
	)
}

// IsEmpty returns if the partiton is empty
func (p Partition) IsEmpty() bool {
	return p.Type == [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

// Name returns the partiton's name
func (p Partition) Name() string {
	n, err := decodeUtf16(p.PartitionNameUTF16[:], binary.LittleEndian)
	if err != nil {
		return "<unable to decode UTF-16 partition name>"
	}
	return n
}

// GUIDPartitionTable is a GPT table object
type GUIDPartitionTable struct {
	Header     Header
	Partitions []Partition
}

// CalulatePartitionsCRC calculates the partition tables's CRC32 hash
func (g GUIDPartitionTable) CalulatePartitionsCRC() uint32 {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, g.Partitions)
	return crc32.ChecksumIEEE(buf.Bytes())
}

func decodeUtf16(b []byte, order binary.ByteOrder) (string, error) {
	ints := make([]uint16, len(b)/2)
	if err := binary.Read(bytes.NewReader(b), order, &ints); err != nil {
		return "", err
	}
	return string(utf16.Decode(ints)), nil
}

// NewGUIDPartitionTable reads a GPT from the given io.Reader
func NewGUIDPartitionTable(r io.Reader) (*GUIDPartitionTable, error) {
	var gpt GUIDPartitionTable
	if err := binary.Read(r, binary.LittleEndian, &gpt.Header); err != nil {
		return nil, fmt.Errorf("failed to read %T: %w", gpt.Header, err)
	}

	if gpt.Header.EntriesSize != 128 {
		return nil, fmt.Errorf("unsupported GPT format, must be 128 byte")
	}

	if SectorSize-len(gpt.Header.Padding) != int(gpt.Header.HeaderSize) {
		return nil, fmt.Errorf("invalid header size")
	}

	if string(gpt.Header.Signature[:]) != Signature {
		return nil, fmt.Errorf("invalid GPT signature: %s", gpt.Header.Signature)
	}

	gpt.Partitions = make([]Partition, gpt.Header.EntriesCount)
	if err := binary.Read(r, binary.LittleEndian, &gpt.Partitions); err != nil {
		return nil, fmt.Errorf("failed to read %T: %w", gpt.Partitions, err)
	}

	return &gpt, nil
}
