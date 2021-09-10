package mbr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	signature = 0xAA55
	mbrSize   = 512
)

type partType byte // https://en.wikipedia.org/wiki/Partition_type

const (
	Empty        partType = 0x00
	AppleUFS     partType = 0xA8
	AppleBoot    partType = 0xAB
	AppleRAID    partType = 0xAC
	AppleHFSPlus partType = 0xAF
	LegacyMBR    partType = 0xEE
)

func (t partType) String() string {
	switch t {
	case AppleUFS:
		return "AppleUFS"
	case AppleBoot:
		return "AppleBoot"
	case AppleRAID:
		return "AppleRAID"
	case AppleHFSPlus:
		return "AppleHFSPlus"
	case LegacyMBR:
		return "Legacy MBR (followed by an EFI header)"
	default:
		return fmt.Sprintf("%#x", t)
	}
}

// MasterBootRecord is a MBR object (512 bytes)
type MasterBootRecord struct {
	BootLoader [446]byte
	Partitions [4]Partition
	Signature  uint16
}

// Partition is a MBR partition object
type Partition struct {
	Boot          bool
	StartCHS      chs // These bytes represent the partition’s starting sector in CHS (Cylinder-Head-Sector)
	Type          partType
	EndCHS        chs
	StartLBA      uint32
	NumberSectors uint32
}

func (p Partition) String() string {
	return fmt.Sprintf(
		"Boot:          %t\n"+
			"StartCHS:      %s\n"+
			"Type:          %s\n"+
			"EndCHS:        %s\n"+
			"StartLBA:      %d\n"+
			"NumberSectors: %d\n",
		p.Boot,
		p.StartCHS,
		p.Type,
		p.EndCHS,
		p.StartLBA,
		p.NumberSectors,
	)
}

type chs [3]byte // FIXME: parsing out the fields might be wrong

func (c chs) cylinder() byte {
	return c[2] + (c[1] & 192 << 2)
}
func (c chs) head() byte {
	return c[0]
}
func (c chs) sector() byte {
	return c[1] & 63
}
func (c chs) String() string {
	return fmt.Sprintf("cylinder=%d, head=%d, sector=%d", c.cylinder(), c.head(), c.sector())
}

// LBA converts CHS to LBA requires heads Per Track and sectors Per Track
func (c chs) LBA(hpt, spt int) int {
	return (int(c.cylinder())*hpt+int(c.head()))*spt + (int(c.sector()) - 1)
}

// NewMasterBootRecord reads a MBR from a given io.Reader
func NewMasterBootRecord(r io.Reader) (*MasterBootRecord, error) {

	buf := make([]byte, mbrSize)
	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return nil, fmt.Errorf("failed to read %T: %w", buf, err)
	}

	rr := bytes.NewReader(buf)

	var mbr MasterBootRecord

	if err := binary.Read(rr, binary.LittleEndian, &mbr); err != nil {
		return nil, fmt.Errorf("failed to read %T: %w", mbr, err)
	}

	if mbr.Signature != signature {
		return nil, fmt.Errorf("invalid MBR signature: %#x (expected %#x)", mbr.Signature, signature)
	}

	return &mbr, nil
}
