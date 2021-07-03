package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/apfs/types"
)

// APFS apple file system object
type APFS struct {
	nxsb   types.NxSuperblockT
	xpDesc []interface{}

	sr     *io.SectionReader
	closer io.Closer
}

// Open opens the named file using os.Open and prepares it for use as an APFS.
func Open(name string) (*APFS, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	ff, err := NewAPFS(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	ff.closer = f
	return ff, nil
}

// Close closes the APFS.
// If the APFS was created using NewFile directly instead of Open,
// Close has no effect.
func (a *APFS) Close() error {
	var err error
	if a.closer != nil {
		err = a.closer.Close()
		a.closer = nil
	}
	return err
}

// NewAPFS creates a new APFS for accessing a apple filesystem container or file in an underlying reader.
// The apfs is expected to start at position 0 in the ReaderAt.
func NewAPFS(r *os.File) (*APFS, error) {

	a := new(APFS)
	a.sr = io.NewSectionReader(r, 0, 1<<63-1)

	if err := binary.Read(r, binary.LittleEndian, &a.nxsb); err != nil {
		return nil, fmt.Errorf("failed to read APFS nx_superblock_t: %v", err)
	}

	if a.nxsb.Magic.String() != types.NX_MAGIC {
		return nil, fmt.Errorf("found unexpected nx_superblock_t magic: %s, expected: %s", a.nxsb.Magic.String(), types.NX_MAGIC)
	}

	//TODO: check checksum & validate struct

	// fmt.Printf("%#v\n", a.nxsb)

	r.Seek(int64(a.nxsb.XpDescBase*uint64(a.nxsb.BlockSize)), io.SeekStart)

	xpDescBlocks := a.nxsb.XpDescBlocks & ^(uint32(1) << 31)
	// TODO: check for continuous

	a.xpDesc = make([]interface{}, xpDescBlocks)
	block := make([]byte, a.nxsb.BlockSize)

	for i := uint32(0); i < xpDescBlocks; i++ {
		if err := binary.Read(r, binary.LittleEndian, &block); err != nil {
			return nil, fmt.Errorf("failed to read APFS checkpoint block: %v", err)
		}

		rr := bytes.NewReader(block)

		var o types.ObjPhysT
		if err := binary.Read(rr, binary.LittleEndian, &o); err != nil {
			return nil, fmt.Errorf("failed to read APFS checkpoint desc obj_phys_t: %v", err)
		}

		rr.Seek(0, io.SeekStart)

		switch o.GetType() {
		case types.OBJECT_TYPE_CHECKPOINT_MAP:
			var checkpointMap types.CheckpointMapPhys
			if err := binary.Read(rr, binary.LittleEndian, &checkpointMap.Hdr); err != nil {
				return nil, fmt.Errorf("failed to read APFS checkpoint_map_phys_t.flags: %v", err)
			}
			checkpointMap.Map = make([]types.CheckpointMappingT, checkpointMap.Hdr.Count)
			if err := binary.Read(rr, binary.LittleEndian, &checkpointMap.Map); err != nil {
				return nil, fmt.Errorf("failed to read APFS checkpoint_mapping_t array: %v", err)
			}
			a.xpDesc[i] = checkpointMap
		case types.OBJECT_TYPE_NX_SUPERBLOCK:
			var nxsb types.NxSuperblockT
			if err := binary.Read(rr, binary.LittleEndian, &nxsb); err != nil {
				return nil, fmt.Errorf("failed to read APFS nx_superblock_t: %v", err)
			}
			a.xpDesc[i] = nxsb
		case types.OBJECT_TYPE_INVALID:
			break
		default:
			log.Fatalf("found unsupported object type: %s", o.GetType().String())
		}
		// check checksum
		if !types.VerifyChecksum(block) {
			log.Warnf("block at index %d within this area failed checksum validation. Skipping it.", i)
			continue
		}
	}

	return a, nil
}
