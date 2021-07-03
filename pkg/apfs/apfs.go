package apfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/blacktop/ipsw/pkg/apfs/types"
)

// APFS apple file system object
type APFS struct {
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

	var nxSuperBlock types.NxSuperblockT
	if err := binary.Read(r, binary.LittleEndian, &nxSuperBlock); err != nil {
		return nil, fmt.Errorf("failed to read APFS nx_superblock_t: %v", err)
	}

	if nxSuperBlock.Magic.String() != types.NX_MAGIC {
		return nil, fmt.Errorf("found unexpected NxSuperblockT magic: %s, expected: %s", nxSuperBlock.Magic.String(), types.NX_MAGIC)
	}

	//TODO: check checksum & validate struct

	fmt.Printf("%v\n", nxSuperBlock)

	xpDescBlocks := nxSuperBlock.XpDescBlocks & ^(uint32(1) << 31)
	for i := uint32(0); i < xpDescBlocks; i++ {
		fmt.Println(i)
	}

	return a, nil
}
