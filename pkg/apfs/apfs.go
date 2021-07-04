package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
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

	var iLatestNx uint32
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
			log.Debugf("block at index %d within this area failed checksum validation. Skipping it.", i)
			continue
		}
		iLatestNx = i
	}

	nxsb := a.xpDesc[iLatestNx].(types.NxSuperblockT)
	if nxsb.XpDescIndex+nxsb.XpDescLen <= xpDescBlocks {
		fmt.Println("contig")
	} else {
		fmt.Println("shizzzz")
	}
	xp := a.xpDesc[nxsb.XpDescIndex].(types.CheckpointMapPhys)
	fmt.Println(xp)

	log.Infof("the container superblock states that the container object map has physical OID %#016x", nxsb.OmapOid)

	r.Seek(int64(uint64(nxsb.OmapOid)*uint64(a.nxsb.BlockSize)), io.SeekStart)

	var omap types.OmapPhysT
	if err := binary.Read(r, binary.LittleEndian, &omap); err != nil {
		return nil, fmt.Errorf("failed to read APFS omap_phys_t: %v", err)
	}
	fmt.Println(omap)

	r.Seek(int64(uint64(omap.TreeOid)*uint64(a.nxsb.BlockSize)), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &block); err != nil {
		return nil, fmt.Errorf("failed to read APFS btree_node_phys_t block: %v", err)
	}

	r.Seek(int64(uint64(omap.TreeOid)*uint64(a.nxsb.BlockSize)), io.SeekStart)

	var omapBtree types.BTreeNodePhys
	if err := binary.Read(r, binary.LittleEndian, &omapBtree.BTreeNodePhysT); err != nil {
		return nil, fmt.Errorf("failed to read APFS btree_node_phys_t: %v", err)
	}

	omapBtree.Data = make([]uint64, (a.nxsb.BlockSize-uint32(binary.Size(omapBtree.BTreeNodePhysT)))/uint32(binary.Size(uint64(1))))
	if err := binary.Read(r, binary.LittleEndian, &omapBtree.Data); err != nil {
		return nil, fmt.Errorf("failed to read APFS btree_node_phys_t Data: %v", err)
	}
	fmt.Println(omapBtree)

	var numFileSystems uint32
	for _, fsOid := range nxsb.FsOids {
		if fsOid == 0 {
			break
		}
		numFileSystems++
	}

	log.Infof("the container superblock lists %d APFS volumes, whose superblocks have the following virtual OIDs:", numFileSystems)
	apsbs := make([]types.ApfsSuperblockT, numFileSystems)
	for i := uint32(0); i < numFileSystems; i++ {
		utils.Indent(log.Info, 2)(fmt.Sprintf("- %#x", nxsb.FsOids[i]))
		// omap_entry_t* fs_entry = get_btree_phys_omap_entry(nx_omap_btree, nxsb->nx_fs_oid[i], nxsb->nx_o.o_xid);
		fsEntry, err := a.GetBTreePhysOMapEntry(bytes.NewReader(block), nxsb.FsOids[i], nxsb.Obj.Xid)
		if err != nil {
			// fprintf(stderr, "\nABORT: No objects with Virtual OID 0x%" PRIx64 " and maximum XID 0x%" PRIx64 " exist in `nx_omap_btree`.\n", nxsb->nx_fs_oid[i], nxsb->nx_o.o_xid);
			return nil, fmt.Errorf("failed to get btree phys omap entry: %v", err)
		}

		r.Seek(int64(fsEntry.Val.Paddr*uint64(a.nxsb.BlockSize)), io.SeekStart)

		if err := binary.Read(r, binary.LittleEndian, &apsbs[i]); err != nil {
			return nil, fmt.Errorf("failed to read apfs_superblock_t data: %v", err)
		}
	}

	var apsb types.ApfsSuperblockT
	if len(apsbs) == 1 {
		apsb = apsbs[0]
	}

	r.Seek(int64(uint64(apsb.OmapOid)*uint64(a.nxsb.BlockSize)), io.SeekStart)

	var fsOMap types.OmapPhysT
	if err := binary.Read(r, binary.LittleEndian, &fsOMap); err != nil {
		return nil, fmt.Errorf("failed to read omap_phys_t data for volume: %v", err)
	}

	r.Seek(int64(uint64(fsOMap.TreeOid)*uint64(a.nxsb.BlockSize)), io.SeekStart)

	if err := binary.Read(r, binary.LittleEndian, &block); err != nil {
		return nil, fmt.Errorf("failed to read APFS btree_node_phys_t block: %v", err)
	}

	r.Seek(int64(uint64(fsOMap.TreeOid)*uint64(a.nxsb.BlockSize)), io.SeekStart)

	var fsOMapBTree types.BTreeNodePhys
	if err := binary.Read(r, binary.LittleEndian, &fsOMapBTree.BTreeNodePhysT); err != nil {
		return nil, fmt.Errorf("failed to read btree_node_phys_t data for root node of the volume object map B-tree: %v", err)
	}
	// TODO: get Data ??
	fsRootEntry, err := a.GetBTreePhysOMapEntry(bytes.NewReader(block), apsb.RootTreeOid, apsb.Obj.Xid)
	if err != nil {
		return nil, fmt.Errorf("failed to get btree phys omap entry: %v", err)
	}

	r.Seek(int64(fsRootEntry.Val.Paddr*uint64(a.nxsb.BlockSize)), io.SeekStart)

	var fsRootBTree types.BTreeNodePhys
	if err := binary.Read(r, binary.LittleEndian, &fsRootBTree.BTreeNodePhysT); err != nil {
		return nil, fmt.Errorf("failed to read btree_node_phys_t data for root node of the filesystem object map B-tree: %v", err)
	}
	// TODO: get Data ??

	fmt.Println(fsRootBTree)

	return a, nil
}
