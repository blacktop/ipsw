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
	nxsb            *types.NxSuperblock // Container
	checkPointDesc  []interface{}
	validCheckPoint *types.NxSuperblockT

	r      *os.File
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

// SeekBlock seeks to a given block ID's block in the apfs file data
func (a *APFS) SeekBlock(blockID uint64) (ret int64, err error) {
	return a.r.Seek(int64(blockID*uint64(a.nxsb.BlockSize)), io.SeekStart)
}

// NewAPFS creates a new APFS for accessing a apple filesystem container or file in an underlying reader.
// The apfs is expected to start at position 0 in the ReaderAt.
func NewAPFS(r *os.File) (*APFS, error) {

	var err error

	a := new(APFS)
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	a.r = r

	a.nxsb, err = types.ReadNxSuperblock(sr)
	if err != nil {
		return nil, fmt.Errorf("failed to read APFS container")
	}

	log.WithFields(log.Fields{
		"checksum": fmt.Sprintf("%#x", a.nxsb.Obj.Checksum()),
		"oid":      fmt.Sprintf("%#x", a.nxsb.Obj.Oid),
		"xid":      fmt.Sprintf("%#x", a.nxsb.Obj.Xid),
		"type":     a.nxsb.Obj.GetType(),
		"sub_type": a.nxsb.Obj.GetSubType(),
		"flag":     a.nxsb.Obj.GetFlag(),
		"magic":    a.nxsb.Magic.String(),
	}).Debug("APFS Container")

	sr.Seek(int64(a.nxsb.XpDescBase*uint64(a.nxsb.BlockSize)), io.SeekStart)

	if (a.nxsb.XpDescBlocks >> 31) != 0 {
		return nil, fmt.Errorf("unable to parse non-contiguous checkpoint descriptor area")
	}

	xpDescBlocks := a.nxsb.XpDescBlocks & ^(uint32(1) << 31)
	a.checkPointDesc = make([]interface{}, xpDescBlocks)
	block := make([]byte, a.nxsb.BlockSize)

	log.Debug("Parsing Checkpoint Descrip")

	var iLatestNx uint32
	for i := uint32(0); i < xpDescBlocks; i++ {
		if err := binary.Read(sr, binary.LittleEndian, &block); err != nil {
			return nil, fmt.Errorf("failed to read APFS checkpoint block: %v", err)
		}

		// check checksum
		if !types.VerifyChecksum(block) {
			utils.Indent(log.Debug, 2)(fmt.Sprintf("checkpoint block at index %d within this area failed checksum validation. Skipping it.", i))
			continue
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
				return nil, fmt.Errorf("failed to read APFS checkpoint_map_phys_t: %v", err)
			}
			checkpointMap.Map = make([]types.CheckpointMappingT, checkpointMap.Hdr.Count)
			if err := binary.Read(rr, binary.LittleEndian, &checkpointMap.Map); err != nil {
				return nil, fmt.Errorf("failed to read APFS checkpoint_mapping_t array: %v", err)
			}
			a.checkPointDesc[i] = checkpointMap
		case types.OBJECT_TYPE_NX_SUPERBLOCK:
			var nxsb types.NxSuperblockT
			if err := binary.Read(rr, binary.LittleEndian, &nxsb); err != nil {
				return nil, fmt.Errorf("failed to read APFS checkpoint nx_superblock_t: %v", err)
			}
			a.checkPointDesc[i] = nxsb
		case types.OBJECT_TYPE_INVALID:
			break
		default:
			log.Fatalf("found unsupported object type: %s", o.GetType().String())
		}

		iLatestNx = i
	}

	if valid, ok := a.checkPointDesc[iLatestNx].(types.NxSuperblockT); ok {
		a.validCheckPoint = &valid
	} else {
		return nil, fmt.Errorf("last valid checkpoint is NOT a nx_superblock_t")
	}

	if a.validCheckPoint.XpDescIndex+a.validCheckPoint.XpDescLen <= xpDescBlocks {
		fmt.Println("contiguous")
	} else {
		fmt.Println("shizzzz")
	}

	a.nxsb.OMap, err = types.ReadOMap(sr, uint64(a.validCheckPoint.OmapOid))
	if err != nil {
		return nil, fmt.Errorf("failed to read APFS omap_phys_t: %v", err)
	}

	log.WithFields(log.Fields{
		"checksum": fmt.Sprintf("%#x", a.nxsb.OMap.Obj.Checksum()),
		"type":     a.nxsb.OMap.Obj.GetType(),
		"oid":      fmt.Sprintf("%#x", a.nxsb.OMap.Obj.Oid),
		"xid":      fmt.Sprintf("%#x", a.nxsb.OMap.Obj.Xid),
		"sub_type": a.nxsb.OMap.Obj.GetSubType(),
		"flag":     a.nxsb.OMap.Obj.GetFlag(),
	}).Debug("APFS Container Object Map")

	entry, ok := a.nxsb.OMap.Tree.Entries[0].(types.OMapNodeEntry)
	if !ok {
		log.Error("can't cast Entries[0] to OMapNodeEntry")
	}
	volOMap, err := types.ReadOMap(sr, uint64(entry.Val.Paddr))
	if err != nil {
		return nil, fmt.Errorf("failed to read APFS omap_phys_t: %v", err)
	}

	log.WithFields(log.Fields{
		"checksum": fmt.Sprintf("%#x", volOMap.Obj.Checksum()),
		"type":     volOMap.Obj.GetType(),
		"oid":      fmt.Sprintf("%#x", volOMap.Obj.Oid),
		"xid":      fmt.Sprintf("%#x", volOMap.Obj.Xid),
		"sub_type": volOMap.Obj.GetSubType(),
		"flag":     volOMap.Obj.GetFlag(),
	}).Debug("APFS Volume")

	var numFileSystems uint32
	for _, fsOid := range a.validCheckPoint.FsOids {
		if fsOid == 0 {
			break
		}
		numFileSystems++
	}

	// log.Infof("the container superblock lists %d APFS volumes, whose superblocks have the following virtual OIDs:", numFileSystems)
	// vols := make([]types.ApfsSuperblockT, numFileSystems)
	// for i := uint32(0); i < numFileSystems; i++ {
	// 	utils.Indent(log.Info, 2)(fmt.Sprintf("%#x", validContSB.FsOids[i]))
	// 	// omap_entry_t* fs_entry = get_btree_phys_omap_entry(nx_omap_btree, nxsb->nx_fs_oid[i], nxsb->nx_o.o_xid);
	// 	fsEntry, err := a.GetBTreePhysOMapEntry(oMapBtree, validContSB.FsOids[i], validContSB.Obj.Xid)
	// 	if err != nil {
	// 		// fprintf(stderr, "\nABORT: No objects with Virtual OID 0x%" PRIx64 " and maximum XID 0x%" PRIx64 " exist in `nx_omap_btree`.\n", nxsb->nx_fs_oid[i], nxsb->nx_o.o_xid);
	// 		return nil, fmt.Errorf("failed to get btree phys omap entry: %v", err)
	// 	}

	// 	r.Seek(int64(fsEntry.Val.Paddr*uint64(a.nxsb.BlockSize)), io.SeekStart)

	// 	if err := binary.Read(r, binary.LittleEndian, &vols[i]); err != nil {
	// 		return nil, fmt.Errorf("failed to read apfs_superblock_t data: %v", err)
	// 	}
	// }

	// var vol types.ApfsSuperblockT
	// if len(vols) == 1 {
	// 	vol = vols[0]
	// }

	// log.WithField("name", string(vol.VolumeName[:])).Info("Volume")

	// r.Seek(int64(uint64(vol.OmapOid)*uint64(a.nxsb.BlockSize)), io.SeekStart)

	// var fsOMap types.OmapPhysT
	// if err := binary.Read(r, binary.LittleEndian, &fsOMap); err != nil {
	// 	return nil, fmt.Errorf("failed to read omap_phys_t data for volume: %v", err)
	// }

	// fsOMapBTree, err := types.NewBTreeNode(r, int64(fsOMap.TreeOid), int64(a.nxsb.BlockSize))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read root node of the container object map B-tree at block %#x: %v", omap.TreeOid, err)
	// }

	// fsRootEntry, err := a.GetBTreePhysOMapEntry(fsOMapBTree, vol.RootTreeOid, vol.Obj.Xid)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to get btree phys omap entry: %v", err)
	// }

	// fsRootBTree, err := types.NewBTreeNode(r, int64(fsRootEntry.Val.Paddr), int64(a.nxsb.BlockSize))
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to read root node of the container object map B-tree at block %#x: %v", omap.TreeOid, err)
	// }

	// fsRecords, err := a.GetFSRecords(fsOMapBTree, fsRootBTree, 2, types.XidT(^uint64(0)))
	// if err != nil {
	// 	return nil, err
	// }

	// fmt.Println(fsRecords)

	return a, nil
}
