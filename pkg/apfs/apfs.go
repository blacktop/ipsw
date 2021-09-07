package apfs

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/apfs/types"
)

// APFS apple file system object
type APFS struct {
	Container   *types.NxSuperblock
	Valid       *types.NxSuperblock
	Volume      *types.ApfsSuperblock
	FSRootBtree types.BTreeNodePhys

	nxsb            *types.Obj // Container
	checkPointDesc  []*types.Obj
	validCheckPoint *types.Obj
	volume          *types.Obj
	fsOMapBtree     *types.BTreeNodePhys

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

func init() {
	types.BLOCK_SIZE = types.NX_DEFAULT_BLOCK_SIZE
}

// NewAPFS creates a new APFS for accessing a apple filesystem container or file in an underlying reader.
// The apfs is expected to start at position 0 in the ReaderAt.
func NewAPFS(r *os.File) (*APFS, error) {

	var err error

	a := new(APFS)
	sr := io.NewSectionReader(r, 0, 1<<63-1)
	a.r = r

	a.nxsb, err = types.ReadObj(sr, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read APFS container")
	}

	if nxsb, ok := a.nxsb.Body.(types.NxSuperblock); ok {
		a.Container = &nxsb
	}

	if a.Container.BlockSize != types.NX_DEFAULT_BLOCK_SIZE {
		types.BLOCK_SIZE = uint64(a.Container.BlockSize)
		log.Warnf("found non-standard blocksize in APFS nx_superblock_t: %#x", types.BLOCK_SIZE)
	}

	log.WithFields(log.Fields{
		"checksum": fmt.Sprintf("%#x", a.nxsb.Hdr.Checksum()),
		"oid":      fmt.Sprintf("%#x", a.nxsb.Hdr.Oid),
		"xid":      fmt.Sprintf("%#x", a.nxsb.Hdr.Xid),
		"type":     a.nxsb.Hdr.GetType(),
		"sub_type": a.nxsb.Hdr.GetSubType(),
		"flag":     a.nxsb.Hdr.GetFlag(),
		"magic":    a.Container.Magic.String(),
	}).Debug("APFS Container")

	utils.Indent(log.WithFields(log.Fields{
		"checksum": fmt.Sprintf("%#x", a.Container.OMap.Hdr.Checksum()),
		"type":     a.Container.OMap.Hdr.GetType(),
		"oid":      fmt.Sprintf("%#x", a.Container.OMap.Hdr.Oid),
		"xid":      fmt.Sprintf("%#x", a.Container.OMap.Hdr.Xid),
		"sub_type": a.Container.OMap.Hdr.GetSubType(),
		"flag":     a.Container.OMap.Hdr.GetFlag(),
	}).Debug, 2)("Object Map")

	if err := a.getValidCSB(); err != nil {
		return nil, fmt.Errorf("failed to find the container superblock that has the largest transaction identifier and isnʼt malformed: %v", err)
	}

	if len(a.Valid.OMap.Body.(types.OMap).Tree.Body.(types.BTreeNodePhys).Entries) == 1 {
		if entry, ok := a.Valid.OMap.Body.(types.OMap).Tree.Body.(types.BTreeNodePhys).Entries[0].(types.OMapNodeEntry); ok {
			a.volume, err = types.ReadObj(sr, uint64(entry.Val.Paddr))
			if err != nil {
				return nil, fmt.Errorf("failed to read APFS omap.tree.entry.omap (volume): %v", err)
			}
			if vol, ok := a.volume.Body.(types.ApfsSuperblock); ok {
				log.WithFields(log.Fields{
					"checksum": fmt.Sprintf("%#x", a.volume.Hdr.Checksum()),
					"type":     a.volume.Hdr.GetType(),
					"oid":      fmt.Sprintf("%#x", a.volume.Hdr.Oid),
					"xid":      fmt.Sprintf("%#x", a.volume.Hdr.Xid),
					"sub_type": a.volume.Hdr.GetSubType(),
					"flag":     a.volume.Hdr.GetFlag(),
				}).Debug(fmt.Sprintf("APFS Volume (%s)", string(vol.VolumeName[:])))

				a.Volume = &vol
			}
		}
	}

	log.Debugf("File System OMap Btree: %s", a.Volume.OMap.Body.(types.OMap).Tree)

	if ombtree, ok := a.Volume.OMap.Body.(types.OMap).Tree.Body.(types.BTreeNodePhys); ok {
		a.fsOMapBtree = &ombtree
	}

	fsRootEntry, err := a.fsOMapBtree.GetOMapEntry(sr, a.Volume.RootTreeOid, a.volume.Hdr.Xid)
	if err != nil {
		return nil, err
	}

	log.Debugf("File System Root Entry: %s", fsRootEntry)

	fsRootBtreeObj, err := types.ReadObj(sr, fsRootEntry.Val.Paddr)
	if err != nil {
		return nil, err
	}

	if root, ok := fsRootBtreeObj.Body.(types.BTreeNodePhys); ok {
		a.FSRootBtree = root
	}

	return a, nil
}

// getValidCSB returns the container superblock that has the largest transaction identifier and isnʼt malformed
func (a *APFS) getValidCSB() error {
	log.Debug("Parsing Checkpoint Description")

	sr := io.NewSectionReader(a.r, 0, 1<<63-1)

	nxsb := a.nxsb.Body.(types.NxSuperblock)

	if (nxsb.XpDescBlocks >> 31) != 0 {
		return fmt.Errorf("unable to parse non-contiguous checkpoint descriptor area")
	}
	xpDescBlocks := nxsb.XpDescBlocks & ^(uint32(1) << 31)

	for i := uint32(0); i < xpDescBlocks; i++ {
		o, err := types.ReadObj(sr, nxsb.XpDescBase+uint64(i))
		if err != nil {
			if errors.Is(err, types.ErrBadBlockChecksum) {
				utils.Indent(log.Debug, 2)(fmt.Sprintf("checkpoint block at index %d failed checksum validation. Skipping...", i))
				continue
			}
			return fmt.Errorf("failed to read XpDescBlock: %v", err)
		}
		a.checkPointDesc = append(a.checkPointDesc, o)
	}

	a.validCheckPoint = a.checkPointDesc[len(a.checkPointDesc)-1]

	if nxsb, ok := a.validCheckPoint.Body.(types.NxSuperblock); ok {
		a.Valid = &nxsb
	}

	if a.Valid.XpDescIndex+a.Valid.XpDescLen <= xpDescBlocks {
		log.Debug("contiguous")
	} else {
		log.Warn("shizzzz")
	}

	return nil
}

// Ls lists files at a given path
func (a *APFS) Ls(path string) error {

	sr := io.NewSectionReader(a.r, 0, 1<<63-1)

	fsRecords, err := a.fsOMapBtree.GetFSRecordsForOid(sr, a.FSRootBtree, types.OidT(types.FSROOT_OID), types.XidT(^uint64(0)))
	if err != nil {
		return err
	}

	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if len(part) > 0 {
			for _, rec := range fsRecords {
				switch rec.Hdr.GetType() {
				case types.APFS_TYPE_DIR_REC:
					if rec.Key.(types.JDrecHashedKeyT).Name == part {
						fsRecords, err = a.fsOMapBtree.GetFSRecordsForOid(sr, a.FSRootBtree, types.OidT(rec.Val.(types.JDrecVal).FileID), types.XidT(^uint64(0)))
						if err != nil {
							return err
						}
					}
					// default:
					// 	log.Warnf("found fs record type %s", rec.Hdr.GetType())
				}
			}
		}
	}

	fmt.Println(fsRecords)

	return nil
}

// Tree list contents of directories in a tree-like format. TODO: finish this
func (a *APFS) Tree(path string) error {

	sr := io.NewSectionReader(a.r, 0, 1<<63-1)

	fsOMapBtree := a.Volume.OMap.Body.(types.OMap).Tree.Body.(types.BTreeNodePhys)

	fsRootEntry, err := fsOMapBtree.GetOMapEntry(sr, a.Volume.RootTreeOid, a.volume.Hdr.Xid)
	if err != nil {
		return err
	}

	fsRootBtreeObj, err := types.ReadObj(sr, fsRootEntry.Val.Paddr)
	if err != nil {
		return err
	}

	fsRootBtree := fsRootBtreeObj.Body.(types.BTreeNodePhys)

	fsRecords, err := fsOMapBtree.GetFSRecordsForOid(sr, fsRootBtree, types.OidT(types.FSROOT_OID), types.XidT(^uint64(0)))
	if err != nil {
		return err
	}

	fstree := types.NewFSTree("/")

	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if len(part) > 0 {
			for _, rec := range fsRecords {
				switch rec.Hdr.GetType() {
				case types.APFS_TYPE_DIR_REC:
					if rec.Key.(types.JDrecHashedKeyT).Name == part {
						fsRecords, err = fsOMapBtree.GetFSRecordsForOid(sr, fsRootBtree, types.OidT(rec.Val.(types.JDrecVal).FileID), types.XidT(^uint64(0)))
						if err != nil {
							return err
						}
						fstree.AddTree(fsRecords.Tree())
					} else {
						fstree.Add(rec.Key.(types.JDrecHashedKeyT).Name)
					}
				// case types.APFS_TYPE_INODE:
				// 	for _, xf := range rec.Val.(j_inode_val).Xfields {
				// 		if xf.XType == INO_EXT_TYPE_NAME {
				// 			if xf.Field.(string) == "root" {
				// 				t = NewFSTree("/")
				// 			} else {
				// 				t = NewFSTree(xf.Field.(string))
				// 				}
				// 			}
				// 		}
				// 	}
				default:
					log.Warnf("found fs record type %s", rec.Hdr.GetType())
				}
			}
		}
	}

	fmt.Println(fstree.Print())

	return nil
}

// Copy copies the contents of the src file to the dest file TODO: finish this
// func (a *APFS) Copy(src, dest string) error {

// 	sr := io.NewSectionReader(a.r, 0, 1<<63-1)

// 	fsOMapBtree := a.Volume.OMap.Body.(types.OMap).Tree.Body.(types.BTreeNodePhys)

// 	fsRootEntry, err := fsOMapBtree.GetOMapEntry(sr, a.Volume.RootTreeOid, a.volume.Hdr.Xid)
// 	if err != nil {
// 		return err
// 	}

// 	fsRootBtreeObj, err := types.ReadObj(sr, fsRootEntry.Val.Paddr)
// 	if err != nil {
// 		return err
// 	}

// 	fsRootBtree := fsRootBtreeObj.Body.(types.BTreeNodePhys)

// 	fsRecords, err := fsOMapBtree.GetFSRecordsForOid(sr, fsRootBtree, types.OidT(types.FSROOT_OID), types.XidT(^uint64(0)))
// 	if err != nil {
// 		return err
// 	}

// 	// TODO: need to find the file's record

// 	var decmpfsHdr *types.DecmpfsDiskHeader
// 	for _, rec := range fsRecords {
// 		fmt.Println(rec)
// 		decmpfsHdr, err = types.GetDecmpfsHeader(rec)
// 		if err != nil {
// 			log.Error(err.Error())
// 		}
// 	}

// 	fsRecords, err = fsOMapBtree.GetFSRecordsForOid(sr, fsRootBtree, types.OidT(0xfffffff00019f2c), types.XidT(^uint64(0)))
// 	if err != nil {
// 		return err
// 	}

// 	for _, rec := range fsRecords {
// 		fmt.Println(rec)
// 	}

// 	fo, err := os.Create(dest)
// 	if err != nil {
// 		return err
// 	}
// 	defer fo.Close()

// 	w := bufio.NewWriter(fo)

// 	if err := types.DecompressFile(io.NewSectionReader(sr, int64(0xc943d*types.BLOCK_SIZE), 0x5010000), w, decmpfsHdr); err != nil {
// 		return err
// 	}

// 	w.Flush()

// 	return nil
// }
