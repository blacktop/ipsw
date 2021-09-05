package types

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

//go:generate stringer -type=omapValFlag,omapSnapshotFlag,omapFlag -output omap_string.go

type omapValFlag uint32
type omapSnapshotFlag uint32
type omapFlag uint32

const (
	/** Object Map Value Flags **/
	OMAP_VAL_DELETED           omapValFlag = 0x00000001
	OMAP_VAL_SAVED             omapValFlag = 0x00000002
	OMAP_VAL_ENCRYPTED         omapValFlag = 0x00000004
	OMAP_VAL_NOHEADER          omapValFlag = 0x00000008
	OMAP_VAL_CRYPTO_GENERATION omapValFlag = 0x00000010

	/** Snapshot Flags **/
	OMAP_SNAPSHOT_DELETED  omapSnapshotFlag = 0x00000001
	OMAP_SNAPSHOT_REVERTED omapSnapshotFlag = 0x00000002

	/** Object Map Flags **/
	OMAP_MANUALLY_MANAGED  omapFlag = 0x00000001
	OMAP_ENCRYPTING        omapFlag = 0x00000002
	OMAP_DECRYPTING        omapFlag = 0x00000004
	OMAP_KEYROLLING        omapFlag = 0x00000008
	OMAP_CRYPTO_GENERATION omapFlag = 0x00000010

	OMAP_VALID_FLAGS = 0x0000001f

	/** Object Map Constants **/
	OMAP_MAX_SNAP_COUNT = math.MaxUint32

	/** Object Map Reaper Phases **/
	OMAP_REAP_PHASE_MAP_TREE      = 1
	OMAP_REAP_PHASE_SNAPSHOT_TREE = 2
)

// OMapPhysT is a omap_phys_t struct
type OMapPhysT struct {
	// Obj              ObjPhysT
	Flags            omapFlag
	SnapCount        uint32
	TreeType         objType
	SnapshotTreeType objType
	TreeOid          OidT
	SnapshotTreeOid  OidT
	MostRecentSnap   XidT
	PendingRevertMin XidT
	PendingRevertMax XidT
}

type OMap struct {
	OMapPhysT

	Tree         *Obj
	SnapshotTree *Obj

	block
}

// OMapKey is a omap_key_t struct
type OMapKey struct {
	Oid OidT
	Xid XidT
}

func (k OMapKey) String() string {
	return fmt.Sprintf("oid=%#x, xid=%#x", k.Oid, k.Xid)
}

// OMapVal is a omap_val_t struct
type OMapVal struct {
	Flags omapValFlag
	Size  uint32
	Paddr uint64
}

func (v OMapVal) String() string {
	return fmt.Sprintf("flags=%s, size=%#x, paddr=%#x", v.Flags, v.Size, v.Paddr)
}

// OMapSnapshotT is a omap_snapshot_t
type OMapSnapshotT struct {
	Flags omapSnapshotFlag
	Pad   uint32
	Oid   OidT
}

func (s OMapSnapshotT) String() string {
	return fmt.Sprintf("oid=%#x, flags=%s", s.Oid, s.Flags)
}

type FextNodeEntry struct {
	Offset interface{}
	Key    fext_tree_key_t
	Val    fext_tree_val_t
}

func (f FextNodeEntry) String() string {
	var fout []string
	switch off := f.Offset.(type) {
	case KVOffT:
		fout = append(fout, fmt.Sprintf("(key_offset=%d, val_offset=%d)", off.Key, off.Val))
	case KVLocT:
		fout = append(fout, fmt.Sprintf("(key_off=%d, key_len=%d, val_off=%d, val_len=%d)", off.Key.Off, off.Key.Len, off.Val.Off, off.Val.Len))
	}
	fout = append(fout, f.Key.String(), f.Val.String())
	return strings.Join(fout, ", ")
}

type SpacemanFreeQueueNodeEntry struct {
	Offset interface{}
	Key    spaceman_free_queue_key_t
	Val    spaceman_free_queue_val_t
}

func (s SpacemanFreeQueueNodeEntry) String() string {
	var sout []string
	switch off := s.Offset.(type) {
	case KVOffT:
		sout = append(sout, fmt.Sprintf("(key_offset=%d, val_offset=%d)", off.Key, off.Val))
	case KVLocT:
		sout = append(sout, fmt.Sprintf("(key_off=%d, key_len=%d, val_off=%d, val_len=%d)", off.Key.Off, off.Key.Len, off.Val.Off, off.Val.Len))
	}
	sout = append(sout, s.Key.String(), s.Val.String())
	return strings.Join(sout, ", ")
}

type OMapNodeEntry struct {
	Offset interface{}
	Key    OMapKey
	PAddr  uint64
	OMap   *Obj
	Val    OMapVal
}

func (one OMapNodeEntry) String() string {
	var nout []string

	switch off := one.Offset.(type) {
	case KVOffT:
		nout = append(nout, fmt.Sprintf("(key_offset=%d, val_offset=%d)", off.Key, off.Val))
	case KVLocT:
		nout = append(nout, fmt.Sprintf("(key_off=%d, key_len=%d, val_off=%d, val_len=%d)", off.Key.Off, off.Key.Len, off.Val.Off, off.Val.Len))
	}

	nout = append(nout, fmt.Sprintf("key={%s}", one.Key))

	if one.PAddr > 0 {
		nout = append(nout, fmt.Sprintf("paddr=%#x", one.PAddr))
	}

	if one.OMap != nil {
		nout = append(nout, fmt.Sprintf("omap=%s", one.OMap))
	}

	nout = append(nout, fmt.Sprintf("value={%s}", one.Val))

	return strings.Join(nout, ", ")
}

type NodeEntry struct {
	Offset interface{}
	Hdr    JKeyT
	Key    interface{}
	PAddr  uint64
	Val    interface{}
}

func (ne NodeEntry) String() string {
	var nout []string

	nout = append(nout, fmt.Sprintf("%s oid=%d", ne.Hdr.GetType(), ne.Hdr.GetID()))

	switch off := ne.Offset.(type) {
	case KVOffT:
		nout = append(nout, fmt.Sprintf("(key_offset=%d, val_offset=%d)", off.Key, off.Val))
	case KVLocT:
		nout = append(nout, fmt.Sprintf("(key_off=%d, key_len=%d, val_off=%d, val_len=%d)", off.Key.Off, off.Key.Len, off.Val.Off, off.Val.Len))
	}

	switch ne.Hdr.GetType() {
	case APFS_TYPE_SNAP_METADATA:
	case APFS_TYPE_EXTENT:
	case APFS_TYPE_INODE:
	case APFS_TYPE_XATTR:
		nout = append(nout, fmt.Sprintf("name=%s", ne.Key.(j_xattr_key_t).Name))
	case APFS_TYPE_SIBLING_LINK:
		nout = append(nout, fmt.Sprintf("sibling_id=%#x", ne.Key.(SiblingKeyT).SiblingID))
	case APFS_TYPE_DSTREAM_ID:
	case APFS_TYPE_CRYPTO_STATE:
	case APFS_TYPE_FILE_EXTENT:
		nout = append(nout, fmt.Sprintf("logical_addr=%#x", ne.Key.(j_file_extent_key_t).LogicalAddr))
	case APFS_TYPE_DIR_REC:
		nout = append(nout, fmt.Sprintf("name=%s, hash=%#x", ne.Key.(j_drec_hashed_key_t).Name, ne.Key.(j_drec_hashed_key_t).Hash()))
	case APFS_TYPE_DIR_STATS:
	case APFS_TYPE_SNAP_NAME:
		nout = append(nout, fmt.Sprintf("name=%s", ne.Key.(j_snap_name_key_t).Name))
	case APFS_TYPE_SIBLING_MAP:
	case APFS_TYPE_FILE_INFO:
		nout = append(nout, fmt.Sprintf("lba=%#x, info=%s", ne.Key.(j_file_info_key_t).LBA(), ne.Key.(j_file_info_key_t).Info()))
	}

	if ne.PAddr > 0 {
		nout = append(nout, fmt.Sprintf("paddr=%#x", ne.PAddr))
	}

	switch ne.Hdr.GetType() {
	case APFS_TYPE_SNAP_METADATA:
		nout = append(nout, ne.Val.(j_snap_metadata_val).String())
	case APFS_TYPE_EXTENT:
		nout = append(nout, ne.Val.(j_phys_ext_val_t).String())
	case APFS_TYPE_INODE:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_inode_val:
			nout = append(nout, ne.Val.(j_inode_val).String())
		}
	case APFS_TYPE_XATTR:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_xattr_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_SIBLING_LINK:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case SiblingValT:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_DSTREAM_ID:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_dstream_id_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_CRYPTO_STATE:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_crypto_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_FILE_EXTENT:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_file_extent_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_DIR_REC:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_drec_val:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_DIR_STATS:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_dir_stats_val_t:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_SNAP_NAME:
		nout = append(nout, ne.Val.(j_snap_name_val_t).String())
	case APFS_TYPE_SIBLING_MAP:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case SiblingMapValT:
			nout = append(nout, val.String())
		}
	case APFS_TYPE_FILE_INFO:
		switch val := ne.Val.(type) {
		case BTreeNodeIndexNodeValT:
			nout = append(nout, val.String())
		case uint64:
			nout = append(nout, fmt.Sprintf("val=%#x", val))
		case j_file_info_val_t:
			nout = append(nout, val.String())
		}
	}

	return strings.Join(nout, ", ")
}

const (
	newLine      = "\n"
	emptySpace   = "    "
	middleItem   = "├── "
	continueItem = "│   "
	lastItem     = "└── "
)

// FSTree file system tree - credit: https://github.com/d6o/GoTree
type FSTree interface {
	Add(text string) FSTree
	AddTree(tree FSTree)
	Items() []FSTree
	Text() string
	Print() string
}

type tree struct {
	text  string
	items []FSTree
}

type printer struct {
}

// Printer is printer interface
type Printer interface {
	Print(FSTree) string
}

// NewFSTree returns a new FSTree
func NewFSTree(text string) FSTree {
	return &tree{
		text:  text,
		items: []FSTree{},
	}
}

// Add adds a node to the tree
func (t *tree) Add(text string) FSTree {
	n := NewFSTree(text)
	t.items = append(t.items, n)
	return n
}

// AddTree adds a tree as an item
func (t *tree) AddTree(tree FSTree) {
	t.items = append(t.items, tree)
}

// Text returns the node's value
func (t *tree) Text() string {
	return t.text
}

// Items returns all items in the tree
func (t *tree) Items() []FSTree {
	return t.items
}

// Print returns an visual representation of the tree
func (t *tree) Print() string {
	return newPrinter().Print(t)
}

func newPrinter() Printer {
	return &printer{}
}

// Print prints a tree to a string
func (p *printer) Print(t FSTree) string {
	return t.Text() + newLine + p.printItems(t.Items(), []bool{})
}

func (p *printer) printText(text string, spaces []bool, last bool) string {
	var result string
	for _, space := range spaces {
		if space {
			result += emptySpace
		} else {
			result += continueItem
		}
	}

	indicator := middleItem
	if last {
		indicator = lastItem
	}

	var out string
	lines := strings.Split(text, "\n")
	for i := range lines {
		text := lines[i]
		if i == 0 {
			out += result + indicator + text + newLine
			continue
		}
		if last {
			indicator = emptySpace
		} else {
			indicator = continueItem
		}
		out += result + indicator + text + newLine
	}

	return out
}

func (p *printer) printItems(t []FSTree, spaces []bool) string {
	var result string
	for i, f := range t {
		last := i == len(t)-1
		result += p.printText(f.Text(), spaces, last)
		if len(f.Items()) > 0 {
			spacesChild := append(spaces, last)
			result += p.printItems(f.Items(), spacesChild)
		}
	}
	return result
}

// FSRecords are an array of file system records
type FSRecords []NodeEntry

// Tree prints a FSRecords array as a tree
func (recs FSRecords) Tree() string {
	t := NewFSTree("/")
	var fs []string
	for _, rec := range recs {
		switch rec.Hdr.GetType() {
		case APFS_TYPE_DIR_REC:
			fs = append(fs, rec.Key.(j_drec_hashed_key_t).Name)
		}
	}
	sort.Strings(fs)
	for _, f := range fs {
		t.Add(f)
	}
	return t.Print()
}

func (recs FSRecords) String() string {
	var rsout string
	for _, rec := range recs {
		switch rec.Hdr.GetType() {
		case APFS_TYPE_DIR_REC:
			rsout += fmt.Sprintf("%s\n", rec.Key.(j_drec_hashed_key_t).Name)
		}
	}
	return rsout
}
