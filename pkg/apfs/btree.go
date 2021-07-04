package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/ipsw/pkg/apfs/types"
)

// GetBTreePhysOMapEntry with get the latest version of an object, up to a given XID, from an object map
// B-tree that uses Physical OIDs to refer to its child nodes.
func (a *APFS) GetBTreePhysOMapEntry(r *bytes.Reader, oid types.OidT, maxXid types.XidT) (*types.OMapEntry, error) {

	r.Seek(-int64(binary.Size(types.BTreeInfoT{})), io.SeekEnd)

	var btInfo types.BTreeInfoT
	if err := binary.Read(r, binary.LittleEndian, &btInfo); err != nil {
		return nil, fmt.Errorf("failed to read btree_info_t data: %v", err)
	}

	r.Seek(0, io.SeekStart)

	// Create a copy of the root node to use as the current node we're working with
	var node types.BTreeNodePhysT
	if err := binary.Read(r, binary.LittleEndian, &node); err != nil {
		return nil, fmt.Errorf("failed to read btree_node_phys_t data: %v", err)
	}

	// Pointers to areas of the node
	tocStartPtr := binary.Size(types.BTreeNodePhysT{}) + int(node.TableSpace.Off)
	keyStartPtr := tocStartPtr + int(node.TableSpace.Len)
	valEndPtr := int(a.nxsb.BlockSize) - binary.Size(types.BTreeInfoT{})

	// char* toc_start = (char*)(node->btn_data) + node->btn_table_space.off;
	// char* key_start = toc_start + node->btn_table_space.len;
	// char* val_end   = (char*)node + nx_block_size - sizeof(btree_info_t);

	// Descend the B-tree to find the target key–value pair
	for {
		// if !(node.Flags & types.BTNODE_FIXED_KV_SIZE != 0) {
		//     // TODO: Handle this case
		//     fprintf(stderr, "\nget_btree_phys_omap_val: Object map B-trees don't have variable size keys and values ... do they?\n");

		//     free(node);
		//     return NULL;
		// }

		// TOC entries are instances of `kvoff_t`
		tocEntryPtr := tocStartPtr
		r.Seek(int64(tocEntryPtr), io.SeekStart)
		var tocEntry types.KVOffT
		if err := binary.Read(r, binary.LittleEndian, &tocEntry); err != nil {
			return nil, fmt.Errorf("failed to read kvoff_t data: %v", err)
		}

		/**
		 * Find the correct TOC entry, i.e. the last TOC entry whose:
		 * - OID doesn't exceed the given OID; or
		 * - OID matches the given OID, and XID doesn't exceed the given XID
		 */
		for i := uint32(0); i < node.Nkeys; i, tocEntryPtr = i+1, tocEntryPtr+1 {
			r.Seek(int64(keyStartPtr+int(tocEntry.Key)), io.SeekStart)
			var key types.OMapKey
			if err := binary.Read(r, binary.LittleEndian, &key); err != nil {
				return nil, fmt.Errorf("failed to read omap_key_t data: %v", err)
			}
			if key.Oid > oid || (key.Oid == oid && key.Xid > maxXid) {
				tocEntryPtr--
				r.Seek(int64(tocEntryPtr), io.SeekStart)
				if err := binary.Read(r, binary.LittleEndian, &tocEntry); err != nil {
					return nil, fmt.Errorf("failed to read kvoff_t data: %v", err)
				}
				break
			}
		}

		/**
		 * One of the following is now true about `toc_entry`:
		 *
		 * (a) it points before `toc_start` if no matching records exist
		 *      in this B-tree.
		 * (b) it points directly after the last TOC entry if we should descend
		 *      the last entry.
		 * (c) it points to the correct entry to descend.
		 */

		// Handle case (a)
		if tocEntryPtr < tocStartPtr {
			return nil, fmt.Errorf("no matching records exist in this B-tree")
		}

		// Convert case (b) into case (c)
		if tocEntryPtr-tocStartPtr == int(node.Nkeys) {
			tocEntryPtr--
		}

		// Handle case (c)

		// #ifdef DEBUG
		// fprintf(stderr, "\n- get_btree_phys_omap_val: Picked entry %lu\n", toc_entry - (kvoff_t*)toc_start);
		// #endif

		// If this is a leaf node, return the object map entry
		if (node.Flags & types.BTNODE_LEAF) != 0 {
			// If the object doesn't have the specified OID or its XID exceeds
			// the specifed maximum, then no matching object exists in the B-tree.
			omapEntry := types.OMapEntry{}

			r.Seek(int64(keyStartPtr+int(tocEntry.Key)), io.SeekStart)

			if err := binary.Read(r, binary.LittleEndian, &omapEntry.Key); err != nil {
				return nil, fmt.Errorf("failed to read omap_key_t data: %v", err)
			}

			if omapEntry.Key.Oid != oid || omapEntry.Key.Xid > maxXid {
				return nil, fmt.Errorf("key.Oid != oid || key.Xid > maxXid")
			}

			r.Seek(int64(uint16(valEndPtr)-tocEntry.Val), io.SeekStart)

			if err := binary.Read(r, binary.LittleEndian, &omapEntry.Val); err != nil {
				return nil, fmt.Errorf("failed to read omap_val_t data: %v", err)
			}

			return &omapEntry, nil
		}

		// // Else, read the corresponding child node into memory and loop
		// paddr_t* child_node_addr = val_end - toc_entry->v;

		// if (read_blocks(node, *child_node_addr, 1) != 1) {
		//     fprintf(stderr, "\nABORT: get_btree_phys_omap_val: Failed to read block 0x%" PRIx64 ".\n", *child_node_addr);
		//     exit(-1);
		// }

		// if (!is_cksum_valid(node)) {
		//     fprintf(stderr, "\nget_btree_phys_omap_val: Checksum of node at block 0x%" PRIx64 " did not validate. Proceeding anyway as if it did.\n", *child_node_addr);
		// }

		// toc_start = (char*)(node->btn_data) + node->btn_table_space.off;
		// key_start = toc_start + node->btn_table_space.len;
		// val_end   = (char*)node + nx_block_size;    // Always dealing with non-root node here
	}
}

func (a *APFS) GetFSRecords() *types.JRecT {
	return nil
}
