package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/apfs/types"
)

// GetBTreePhysOMapEntry with get the latest version of an object, up to a given XID, from an object map
// B-tree that uses Physical OIDs to refer to its child nodes.
func (a *APFS) GetBTreePhysOMapEntry(rootNode *types.BTreeNodePhys, oid types.OidT, maxXid types.XidT) (*types.OMapEntry, error) {

	btInfo, err := rootNode.GetInfo()
	if err != nil {
		return nil, err
	}

	// Create a copy of the root node to use as the current node we're working with
	node := rootNode

	tocStartOffset := binary.Size(types.BTreeNodePhysT{}) + int(node.TableSpace.Off)
	// Pointers to areas of the node
	tocStartPtr := binary.Size(types.BTreeNodePhysT{})
	// tocStartPtr := binary.Size(types.BTreeNodePhysT{}) + int(node.TableSpace.Off)
	keyStartPtr := tocStartPtr + int(node.TableSpace.Len)
	valEndPtr := int(a.nxsb.BlockSize) - binary.Size(types.BTreeInfoT{})

	entries, err := node.GetTocKVOffEntries(tocStartOffset, node.TableSpace.Len)
	if err != nil {
		return nil, err
	}
	for _, ent := range entries {
		fmt.Printf(
			"Key: %d\n"+
				"Val: %d\n",
			ent.Key,
			ent.Val,
		)
		keys, err := node.GetOMapKeys(int64(keyStartPtr+int(ent.Key)), btInfo.KeyCount)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			fmt.Printf(
				"Oid: %d\n"+
					"Xid: %d\n",
				key.Oid,
				key.Xid,
			)
		}
		fmt.Println()
	}

	// Descend the B-tree to find the target key–value pair
	for {
		if !(node.Flags&types.BTNODE_FIXED_KV_SIZE != 0) {
			// TODO: Handle this case
			// fprintf(stderr, "\nget_btree_phys_omap_val: Object map B-trees don't have variable size keys and values ... do they?\n")
			return nil, fmt.Errorf("TODO")
		}

		// TOC entries are instances of `kvoff_t`
		tocEntryPtr := tocStartPtr
		tocEntry, err := node.GetTocKVOffEntry(int64(tocEntryPtr))
		if err != nil {
			return nil, err
		}

		/**
		 * Find the correct TOC entry, i.e. the last TOC entry whose:
		 * - OID doesn't exceed the given OID; or
		 * - OID matches the given OID, and XID doesn't exceed the given XID
		 */
		for i := uint32(0); i < node.Nkeys; i++ {
			key, err := node.GetOMapKey(int64(keyStartPtr + int(tocEntry.Key)))
			if err != nil {
				return nil, err
			}
			if key.Oid > oid || (key.Oid == oid && key.Xid > maxXid) {
				tocEntryPtr -= binary.Size(types.KVOffT{})
				tocEntry, err = node.GetTocKVOffEntry(int64(tocEntryPtr))
				if err != nil {
					return nil, err
				}
				break
			} else {
				tocEntryPtr += binary.Size(types.KVOffT{})
				tocEntry, err = node.GetTocKVOffEntry(int64(tocEntryPtr))
				if err != nil {
					return nil, err
				}
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
			tocEntryPtr -= binary.Size(types.KVOffT{})
			tocEntry, err = node.GetTocKVOffEntry(int64(tocEntryPtr))
			if err != nil {
				return nil, err
			}
		}

		// Handle case (c)
		log.WithFields(log.Fields{
			"entry": fmt.Sprintf("%#v", entries[0]),
		}).Debug("selected entry")

		// If this is a leaf node, return the object map entry
		if (node.Flags & types.BTNODE_LEAF) != 0 {
			// If the object doesn't have the specified OID or its XID exceeds
			// the specifed maximum, then no matching object exists in the B-tree.
			return node.GetOMapEntry(
				int64(keyStartPtr+int(tocEntry.Key)),
				int64(uint16(valEndPtr)-tocEntry.Val),
				oid,
				maxXid,
			)
		}

		// Else, read the corresponding child node into memory and loop
		node, err = node.GetChildNode(a.r, int64(valEndPtr-int(tocEntry.Val)))
		if err != nil {
			return nil, err
		}

		log.WithFields(log.Fields{
			"checksum": fmt.Sprintf("%#x", binary.LittleEndian.Uint64(node.Obj.Cksum[:])),
		}).Debug("child node")

		if !node.ValidChecksum() {
			log.Warnf("node at block %#x has a bad checksum. Proceeding anyway 🤷‍♀️", node.Block)
		}

		tocStartPtr = binary.Size(types.BTreeNodePhysT{}) + int(node.TableSpace.Off)
		keyStartPtr = tocStartPtr + int(node.TableSpace.Len)
		valEndPtr = int(a.nxsb.BlockSize) // Always dealing with non-root node here
	}
}

// GetFSRecords returns the filesystem records
func (a *APFS) GetFSRecords(volOMapRootNode, volFsRootNode *types.BTreeNodePhys, oid types.OidT, maxXid types.XidT) ([]*types.JRecT, error) {

	volOmapRootInfo, err := volOMapRootNode.GetInfo()
	if err != nil {
		return nil, err
	}
	fmt.Printf("%#v\n", volOmapRootInfo)

	volFsInfo, err := volFsRootNode.GetInfo()
	if err != nil {
		return nil, err
	}
	fmt.Printf("%#v\n", volFsInfo)

	treeHeight := volFsRootNode.Level + 1

	/**
	 * `desc_path` describes the path we have taken to descend down the file-
	 * system root tree. Since these B+ trees do not contain pointers to their
	 * siblings, this info is needed in order to easily walk the tree after we
	 * find the first record with the given OID.
	 *
	 * The value of `desc_path[i]` is the index of the key
	 * chosen `i` levels beneath the root level, out of the keys within the
	 * node that key was chosen from. The length of `desc_path` is the height
	 * of the tree.
	 *
	 * For example, suppose the height of the tree is 4, and:
	 *
	 * 1. we descend to the 1st child (index 0) of the root node (level 3); then
	 * 2. we descend to the 3rd child (index 2) of that level 2 node; then
	 * 3. we descend to the 2nd child (index 1) of that level 1 node; then
	 * 4. we are currently looking at the 4th entry (index 3) of that leaf node;
	 *
	 * then `desc_path` will be equal to the array `{0, 2, 1, 3}`.
	 */
	descPath := make([]uint32, treeHeight)

	/**
	 * Let `node` be the working node (the FS tree node that we're currently
	 * looking at), and copy the FS tree's root node there. We do this so that
	 * when we look at child nodes later, we can copy them to `node` without
	 * losing access to the root node, an instance of which will still be
	 * present as `vol_fs_root_node`.
	 */
	node := volFsRootNode

	// Pointers to areas of the working node
	tocStartPtr := binary.Size(types.BTreeNodePhysT{}) + int(node.TableSpace.Off)
	keyStartPtr := tocStartPtr + int(node.TableSpace.Len)
	valEndPtr := int(a.nxsb.BlockSize) - binary.Size(types.BTreeInfoT{})

	/**
	 * DESCENT LOOP
	 * Descend the tree to find the first record in the tree with the desired OID.
	 */
	for i := uint16(0); i < treeHeight; i++ {
		// if (node->btn_flags & BTNODE_FIXED_KV_SIZE) {
		//     // TODO: Handle this case
		//     fprintf(stderr, "\nget_fs_records: File-system root B-trees don't have fixed size keys and values ... do they?\n");
		//     exit(-1);
		// }

		// TOC entries are instances of `kvloc_t`
		tocEntryPtr := tocStartPtr
		tocEntry, err := node.GetTocKVLocEntry(int64(tocEntryPtr))
		if err != nil {
			return nil, err
		}

		/**
		 * Determine which entry in this node we should descend; we break from
		 * this loop once we have determined the right entry or looked at all
		 * of them.
		 */
		for descPath[i] = uint32(0); descPath[i] < node.Nkeys; descPath[i]++ {
			// for (desc_path[i] = 0;    desc_path[i] < node->btn_nkeys;    desc_path[i]++, toc_entry++) {
			key, err := node.GetJKey(int64(keyStartPtr + int(tocEntry.Key.Off)))
			if err != nil {
				return nil, err
			}

			recordOid := types.OidT(key.ObjIDAndType & types.OBJ_ID_MASK)

			/** Handle leaf nodes **/
			if (node.Flags & types.BTNODE_LEAF) != 0 {
				if recordOid == oid {
					/**
					 * This is the first matching record, and `desc_path`
					 * now describes the path to it in the tree.
					 */
					break
				}

				if recordOid > oid {
					/**
					 * If a record with the desired OID existed, we would've
					 * encountered it by now, so no such records exist.
					 */
					return nil, fmt.Errorf("TODO")
				}

				// assert(record_oid < oid);
				tocEntryPtr += binary.Size(types.KVLocT{})
				tocEntry, err = node.GetTocKVLocEntry(int64(tocEntryPtr))
				if err != nil {
					return nil, err
				}
				continue // Look at the next record
			}

			/** Handle non-leaf nodes **/
			// assert(!(node->btn_flags & BTNODE_LEAF));

			if recordOid >= oid {
				/**
				 * We've encountered the first entry in this non-leaf node
				 * whose key states an OID that is greater than or equal to the
				 * desired OID. Thus, if this *isn't* the first entry in this
				 * node, we descend the previous entry, as a record with the
				 * desired OID may exist in that sub-tree.
				 */
				if descPath[i] != 0 {
					descPath[i]--
					tocEntryPtr -= binary.Size(types.KVLocT{})
					tocEntry, err = node.GetTocKVLocEntry(int64(tocEntryPtr))
					if err != nil {
						return nil, err
					}
					break
				}

				/**
				 * However, if this *is* the first entry in this node, we only
				 * descend it if its key's stated OID matches the desired OID;
				 * else it exceeds the desired OID, and thus no records with the
				 * desired OID exist *in the whole tree*.
				 */
				if recordOid == oid {
					break
				}

				return nil, fmt.Errorf("TODO")
			}

			// assert(record_oid < oid);
			// Implicit `continue`; look at the next entry.

			tocEntryPtr += binary.Size(types.KVLocT{})
			tocEntry, err = node.GetTocKVLocEntry(int64(tocEntryPtr))
			if err != nil {
				return nil, err
			}
		}

		/**
		 * One of the following is now true about `toc_entry`:
		 *
		 * (a) it points directly after the last TOC entry, in which case:
		 *      (i)  if this is a leaf node, we're looking at it because the
		 *              first record in the *next* leaf node has the desired
		 *              OID, or no records with the desired OID exist in the
		 *              whole tree. We just break from the descent loop, and the
		 *              walk loop will handle the current value of `desc_path`
		 *              correctly.
		 *      (ii) if this is a non-leaf node, we should descend the last
		 *              entry.
		 * (b) it points to the correct entry to descend.
		 */

		/**
		 * If this is a leaf node, then we have finished descending the tree,
		 * and `desc_path` describes the path to the first record with the
		 * desired OID. We break from this while-loop (the descent loop) and
		 * enter the next while-loop (the walk loop), which should behave
		 * correctly based on the vale of `desc_path`.
		 *
		 * This handles case (a)(i) above, and also case (b) when we're looking
		 * at a leaf node.
		 */
		if (node.Flags & types.BTNODE_LEAF) != 0 {
			break
		}

		/** Convert case (a)(ii) to case (b) */
		if tocEntryPtr-tocStartPtr == int(node.Nkeys) {
			descPath[i]--
			tocEntryPtr -= binary.Size(types.KVLocT{})
			tocEntry, err = node.GetTocKVLocEntry(int64(tocEntryPtr))
			if err != nil {
				return nil, err
			}
		}

		/**
		 * Else, read the corresponding child node into memory and loop.
		 * This handles case (b) when we're looking at a non-leaf node.
		 */
		childNodeVirtOid, err := node.GetOid(int64(valEndPtr) - int64(tocEntry.Val.Off))
		if err != nil {
			return nil, fmt.Errorf("TODO")
		}
		fmt.Printf("childNodeVirtOid: %#x\n", *childNodeVirtOid)
		childNodeOmapEntry, err := a.GetBTreePhysOMapEntry(volOMapRootNode, *childNodeVirtOid, maxXid)
		if err != nil {
			return nil, fmt.Errorf("failed to get btree phys omap entry: %v", err)
		}

		// `node` is now the child node we will scan on next loop
		node, err = types.NewBTreeNode(a.r, int64(childNodeOmapEntry.Val.Paddr), node.GetBlockSize())
		if err != nil {
			return nil, err
		}

		log.WithFields(log.Fields{
			"checksum": fmt.Sprintf("%#x", binary.LittleEndian.Uint64(node.Obj.Cksum[:])),
		}).Debug("child node")

		if !node.ValidChecksum() {
			log.Warnf("node at block %#x has a bad checksum. Proceeding anyway 🤷‍♀️", node.Block)
		}

		tocStartPtr = binary.Size(types.BTreeNodePhysT{}) + int(node.TableSpace.Off)
		keyStartPtr = tocStartPtr + int(node.TableSpace.Len)
		valEndPtr = int(a.nxsb.BlockSize) // Always dealing with non-root node here
	}

	// Initialise the array of records which will be returned to the caller
	var numRecords uint32
	var records []*types.JRecT

	/**
	 * WALK LOOP
	 *
	 * Now that we've found the first record with the given OID, walk along the
	 * tree to get the rest of the records with that OID.
	 *
	 * We do so by following `desc_path`, which describes the descent path to a
	 * record in the tree, and then adjusting the value of `desc_path` so that
	 * it refers to the next record in tree, so that when we loop, we visit
	 * that next record.
	 */
	for {
		// Reset working node and pointers to the root node
		node = volFsRootNode

		tocStartPtr = binary.Size(types.BTreeNodePhysT{}) + int(node.TableSpace.Off)
		keyStartPtr = tocStartPtr + int(node.TableSpace.Len)
		valEndPtr = int(a.nxsb.BlockSize) - binary.Size(types.BTreeInfoT{})

		// Descend to the record described by `desc_path`.
		for i := uint16(0); i < treeHeight; i++ {
			// if (node->btn_flags & BTNODE_FIXED_KV_SIZE) {
			// 	// TODO: Handle this case
			// 	fprintf(stderr, "\nget_fs_records: File-system root B-trees don't have fixed size keys and values ... do they?\n");

			// 	free(node);
			// 	free_j_rec_array(records);
			// 	return NULL;
			// }

			/**
			 * If `desc_path[i]` isn't a valid entry index in this node, that
			 * means we've already looked at all the entries in this node, and
			 * should look at the next node on this level.
			 */
			if descPath[i] >= node.Nkeys {
				/**
				 * If this is a root node, then there are no other nodes on this
				 * level; we've gone through the whole tree, return the results.
				 */
				if node.Flags&types.BTNODE_ROOT != 0 {
					node = nil
					return records, nil
				}

				/**
				 * Else, we adjust the value of `desc_path` so that it refers
				 * to the leftmost descendant of the next node on this level.
				 * We then break from this for-loop so that we loop inside the
				 * while-loop (the walk loop), which will result in us making
				 * a new descent from the root based on the new value of
				 * `desc_path`.
				 */
				descPath[i-1]++
				for j := i; j < treeHeight; j++ {
					descPath[j] = 0
				}
				break
			}

			/**
			 * Handle leaf nodes:
			 * The entry we're looking at is the next record, so add it to the
			 * records array, then adjust `desc_path` and loop.
			 */
			if (node.Flags & types.BTNODE_LEAF) != 0 {
				// TOC entries are instances of `kvloc_t`.
				// ents, err := node.GetTocKVLocEntries(int64(tocStartPtr)) // FIXME: doesn't match the C val
				// if err != nil {
				// 	return nil, err
				// }
				// for _, ent := range ents {
				// 	fmt.Printf(
				// 		"Key.Off: %d\n"+
				// 			"Key.Len: %d\n"+
				// 			"Val.Off: %d\n"+
				// 			"Val.Len: %d\n\n",
				// 		ent.Key.Off,
				// 		ent.Key.Len,
				// 		ent.Val.Off,
				// 		ent.Val.Len,
				// 	)
				// }
				tocEntry, err := node.GetTocKVLocEntry(int64(tocStartPtr)) // FIXME: doesn't match the C val
				if err != nil {
					return nil, err
				}
				// Walk along this leaf node
				for ; descPath[i] < node.Nkeys; descPath[i]++ {
					// for (
					// 	kvloc_t* toc_entry = (kvloc_t*)toc_start + desc_path[i];
					// 	desc_path[i] < node->btn_nkeys;
					// 	desc_path[i]++, toc_entry++
					// ) {
					key, err := node.GetJKey(int64(keyStartPtr + int(tocEntry.Key.Off)))
					if err != nil {
						return nil, err
					}
					fmt.Printf("%v\n", key)
					recordOid := types.OidT(key.ObjIDAndType & types.OBJ_ID_MASK)

					if recordOid != oid {
						// This record doesn't have the right OID, so we must have
						// found all of the relevant records; return the results
						return records, nil
					}

					// char* val = valEnd - toc_entry->v.off;
					val, err := node.GetBytes(int64(valEndPtr)-int64(tocEntry.Val.Off), tocEntry.Val.Len)

					rec := &types.JRecT{
						KeyLen: tocEntry.Key.Len,
						ValLen: tocEntry.Val.Len,
					}
					// w := bytes.NewBuffer(rec.Data)
					binary.Write(bytes.NewBuffer(rec.Data), binary.LittleEndian, key)
					binary.Write(bytes.NewBuffer(rec.Data), binary.LittleEndian, val)

					// memcpy(records[num_records]->data,                                  key,  records[num_records]->key_len);
					// memcpy(records[num_records]->data + records[num_records]->key_len,  val,  records[num_records]->val_len);

					records = append(records, rec)
					numRecords++

					//                 records = realloc(records, (num_records + 1) * sizeof(j_rec_t*));
					//                 if (!records) {
					//                     fprintf(stderr, "\nABORT: get_fs_records: Could not allocate sufficient memory for `records`.\n");
					//                     exit(-1);
					//                 }
					//                 records[num_records] = NULL;
				}

				/**
				 * We've run off the end of this leaf node, and `desc_path` now
				 * refers to the first record of the next leaf node.
				 * Loop so that we correctly make a new descent to that record
				 * from the root node.
				 */
				break
			}

			/**
			 * Handle non-leaf nodes:
			 * Read the child node that this entry points to, then loop.
			 */
			// assert(!(node->btn_flags & BTNODE_LEAF));

			// We look at the TOC entry corresponding to the child node we need
			// to descend to.

			// TOC entries are instances of `kvloc_t`.
			tocEntry, err := node.GetTocKVLocEntry(int64(tocStartPtr + int(descPath[i])))
			if err != nil {
				return nil, err
			}

			childNodeVirtOid, err := node.GetOid(int64(valEndPtr) - int64(tocEntry.Val.Off))
			if err != nil {
				return nil, fmt.Errorf("TODO")
			}
			fmt.Printf("childNodeVirtOid: %#x\n", *childNodeVirtOid)
			childNodeOmapEntry, err := a.GetBTreePhysOMapEntry(volOMapRootNode, *childNodeVirtOid, maxXid)
			if err != nil {
				return nil, fmt.Errorf("failed to get btree phys omap entry: %v", err)
			}

			// `node` is now the child node that we will examine on next loop
			node, err = types.NewBTreeNode(a.r, int64(childNodeOmapEntry.Val.Paddr), node.GetBlockSize())
			if err != nil {
				return nil, err
			}

			log.WithFields(log.Fields{
				"checksum": fmt.Sprintf("%#x", binary.LittleEndian.Uint64(node.Obj.Cksum[:])),
			}).Debug("child node")

			if !node.ValidChecksum() {
				log.Warnf("node at block %#x has a bad checksum. Proceeding anyway 🤷‍♀️", node.Block)
			}

			tocStartPtr = binary.Size(types.BTreeNodePhysT{}) + int(node.TableSpace.Off)
			keyStartPtr = tocStartPtr + int(node.TableSpace.Len)
			valEndPtr = int(a.nxsb.BlockSize) // Always dealing with non-root node here
		}
	}
}
