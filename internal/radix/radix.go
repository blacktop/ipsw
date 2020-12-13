package radix

// src: https://github.com/armon/go-radix

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"sort"
	"strings"
)

// WalkFn is used when walking the tree. Takes a
// key and value, returning if iteration should
// be terminated.
type WalkFn func(s string, v interface{}) bool

// leafNode is used to represent a value
type leafNode struct {
	Key string
	Val interface{}
}

// edge is used to represent an edge node
type edge struct {
	Label byte
	Node  *node
}

type node struct {
	// Leaf is used to store possible Leaf
	Leaf *leafNode

	// Prefix is the common Prefix we ignore
	Prefix string

	// Edges should be stored in-order for iteration.
	// We avoid a fully materialized slice to save memory,
	// since in most cases we expect to be sparse
	Edges edges
}

func (n *node) isLeaf() bool {
	return n.Leaf != nil
}

func (n *node) addEdge(e edge) {
	n.Edges = append(n.Edges, e)
	n.Edges.Sort()
}

func (n *node) updateEdge(label byte, node *node) {
	num := len(n.Edges)
	idx := sort.Search(num, func(i int) bool {
		return n.Edges[i].Label >= label
	})
	if idx < num && n.Edges[idx].Label == label {
		n.Edges[idx].Node = node
		return
	}
	panic("replacing missing edge")
}

func (n *node) getEdge(label byte) *node {
	num := len(n.Edges)
	idx := sort.Search(num, func(i int) bool {
		return n.Edges[i].Label >= label
	})
	if idx < num && n.Edges[idx].Label == label {
		return n.Edges[idx].Node
	}
	return nil
}

func (n *node) delEdge(label byte) {
	num := len(n.Edges)
	idx := sort.Search(num, func(i int) bool {
		return n.Edges[i].Label >= label
	})
	if idx < num && n.Edges[idx].Label == label {
		copy(n.Edges[idx:], n.Edges[idx+1:])
		n.Edges[len(n.Edges)-1] = edge{}
		n.Edges = n.Edges[:len(n.Edges)-1]
	}
}

type edges []edge

func (e edges) Len() int {
	return len(e)
}

func (e edges) Less(i, j int) bool {
	return e[i].Label < e[j].Label
}

func (e edges) Swap(i, j int) {
	e[i], e[j] = e[j], e[i]
}

func (e edges) Sort() {
	sort.Sort(e)
}

// Tree implements a radix tree. This can be treated as a
// Dictionary abstract data type. The main advantage over
// a standard hash map is prefix-based lookups and
// ordered iteration,
type Tree struct {
	Root *node
	Size int
}

// New returns an empty Tree
func New() *Tree {
	return NewFromMap(nil)
}

// NewFromMap returns a new tree containing the keys
// from an existing map
func NewFromMap(m map[string]interface{}) *Tree {
	t := &Tree{Root: &node{}}
	for k, v := range m {
		t.Insert(k, v)
	}
	return t
}

// Unmarshal parses the gob-encoded data and stores the result in the radix tree pointed to by t.
func Unmarshal(data []byte, t Tree) error {
	return gob.NewDecoder(bytes.NewReader(data)).Decode(&t)
}

// Marshal returns the gob encoding of radix tree.
func (t *Tree) Marshal() ([]byte, error) {
	buff := new(bytes.Buffer)

	enc := gob.NewEncoder(buff)

	// Encoding the tree
	err := enc.Encode(t)
	if err != nil {
		return nil, fmt.Errorf("failed to encode tree to buffer: %v", err)
	}

	return buff.Bytes(), nil
}

// Len is used to return the number of elements in the tree
func (t *Tree) Len() int {
	return t.Size
}

// longestPrefix finds the length of the shared prefix
// of two strings
func longestPrefix(k1, k2 string) int {
	max := len(k1)
	if l := len(k2); l < max {
		max = l
	}
	var i int
	for i = 0; i < max; i++ {
		if k1[i] != k2[i] {
			break
		}
	}
	return i
}

// Insert is used to add a newentry or update
// an existing entry. Returns if updated.
func (t *Tree) Insert(s string, v interface{}) (interface{}, bool) {
	var parent *node
	n := t.Root
	search := s
	for {
		// Handle key exhaution
		if len(search) == 0 {
			if n.isLeaf() {
				old := n.Leaf.Val
				n.Leaf.Val = v
				return old, true
			}

			n.Leaf = &leafNode{
				Key: s,
				Val: v,
			}
			t.Size++
			return nil, false
		}

		// Look for the edge
		parent = n
		n = n.getEdge(search[0])

		// No edge, create one
		if n == nil {
			e := edge{
				Label: search[0],
				Node: &node{
					Leaf: &leafNode{
						Key: s,
						Val: v,
					},
					Prefix: search,
				},
			}
			parent.addEdge(e)
			t.Size++
			return nil, false
		}

		// Determine longest prefix of the search key on match
		commonPrefix := longestPrefix(search, n.Prefix)
		if commonPrefix == len(n.Prefix) {
			search = search[commonPrefix:]
			continue
		}

		// Split the node
		t.Size++
		child := &node{
			Prefix: search[:commonPrefix],
		}
		parent.updateEdge(search[0], child)

		// Restore the existing node
		child.addEdge(edge{
			Label: n.Prefix[commonPrefix],
			Node:  n,
		})
		n.Prefix = n.Prefix[commonPrefix:]

		// Create a new leaf node
		leaf := &leafNode{
			Key: s,
			Val: v,
		}

		// If the new key is a subset, add to to this node
		search = search[commonPrefix:]
		if len(search) == 0 {
			child.Leaf = leaf
			return nil, false
		}

		// Create a new edge for the node
		child.addEdge(edge{
			Label: search[0],
			Node: &node{
				Leaf:   leaf,
				Prefix: search,
			},
		})
		return nil, false
	}
}

// Delete is used to delete a key, returning the previous
// value and if it was deleted
func (t *Tree) Delete(s string) (interface{}, bool) {
	var parent *node
	var label byte
	n := t.Root
	search := s
	for {
		// Check for key exhaution
		if len(search) == 0 {
			if !n.isLeaf() {
				break
			}
			goto DELETE
		}

		// Look for an edge
		parent = n
		label = search[0]
		n = n.getEdge(label)
		if n == nil {
			break
		}

		// Consume the search prefix
		if strings.HasPrefix(search, n.Prefix) {
			search = search[len(n.Prefix):]
		} else {
			break
		}
	}
	return nil, false

DELETE:
	// Delete the leaf
	leaf := n.Leaf
	n.Leaf = nil
	t.Size--

	// Check if we should delete this node from the parent
	if parent != nil && len(n.Edges) == 0 {
		parent.delEdge(label)
	}

	// Check if we should merge this node
	if n != t.Root && len(n.Edges) == 1 {
		n.mergeChild()
	}

	// Check if we should merge the parent's other child
	if parent != nil && parent != t.Root && len(parent.Edges) == 1 && !parent.isLeaf() {
		parent.mergeChild()
	}

	return leaf.Val, true
}

// DeletePrefix is used to delete the subtree under a prefix
// Returns how many nodes were deleted
// Use this to delete large subtrees efficiently
func (t *Tree) DeletePrefix(s string) int {
	return t.deletePrefix(nil, t.Root, s)
}

// delete does a recursive deletion
func (t *Tree) deletePrefix(parent, n *node, prefix string) int {
	// Check for key exhaustion
	if len(prefix) == 0 {
		// Remove the leaf node
		subTreeSize := 0
		//recursively walk from all edges of the node to be deleted
		recursiveWalk(n, func(s string, v interface{}) bool {
			subTreeSize++
			return false
		})
		if n.isLeaf() {
			n.Leaf = nil
		}
		n.Edges = nil // deletes the entire subtree

		// Check if we should merge the parent's other child
		if parent != nil && parent != t.Root && len(parent.Edges) == 1 && !parent.isLeaf() {
			parent.mergeChild()
		}
		t.Size -= subTreeSize
		return subTreeSize
	}

	// Look for an edge
	label := prefix[0]
	child := n.getEdge(label)
	if child == nil || (!strings.HasPrefix(child.Prefix, prefix) && !strings.HasPrefix(prefix, child.Prefix)) {
		return 0
	}

	// Consume the search prefix
	if len(child.Prefix) > len(prefix) {
		prefix = prefix[len(prefix):]
	} else {
		prefix = prefix[len(child.Prefix):]
	}
	return t.deletePrefix(n, child, prefix)
}

func (n *node) mergeChild() {
	e := n.Edges[0]
	child := e.Node
	n.Prefix = n.Prefix + child.Prefix
	n.Leaf = child.Leaf
	n.Edges = child.Edges
}

// Get is used to lookup a specific key, returning
// the value and if it was found
func (t *Tree) Get(s string) (interface{}, bool) {
	n := t.Root
	search := s
	for {
		// Check for key exhaution
		if len(search) == 0 {
			if n.isLeaf() {
				return n.Leaf.Val, true
			}
			break
		}

		// Look for an edge
		n = n.getEdge(search[0])
		if n == nil {
			break
		}

		// Consume the search prefix
		if strings.HasPrefix(search, n.Prefix) {
			search = search[len(n.Prefix):]
		} else {
			break
		}
	}
	return nil, false
}

// LongestPrefix is like Get, but instead of an
// exact match, it will return the longest prefix match.
func (t *Tree) LongestPrefix(s string) (string, interface{}, bool) {
	var last *leafNode
	n := t.Root
	search := s
	for {
		// Look for a leaf node
		if n.isLeaf() {
			last = n.Leaf
		}

		// Check for key exhaution
		if len(search) == 0 {
			break
		}

		// Look for an edge
		n = n.getEdge(search[0])
		if n == nil {
			break
		}

		// Consume the search prefix
		if strings.HasPrefix(search, n.Prefix) {
			search = search[len(n.Prefix):]
		} else {
			break
		}
	}
	if last != nil {
		return last.Key, last.Val, true
	}
	return "", nil, false
}

// Minimum is used to return the minimum value in the tree
func (t *Tree) Minimum() (string, interface{}, bool) {
	n := t.Root
	for {
		if n.isLeaf() {
			return n.Leaf.Key, n.Leaf.Val, true
		}
		if len(n.Edges) > 0 {
			n = n.Edges[0].Node
		} else {
			break
		}
	}
	return "", nil, false
}

// Maximum is used to return the maximum value in the tree
func (t *Tree) Maximum() (string, interface{}, bool) {
	n := t.Root
	for {
		if num := len(n.Edges); num > 0 {
			n = n.Edges[num-1].Node
			continue
		}
		if n.isLeaf() {
			return n.Leaf.Key, n.Leaf.Val, true
		}
		break
	}
	return "", nil, false
}

// Walk is used to walk the tree
func (t *Tree) Walk(fn WalkFn) {
	recursiveWalk(t.Root, fn)
}

// WalkPrefix is used to walk the tree under a prefix
func (t *Tree) WalkPrefix(prefix string, fn WalkFn) {
	n := t.Root
	search := prefix
	for {
		// Check for key exhaution
		if len(search) == 0 {
			recursiveWalk(n, fn)
			return
		}

		// Look for an edge
		n = n.getEdge(search[0])
		if n == nil {
			break
		}

		// Consume the search prefix
		if strings.HasPrefix(search, n.Prefix) {
			search = search[len(n.Prefix):]

		} else if strings.HasPrefix(n.Prefix, search) {
			// Child may be under our search prefix
			recursiveWalk(n, fn)
			return
		} else {
			break
		}
	}

}

// WalkPath is used to walk the tree, but only visiting nodes
// from the root down to a given leaf. Where WalkPrefix walks
// all the entries *under* the given prefix, this walks the
// entries *above* the given prefix.
func (t *Tree) WalkPath(path string, fn WalkFn) {
	n := t.Root
	search := path
	for {
		// Visit the leaf values if any
		if n.Leaf != nil && fn(n.Leaf.Key, n.Leaf.Val) {
			return
		}

		// Check for key exhaution
		if len(search) == 0 {
			return
		}

		// Look for an edge
		n = n.getEdge(search[0])
		if n == nil {
			return
		}

		// Consume the search prefix
		if strings.HasPrefix(search, n.Prefix) {
			search = search[len(n.Prefix):]
		} else {
			break
		}
	}
}

// recursiveWalk is used to do a pre-order walk of a node
// recursively. Returns true if the walk should be aborted
func recursiveWalk(n *node, fn WalkFn) bool {
	// Visit the leaf values if any
	if n.Leaf != nil && fn(n.Leaf.Key, n.Leaf.Val) {
		return true
	}

	// Recurse on the children
	for _, e := range n.Edges {
		if recursiveWalk(e.Node, fn) {
			return true
		}
	}
	return false
}

// ToMap is used to walk the tree and convert it into a map
func (t *Tree) ToMap() map[string]interface{} {
	out := make(map[string]interface{}, t.Size)
	t.Walk(func(k string, v interface{}) bool {
		out[k] = v
		return false
	})
	return out
}
