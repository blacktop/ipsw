package sandbox

import (
	"bytes"
	"sort"
)

// LongestCommonSubstring returns the longest substring which is present in all the given strings.
// https://en.wikipedia.org/wiki/Longest_common_substring_problem
// Not to be confused with the Longest Common Subsequence.
// Complexity:
// * time: sum of `n_i*log(n_i)` where `n_i` is the length of each string.
// * space: sum of `n_i`.
// Returns a byte slice which is never a nil.
//
// ### Algorithm.
// We build suffix arrays for each of the passed string and then follow the same procedure
// as in merge sort: pick the least suffix in the lexicographical order. It is possible
// because the suffix arrays are already sorted.
// We record the last encountered suffixes from each of the strings and measure the longest
// common prefix of those at each "merge sort" step.
// The string comparisons are optimized by maintaining the char-level prefix tree of the "heads"
// of the suffix array sequences.
func LongestCommonSubstring(strs []string) []byte {
	var bystrs [][]byte
	for _, str := range strs {
		bystrs = append(bystrs, []byte(str))
	}
	strslen := len(bystrs)
	if strslen == 0 {
		return []byte{}
	}
	if strslen == 1 {
		return bystrs[0]
	}
	suffixes := make([][]int, strslen)
	for i, str := range bystrs {
		suffixes[i] = Qsufsort(str) // stdlib's qsufsort
	}
	return LongestCommonSubstringWithSuffixArrays(bystrs, suffixes)
}

// LongestCommonSubstringWithSuffixArrays returns the longest substring which is present in all
// the given strings. The corresponding suffix arrays must be precomputed with `lcss.Qsufsort`.
// https://en.wikipedia.org/wiki/Longest_common_substring_problem
// Not to be confused with the Longest Common Subsequence.
// Complexity:
// * time: sum of the string lengths.
// * space: sum of the string lengths.
// Returns a byte slice which is never a nil.
//
// ### Algorithm.
// We follow the same procedure as in merge sort: pick the least suffix in the lexicographical
// order. It is possible because the suffix arrays are already sorted.
// We record the last encountered suffixes from each of the strings and measure the longest
// common prefix of those at each "merge sort" step. The string comparisons are optimized by
// maintaining the char-level prefix tree of the "heads" of the suffix array sequences.
func LongestCommonSubstringWithSuffixArrays(strs [][]byte, suffixes [][]int) []byte {
	strslen := len(strs)
	if strslen != len(suffixes) {
		panic("the suffix array must be computed with lcss.Qsufsort for each string")
	}
	if strslen == 0 {
		return []byte{}
	}
	if strslen == 1 {
		return strs[0]
	}
	minstrlen := len(strs[0]) // minimum length of the strings
	for i, str := range strs {
		if len(str) != len(suffixes[i]) {
			panic("each suffix array must be exactly the same length as the corresponding string")
		}
		if minstrlen > len(str) {
			minstrlen = len(str)
		}
	}
	heads := make([]int, strslen)          // position in each suffix array
	boilerplate := make([][]byte, strslen) // existing suffixes in the tree
	boiling := 0                           // indicates how many distinct suffix arrays are presented in `boilerplate`
	var root charNode                      // the character tree built on the strings from `boilerplate`
	lcs := []byte{}                        // our function's return value, `var lcss []byte` does *not* work
	for {
		mini := -1
		var minSuffixStr []byte
		for i, head := range heads {
			if head >= len(suffixes[i]) {
				// this suffix array has been scanned till the end
				continue
			}
			suffix := strs[i][suffixes[i][head]:]
			if minSuffixStr == nil {
				// initialize
				mini = i
				minSuffixStr = suffix
			} else if bytes.Compare(minSuffixStr, suffix) > 0 {
				// the current suffix is the smallest in the lexicographical order
				mini = i
				minSuffixStr = suffix
			}
		}
		if mini == -1 {
			// all heads exhausted
			break
		}
		if boilerplate[mini] != nil {
			// if we already have a suffix from this string, replace it with the new one
			root.Remove(boilerplate[mini])
		} else {
			// we track the number of distinct strings which have been touched
			// when `boiling` becomes strslen we can start measuring the longest common prefix
			boiling++
		}
		boilerplate[mini] = minSuffixStr
		root.Add(minSuffixStr)
		heads[mini]++
		if boiling == strslen && root.LongestCommonPrefixLength() > len(lcs) {
			// all heads > 0, the current common prefix of the suffixes is the longest
			lcs = root.LongestCommonPrefix()
			if len(lcs) == minstrlen {
				// early exit - we will never find a longer substring
				break
			}
		}
	}
	return lcs
}

// charNode builds a tree of individual characters.
// `used` is the counter for collecting garbage: those nodes which have `used`=0 are removed.
// The root charNode always remains intact apart from `children`.
// The tree supports 4 operations:
// 1. Add() a new string.
// 2. Remove() an existing string which was previously Add()-ed.
// 3. LongestCommonPrefixLength().
// 4. LongestCommonPrefix().
type charNode struct {
	char     byte
	children []charNode
	used     int
}

// Add includes a new string into the tree. We start from the root and
// increment `used` of all the nodes we visit.
func (cn *charNode) Add(str []byte) {
	head := cn
	for i, char := range str {
		found := false
		for j, child := range head.children {
			if child.char == char {
				head.children[j].used++
				head = &head.children[j] // -> child
				found = true
				break
			}
		}
		if !found {
			// add the missing nodes one by one
			for _, char = range str[i:] {
				head.children = append(head.children, charNode{char: char, children: nil, used: 1})
				head = &head.children[len(head.children)-1]
			}
			break
		}
	}
}

// Remove excludes a node which was previously Add()-ed.
// We start from the root and decrement `used` of all the nodes we visit.
// If there is a node with `used`=0, we erase it from the parent's list of children
// and stop traversing the tree.
func (cn *charNode) Remove(str []byte) {
	stop := false
	head := cn
	for _, char := range str {
		for j, child := range head.children {
			if child.char != char {
				continue
			}
			head.children[j].used--
			var parent *charNode
			head, parent = &head.children[j], head // shift to the child
			if head.used == 0 {
				parent.children = append(parent.children[:j], parent.children[j+1:]...)
				// we can skip deleting the rest of the nodes - they have been already discarded
				stop = true
			}
			break
		}
		if stop {
			break
		}
	}
}

// LongestCommonPrefixLength returns the length of the longest common prefix of the strings
// which are stored in the tree. We visit the children recursively starting from the root and
// stop if `used` value decreases or there is more than one child.
func (cn charNode) LongestCommonPrefixLength() int {
	var result int
	for head := cn; len(head.children) == 1 && head.children[0].used >= head.used; head = head.children[0] {

		result++
	}
	return result
}

// LongestCommonPrefix returns the longest common prefix of the strings
// which are stored in the tree. We compute the length by calling LongestCommonPrefixLength()
// and then record the characters which we visit along the way from the root to the last node.
func (cn charNode) LongestCommonPrefix() []byte {
	result := make([]byte, cn.LongestCommonPrefixLength())
	if len(result) == 0 {
		return result
	}
	var i int
	for head := cn.children[0]; ; head = head.children[0] {
		result[i] = head.char
		i++
		if i == len(result) {
			break
		}
	}
	return result
}

// Qsufsort constructs the suffix array for a given string.
func Qsufsort(data []byte) []int {
	// initial sorting by first byte of suffix
	sa := sortedByFirstByte(data)
	if len(sa) < 2 {
		return sa
	}
	// initialize the group lookup table
	// this becomes the inverse of the suffix array when all groups are sorted
	inv := initGroups(sa, data)

	// the index starts 1-ordered
	sufSortable := &suffixSortable{sa: sa, inv: inv, h: 1}

	for sa[0] > -len(sa) { // until all suffixes are one big sorted group
		// The suffixes are h-ordered, make them 2*h-ordered
		pi := 0 // pi is first position of first group
		sl := 0 // sl is negated length of sorted groups
		for pi < len(sa) {
			if s := sa[pi]; s < 0 { // if pi starts sorted group
				pi -= s // skip over sorted group
				sl += s // add negated length to sl
			} else { // if pi starts unsorted group
				if sl != 0 {
					sa[pi+sl] = sl // combine sorted groups before pi
					sl = 0
				}
				pk := inv[s] + 1 // pk-1 is last position of unsorted group
				sufSortable.sa = sa[pi:pk]
				sort.Sort(sufSortable)
				sufSortable.updateGroups(pi)
				pi = pk // next group
			}
		}
		if sl != 0 { // if the array ends with a sorted group
			sa[pi+sl] = sl // combine sorted groups at end of sa
		}

		sufSortable.h *= 2 // double sorted depth
	}

	for i := range sa { // reconstruct suffix array from inverse
		sa[inv[i]] = i
	}
	return sa
}

func sortedByFirstByte(data []byte) []int {
	// total byte counts
	var count [256]int
	for _, b := range data {
		count[b]++
	}
	// make count[b] equal index of first occurrence of b in sorted array
	sum := 0
	for b := range count {
		count[b], sum = sum, count[b]+sum
	}
	// iterate through bytes, placing index into the correct spot in sa
	sa := make([]int, len(data))
	for i, b := range data {
		sa[count[b]] = i
		count[b]++
	}
	return sa
}

func initGroups(sa []int, data []byte) []int {
	// label contiguous same-letter groups with the same group number
	inv := make([]int, len(data))
	prevGroup := len(sa) - 1
	groupByte := data[sa[prevGroup]]
	for i := len(sa) - 1; i >= 0; i-- {
		if b := data[sa[i]]; b < groupByte {
			if prevGroup == i+1 {
				sa[i+1] = -1
			}
			groupByte = b
			prevGroup = i
		}
		inv[sa[i]] = prevGroup
		if prevGroup == 0 {
			sa[0] = -1
		}
	}
	// Separate out the final suffix to the start of its group.
	// This is necessary to ensure the suffix "a" is before "aba"
	// when using a potentially unstable sort.
	lastByte := data[len(data)-1]
	s := -1
	for i := range sa {
		if sa[i] >= 0 {
			if data[sa[i]] == lastByte && s == -1 {
				s = i
			}
			if sa[i] == len(sa)-1 {
				sa[i], sa[s] = sa[s], sa[i]
				inv[sa[s]] = s
				sa[s] = -1 // mark it as an isolated sorted group
				break
			}
		}
	}
	return inv
}

type suffixSortable struct {
	sa  []int
	inv []int
	h   int
	buf []int // common scratch space
}

func (x *suffixSortable) Len() int           { return len(x.sa) }
func (x *suffixSortable) Less(i, j int) bool { return x.inv[x.sa[i]+x.h] < x.inv[x.sa[j]+x.h] }
func (x *suffixSortable) Swap(i, j int)      { x.sa[i], x.sa[j] = x.sa[j], x.sa[i] }

func (x *suffixSortable) updateGroups(offset int) {
	bounds := x.buf[0:0]
	group := x.inv[x.sa[0]+x.h]
	for i := 1; i < len(x.sa); i++ {
		if g := x.inv[x.sa[i]+x.h]; g > group {
			bounds = append(bounds, i)
			group = g
		}
	}
	bounds = append(bounds, len(x.sa))
	x.buf = bounds

	// update the group numberings after all new groups are determined
	prev := 0
	for _, b := range bounds {
		for i := prev; i < b; i++ {
			x.inv[x.sa[i]] = offset + b - 1
		}
		if b-prev == 1 {
			x.sa[prev] = -1
		}
		prev = b
	}
}
