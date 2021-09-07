package types

import (
	"fmt"
	"sort"
	"strings"
)

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
func (recs FSRecords) Tree() FSTree {
	var t FSTree
	var fs []string
	for _, rec := range recs {
		switch rec.Hdr.GetType() {
		case APFS_TYPE_DIR_REC:
			fs = append(fs, rec.Key.(JDrecHashedKeyT).Name)
		case APFS_TYPE_INODE:
			for _, xf := range rec.Val.(j_inode_val).Xfields {
				if xf.XType == INO_EXT_TYPE_NAME {
					if xf.Field.(string) == "root" {
						t = NewFSTree("/")
					} else {
						t = NewFSTree(xf.Field.(string))
					}
				}
			}
		}
	}
	sort.Strings(fs)
	for _, f := range fs {
		t.Add(f)
	}
	return t
}

func (recs FSRecords) String() string {
	var fs []string
	for _, rec := range recs {
		switch rec.Hdr.GetType() {
		case APFS_TYPE_DIR_REC:
			name := rec.Key.(JDrecHashedKeyT).Name
			if rec.Val.(JDrecVal).Flags == DT_DIR {
				name = dirColor(name)
			}
			fs = append(fs, fmt.Sprintf("%s - %s - %s\n",
				rec.Val.(JDrecVal).Flags.String(),
				rec.Val.(JDrecVal).DateAdded,
				name,
			))
		}
	}
	sort.Strings(fs)
	return strings.Join(fs, "")
}
