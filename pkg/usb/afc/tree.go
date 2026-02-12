package afc

import (
	"strings"
)

// CREDIT: https://github.com/d6o/GoTree

const (
	newLine      = "\n"
	emptySpace   = "    "
	middleItem   = "├── "
	continueItem = "│   "
	lastItem     = "└── "
)

type (
	tree struct {
		path  string
		text  string
		items []Tree
	}

	// Tree is tree interface
	Tree interface {
		Add(dir, text string) Tree
		AddTree(tree Tree)
		Items() []Tree
		HasItem(text string) bool
		Text() string
		Path() string
		Print() string
		Find(path string) Tree
	}

	printer struct {
	}

	// Printer is printer interface
	Printer interface {
		Print(Tree) string
	}
)

// NewTree returns a new GoTree.Tree
func NewTree(path, text string) Tree {
	return &tree{
		path:  path,
		text:  text,
		items: []Tree{},
	}
}

// Add adds a node to the tree
func (t *tree) Add(dir, text string) Tree {
	n := NewTree(dir, text)
	t.items = append(t.items, n)
	return n
}

// AddTree adds a tree as an item
func (t *tree) AddTree(tree Tree) {
	t.items = append(t.items, tree)
}

// Text returns the node's value
func (t *tree) Text() string {
	return t.text
}

// Dir returns the node's absolute path
func (t *tree) Path() string {
	return t.path
}

// Items returns all items in the tree
func (t *tree) Items() []Tree {
	return t.items
}

// HasItem returns true if Tree contains item
func (t *tree) HasItem(item string) bool {
	for _, i := range t.items {
		if item == i.Text() {
			return true
		}
	}
	return false
}

func (t *tree) Find(path string) Tree {
	for _, i := range t.items {
		if i.Path() == path {
			return i
		} else {
			if found := i.Find(path); found != nil {
				return found
			}
		}
	}
	return nil
}

// Print returns an visual representation of the tree
func (t *tree) Print() string {
	return newPrinter().Print(t)
}

func newPrinter() Printer {
	return &printer{}
}

// Print prints a tree to a string
func (p *printer) Print(t Tree) string {
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

	var out strings.Builder
	lines := strings.Split(text, "\n")
	for i := range lines {
		text := lines[i]
		if i == 0 {
			out.WriteString(result + indicator + text + newLine)
			continue
		}
		if last {
			indicator = emptySpace
		} else {
			indicator = continueItem
		}
		out.WriteString(result + indicator + text + newLine)
	}

	return out.String()
}

func (p *printer) printItems(t []Tree, spaces []bool) string {
	var result strings.Builder
	for i, f := range t {
		last := i == len(t)-1
		result.WriteString(p.printText(f.Text(), spaces, last))
		if len(f.Items()) > 0 {
			spacesChild := append(spaces, last)
			result.WriteString(p.printItems(f.Items(), spacesChild))
		}
	}
	return result.String()
}
