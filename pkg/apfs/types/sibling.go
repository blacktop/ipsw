package types

import (
	"fmt"

	"github.com/fatih/color"
)

// SiblingKeyT is a j_sibling_key_t object
type SiblingKeyT struct {
	// Hdr       JKeyT
	SiblingID uint64
} // __attribute__((packed))

// SiblingValT is a j_sibling_val_t object
type SiblingValT struct {
	ParentID uint64
	NameLen  uint16
	Name     string
} // __attribute__((packed))

func (v SiblingValT) String() string {
	nameColor := color.New(color.Bold, color.FgHiBlue).SprintFunc()
	return fmt.Sprintf("name=%s, parent_id=%#x", nameColor(v.Name), v.ParentID)
}

// SiblingMapKeyT is a j_sibling_map_key_t object
type SiblingMapKeyT struct {
	Hdr JKeyT
} // __attribute__((packed))

// SiblingMapValT is a j_sibling_map_val_t object
type SiblingMapValT struct {
	FileID uint64
} // __attribute__((packed))

func (v SiblingMapValT) String() string {
	return fmt.Sprintf("file_id=%#x", v.FileID)
}
