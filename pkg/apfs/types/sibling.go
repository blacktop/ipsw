package types

// SiblingKeyT is a j_sibling_key_t object
type SiblingKeyT struct {
	// Hdr       JKeyT
	SiblingID uint64
} // __attribute__((packed))

// SiblingValT is a j_sibling_val_t object
type SiblingValT struct {
	ParentID uint64
	NameLen  uint16
	Name     [0]uint8
} // __attribute__((packed))

// SiblingMapKeyT is a j_sibling_map_key_t object
type SiblingMapKeyT struct {
	Hdr JKeyT
} // __attribute__((packed))

// SiblingMapValT is a j_sibling_map_val_t object
type SiblingMapValT struct {
	FileID uint64
} // __attribute__((packed))
