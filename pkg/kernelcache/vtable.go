package kernelcache

import (
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache/vtable"
)

// Type aliases for the new modular implementation
type ClassMeta = vtable.ClassMeta
type MethodInfo = vtable.MethodInfo
type VtableSymbolicator = vtable.VtableSymbolicator

// NewVtableSymbolicator creates a new vtable symbolicator using the modular implementation
func NewVtableSymbolicator(file *macho.File) *VtableSymbolicator {
	return vtable.NewVtableSymbolicator(file)
}
