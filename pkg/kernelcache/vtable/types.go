package vtable

import (
	"github.com/blacktop/go-macho"
)

// Analysis constants
const (
	MinConstructorCallThreshold = 10   // Minimum calls to consider a function as constructor
	MaxFunctionSizeForEmulation = 4096 // Maximum function size to emulate (4KB)
)

// ClassMeta represents metadata for a C++ class discovered in the kernelcache
type ClassMeta struct {
	Name        string       // Class name (e.g., "IOService")
	Size        uint32       // Size of class instances in bytes
	MetaPtr     uint64       // Address of the OSMetaClass object for this class
	SuperMeta   uint64       // Address of superclass's meta (0 if none)
	SuperClass  *ClassMeta   // Pointer to parent class (resolved later)
	AllocFunc   uint64       // Address of the alloc function
	VtableAddr  uint64       // Address of the class's vtable
	Methods     []MethodInfo // Virtual methods in the vtable
	DiscoveryPC uint64       // PC where this class was discovered
	Bundle      string       // Bundle/kext this class belongs to
}

// MethodInfo represents a virtual method in a class vtable
type MethodInfo struct {
	Address uint64 // Function address
	Name    string // Method name (if known)
	Index   int    // Position in vtable
}

// Ring buffer for tracking unresolved X1 sites
type rbEntry struct {
	CallAddr uint64
	FnStart  uint64
	Context  []uint32 // last 16 instr words
}

type ringBuffer struct {
	buf []rbEntry
	i   int
}

func newRB(n int) *ringBuffer {
	return &ringBuffer{buf: make([]rbEntry, n)}
}

func (r *ringBuffer) push(e rbEntry) {
	r.buf[r.i%len(r.buf)] = e
	r.i++
}

// Per-function linear trace cache
type traceOut struct {
	X0, X2, X3 uint64
	ClassName  string
	ok         bool
}

// Discovery counters for diagnostics
type discoveryCounters struct {
	TotalBLInstructions    int // Total BL/B instructions encountered
	TotalBLRInstructions   int // Total BLR/BLRAA instructions encountered
	AcceptedBL             int // BL calls accepted as constructors
	AcceptedBLR            int // BLR/BLRAA calls accepted as constructors
	RejectedTargetNotInSet int // Rejected: target not in constructor set
	RejectedX1NotKnown     int // Rejected: X1 name extraction failed
	RejectedDerefFailed    int // Rejected: GOT/const slot dereference failed
	SymbolFallbackUsed     int // Symbol table fallback used
}

// ClassInfo holds extracted class information from constructor analysis
type ClassInfo struct {
	ClassName string
	ClassSize uint32
	MetaPtr   uint64
	SuperMeta uint64
}

// VtableSymbolicator handles C++ vtable symbolication for iOS kernelcache
type VtableSymbolicator struct {
	file                 *macho.File
	classes              map[uint64]*ClassMeta        // keyed by MetaPtr
	classByName          map[string]*ClassMeta        // keyed by class name
	constructorAddr      uint64                       // OSMetaClass constructor address
	constructorTargetSet map[uint64]bool              // All valid constructor entry points (direct + indirect)
	symbolMap            map[uint64]string            // External symbol map for method names
	stringMap            map[string]map[string]uint64 // String to address map for known class names
	// Production hardening features
	unresolvedRB *ringBuffer         // Ring buffer for unresolved X1 sites
	fnTraceCache map[uint64]traceOut // Per-function linear trace cache
	counters     discoveryCounters   // Discovery counters for diagnostics
}
