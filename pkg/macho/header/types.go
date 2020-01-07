package header

//go:generate stringer -type=Type,Flag -output header_string.go

// A Type is the Mach-O file type, e.g. an object file, executable, or dynamic library.
type Type uint32

const (
	Obj        Type = 1
	Exec       Type = 2
	FVMLib     Type = 3
	Core       Type = 4
	Preload    Type = 5 /* preloaded executable file */
	Dylib      Type = 6 /* dynamically bound shared library */
	Dylinker   Type = 7 /* dynamic link editor */
	Bundle     Type = 8
	DylibStub  Type = 0x9 /* shared library stub for static */
	Dsym       Type = 0xa /* companion file with only debug */
	KextBundle Type = 0xb /* x86_64 kexts */
)
