package macho

// A Type is the Mach-O file type, e.g. an object file, executable, or dynamic library.
type Type uint32

const (
	TypeObj        Type = 1
	TypeExec       Type = 2
	TypeFVMLib     Type = 3
	TypeCore       Type = 4
	TypePreload    Type = 5 /* preloaded executable file */
	TypeDylib      Type = 6 /* dynamically bound shared library */
	TypeDylinker   Type = 7 /* dynamic link editor */
	TypeBundle     Type = 8
	TypeDylibStub  Type = 0x9 /* shared library stub for static */
	TypeDsym       Type = 0xa /* companion file with only debug */
	TypeKextBundle Type = 0xb /* x86_64 kexts */
)

var typeStrings = []intName{
	{uint32(TypeObj), "Obj"},
	{uint32(TypeExec), "Exec"},
	{uint32(TypeFVMLib), "FVMLib"},
	{uint32(TypeCore), "Core"},
	{uint32(TypePreload), "Preload"},
	{uint32(TypeDylib), "Dylib"},
	{uint32(TypeDylinker), "Dylinker"},
	{uint32(TypeBundle), "Bundle"},
	{uint32(TypeDylibStub), "DylibStub"},
	{uint32(TypeDsym), "Dsym"},
	{uint32(TypeKextBundle), "KextBundle"},
}

func (t Type) String() string   { return stringName(uint32(t), typeStrings, false) }
func (t Type) GoString() string { return stringName(uint32(t), typeStrings, true) }
