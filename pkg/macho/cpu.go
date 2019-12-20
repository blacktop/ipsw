package macho

// A Cpu is a Mach-O cpu type.
type Cpu uint32

const (
	cpuArch64   = 0x01000000 // 64 bit ABI
	cpuArch6432 = 0x02000000 // ABI for 64-bit hardware with 32-bit types; LP32
)

const (
	Cpu386     Cpu = 7
	CpuAmd64   Cpu = Cpu386 | cpuArch64
	CpuArm     Cpu = 12
	CpuArm64   Cpu = CpuArm | cpuArch64
	CpuArm6432     = CpuArm | cpuArch6432
	CpuPpc     Cpu = 18
	CpuPpc64   Cpu = CpuPpc | cpuArch64
)

var cpuStrings = []intName{
	{uint32(Cpu386), "Cpu386"},
	{uint32(CpuAmd64), "CpuAmd64"},
	{uint32(CpuArm), "CpuArm"},
	{uint32(CpuArm64), "CpuArm64"},
	{uint32(CpuPpc), "CpuPpc"},
	{uint32(CpuPpc64), "CpuPpc64"},
}

func (i Cpu) String() string   { return stringName(uint32(i), cpuStrings, false) }
func (i Cpu) GoString() string { return stringName(uint32(i), cpuStrings, true) }

type CpuSubtypeX86 uint32

const (
	// X86 subtypes
	CpuSubtypeX86All    CpuSubtypeX86 = 3
	CpuSubtypeX86_64All CpuSubtypeX86 = 3
	CpuSubtypeX86Arch1  CpuSubtypeX86 = 4
	CpuSubtypeX86_64H   CpuSubtypeX86 = 8
)

type CpuSubtypeArm uint32

const (
	// ARM subtypes
	CpuSubtypeArmAll    CpuSubtypeArm = 0
	CpuSubtypeArmV4T    CpuSubtypeArm = 5
	CpuSubtypeArmV6     CpuSubtypeArm = 6
	CpuSubtypeArmV5Tej  CpuSubtypeArm = 7
	CpuSubtypeArmXscale CpuSubtypeArm = 8
	CpuSubtypeArmV7     CpuSubtypeArm = 9
	CpuSubtypeArmV7F    CpuSubtypeArm = 10
	CpuSubtypeArmV7S    CpuSubtypeArm = 11
	CpuSubtypeArmV7K    CpuSubtypeArm = 12
	CpuSubtypeArmV8     CpuSubtypeArm = 13
	CpuSubtypeArmV6M    CpuSubtypeArm = 14
	CpuSubtypeArmV7M    CpuSubtypeArm = 15
	CpuSubtypeArmV7Em   CpuSubtypeArm = 16
	CpuSubtypeArmV8M    CpuSubtypeArm = 17
)

type CpuSubtypeArm64 uint32

const (
	// ARM64 subtypes
	CpuSubtypeArm64All CpuSubtypeArm64 = 0
	CpuSubtypeArm64V8  CpuSubtypeArm64 = 1
	CpuSubtypeArm64E   CpuSubtypeArm64 = 2
)
