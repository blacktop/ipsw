/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

	Library Author: Nguyen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details
    (c) 2013 COSEINC. All Rights Reserved.
*/

package gapstone

// #cgo LDFLAGS: -lcapstone
// #cgo freebsd CFLAGS: -I/usr/local/include
// #cgo freebsd LDFLAGS: -L/usr/local/lib
// #include <stdlib.h>
// #include <capstone/capstone.h>
import "C"

const (
	// Engine Architectures
	CS_ARCH_ARM        = C.CS_ARCH_ARM        // ARM architecture (including Thumb Thumb-2)
	CS_ARCH_ARM64      = C.CS_ARCH_ARM64      // ARM-64, also called AArch64
	CS_ARCH_MIPS       = C.CS_ARCH_MIPS       // Mips architecture
	CS_ARCH_X86        = C.CS_ARCH_X86        // X86 architecture (including x86 & x86-64)
	CS_ARCH_PPC        = C.CS_ARCH_PPC        // PowerPC architecture
	CS_ARCH_SPARC      = C.CS_ARCH_SPARC      // Sparc architecture
	CS_ARCH_SYSZ       = C.CS_ARCH_SYSZ       // SystemZ architecture
	CS_ARCH_XCORE      = C.CS_ARCH_XCORE      // Xcore architecture
	CS_ARCH_M68K       = C.CS_ARCH_M68K       // 68K architecture
	CS_ARCH_TMS320C64X = C.CS_ARCH_TMS320C64X // TMS320C64x architecture
	CS_ARCH_M680X      = C.CS_ARCH_M680X      // 680X architecture
	CS_ARCH_EVM        = C.CS_ARCH_EVM        // Ethereum architecture
	CS_ARCH_MOS65XX    = C.CS_ARCH_MOS65XX    // MOS65XX architecture (including MOS6502)
	CS_ARCH_WASM       = C.CS_ARCH_WASM       // WebAssembly architecture
	CS_ARCH_BPF        = C.CS_ARCH_BPF        // Berkeley Packet Filter architecture (including eBPF)
	CS_ARCH_RISCV      = C.CS_ARCH_RISCV      // RISCV architecture
	CS_ARCH_MAX        = C.CS_ARCH_MAX
	CS_ARCH_ALL        = C.CS_ARCH_ALL
)

const (
	// Engine modes
	CS_MODE_LITTLE_ENDIAN          = C.CS_MODE_LITTLE_ENDIAN  // little endian mode (default mode)
	CS_MODE_ARM                    = C.CS_MODE_ARM            // 32-bit ARM
	CS_MODE_16                     = C.CS_MODE_16             // 16-bit mode (X86)
	CS_MODE_32                     = C.CS_MODE_32             // 32-bit mode (X86)
	CS_MODE_64                     = C.CS_MODE_64             // 64-bit mode (X86, PPC)
	CS_MODE_THUMB                  = C.CS_MODE_THUMB          // ARM's Thumb mode, including Thumb-2
	CS_MODE_MCLASS                 = C.CS_MODE_MCLASS         // ARM's Cortex-M series
	CS_MODE_V8                     = C.CS_MODE_V8             // ARMv8 A32 encodings for ARM
	CS_MODE_MICRO                  = C.CS_MODE_MICRO          // MicroMips mode (MIPS)
	CS_MODE_MIPS3                  = C.CS_MODE_MIPS3          // Mips III ISA
	CS_MODE_MIPS32R6               = C.CS_MODE_MIPS32R6       // Mips32r6 ISA
	CS_MODE_MIPS2                  = C.CS_MODE_MIPS2          // Mips II ISA
	CS_MODE_V9                     = C.CS_MODE_V9             // SparcV9 mode (Sparc)
	CS_MODE_QPX                    = C.CS_MODE_QPX            // Quad Processing eXtensions mode (PPC)
	CS_MODE_M68K_000               = C.CS_MODE_M68K_000       // M68K 68000 mode
	CS_MODE_M68K_010               = C.CS_MODE_M68K_010       // M68K 68010 mode
	CS_MODE_M68K_020               = C.CS_MODE_M68K_020       // M68K 68020 mode
	CS_MODE_M68K_030               = C.CS_MODE_M68K_030       // M68K 68030 mode
	CS_MODE_M68K_040               = C.CS_MODE_M68K_040       // M68K 68040 mode
	CS_MODE_M68K_060               = C.CS_MODE_M68K_060       // M68K 68060 mode
	CS_MODE_BIG_ENDIAN             = C.CS_MODE_BIG_ENDIAN     // big-endian mode
	CS_MODE_MIPS32                 = C.CS_MODE_MIPS32         // Mips32 ISA (Mips)
	CS_MODE_MIPS64                 = C.CS_MODE_MIPS64         // Mips64 ISA (Mips)
	CS_MODE_M680X_6301             = C.CS_MODE_M680X_6301     // M680X Hitachi 6301,6303 mode
	CS_MODE_M680X_6309             = C.CS_MODE_M680X_6309     // M680X Hitachi 6309 mode
	CS_MODE_M680X_6800             = C.CS_MODE_M680X_6800     // M680X Motorola 6800,6802 mode
	CS_MODE_M680X_6801             = C.CS_MODE_M680X_6801     // M680X Motorola 6801,6803 mode
	CS_MODE_M680X_6805             = C.CS_MODE_M680X_6805     // M680X Motorola/Freescale 6805 mode
	CS_MODE_M680X_6808             = C.CS_MODE_M680X_6808     // M680X Motorola/Freescale/NXP 68HC08 mode
	CS_MODE_M680X_6809             = C.CS_MODE_M680X_6809     // M680X Motorola 6809 mode
	CS_MODE_M680X_6811             = C.CS_MODE_M680X_6811     // M680X Motorola/Freescale/NXP 68HC11 mode
	CS_MODE_M680X_CPU12            = C.CS_MODE_M680X_CPU12    // M680X Motorola/Freescale/NXP CPU12 used on M68HC12/HCS12
	CS_MODE_M680X_HCS08            = C.CS_MODE_M680X_HCS08    // M680X Freescale/NXP HCS08 mode
	CS_MODE_BPF_CLASSIC            = C.CS_MODE_BPF_CLASSIC    // Classic BPF mode (default)
	CS_MODE_BPF_EXTENDED           = C.CS_MODE_BPF_EXTENDED   // Extended BPF mode
	CS_MODE_RISCV32                = C.CS_MODE_RISCV32        // RISCV RV32G
	CS_MODE_RISCV64                = C.CS_MODE_RISCV64        // RISCV RV64G
	CS_MODE_RISCVC                 = C.CS_MODE_RISCVC         // RISCV compressed instructure mode
	CS_MODE_MOS65XX_6502           = C.CS_MODE_MOS65XX_6502   // MOS65XXX MOS 6502
	CS_MODE_MOS65XX_65C02          = C.CS_MODE_MOS65XX_65C02  // MOS65XXX WDC 65c02
	CS_MODE_MOS65XX_W65C02         = C.CS_MODE_MOS65XX_W65C02 // MOS65XXX WDC W65c02
	CS_MODE_MOS65XX_65816          = C.CS_MODE_MOS65XX_65816  // MOS65XXX WDC 65816, 8-bit m/x
	CS_MODE_MOS65XX_65816_LONG_M   = C.CS_MODE_MOS65XX_65816_LONG_M  // MOS65XXX WDC 65816, 16-bit m, 8-bit x
	CS_MODE_MOS65XX_65816_LONG_X   = C.CS_MODE_MOS65XX_65816_LONG_X  // MOS65XXX WDC 65816, 8-bit m, 16-bit x
	CS_MODE_MOS65XX_65816_LONG_MX  = C.CS_MODE_MOS65XX_65816_LONG_MX
)

const (
	// Engine Options types
	CS_OPT_INVALID        = C.CS_OPT_INVALID        // No option specified
	CS_OPT_SYNTAX         = C.CS_OPT_SYNTAX         // Asssembly output syntax
	CS_OPT_DETAIL         = C.CS_OPT_DETAIL         // Break down instruction structure into details
	CS_OPT_MODE           = C.CS_OPT_MODE           // Change engine's mode at run-time
	CS_OPT_MEM            = C.CS_OPT_MEM            // User-defined memory malloc/calloc/free
	CS_OPT_SKIPDATA       = C.CS_OPT_SKIPDATA       // Skip data when disassembling. Then engine is in SKIPDATA mode.
	CS_OPT_SKIPDATA_SETUP = C.CS_OPT_SKIPDATA_SETUP // Setup user-defined function for SKIPDATA option
	CS_OPT_MNEMONIC       = C.CS_OPT_MNEMONIC       // Customize instruction mnemonic
	CS_OPT_UNSIGNED       = C.CS_OPT_UNSIGNED       // print immediate operands in unsigned form
)

const (
	// Engine Options values
	CS_OPT_OFF              = C.CS_OPT_OFF              // Turn OFF an option - default option for CS_OPT_DETAIL.
	CS_OPT_ON               = C.CS_OPT_ON               // Turn ON an option (CS_OPT_DETAIL).
	CS_OPT_SYNTAX_DEFAULT   = C.CS_OPT_SYNTAX_DEFAULT   // Default asm syntax (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_INTEL     = C.CS_OPT_SYNTAX_INTEL     // X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_ATT       = C.CS_OPT_SYNTAX_ATT       // X86 ATT asm syntax (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_NOREGNAME = C.CS_OPT_SYNTAX_NOREGNAME // Prints register name with only number (CS_OPT_SYNTAX)
	CS_OPT_SYNTAX_MASM      = C.CS_OPT_SYNTAX_MASM      // X86 Intel Masm syntax (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_MOTOROLA  = C.CS_OPT_SYNTAX_MOTOROLA  // MOS65XX use $ as hex prefix
)

const (
	// All type of errors encountered by Capstone API.
	// These are values returned by cs_errno()
	CS_ERR_OK        = C.CS_ERR_OK        // No error: everything was fine
	CS_ERR_MEM       = C.CS_ERR_MEM       // Out-Of-Memory error: cs_open(), cs_disasm_ex()
	CS_ERR_ARCH      = C.CS_ERR_ARCH      // Unsupported architecture: cs_open()
	CS_ERR_HANDLE    = C.CS_ERR_HANDLE    // Invalid handle: cs_op_count(), cs_op_index()
	CS_ERR_CSH       = C.CS_ERR_CSH       // Invalid csh argument: cs_close(), cs_errno(), cs_option()
	CS_ERR_MODE      = C.CS_ERR_MODE      // Invalid/unsupported mode: cs_open()
	CS_ERR_OPTION    = C.CS_ERR_OPTION    // Invalid/unsupported option: cs_option()
	CS_ERR_DETAIL    = C.CS_ERR_DETAIL    // Information is unavailable because detail option is OFF
	CS_ERR_MEMSETUP  = C.CS_ERR_MEMSETUP  // Dynamic memory management uninitialized (see CS_OPT_MEM)
	CS_ERR_VERSION   = C.CS_ERR_VERSION   // Unsupported version (bindings)
	CS_ERR_DIET      = C.CS_ERR_DIET      // Information irrelevant in diet engine
	CS_ERR_SKIPDATA  = C.CS_ERR_SKIPDATA  // Access irrelevant data for "data" instruction in SKIPDATA mode
	CS_ERR_X86_ATT   = C.CS_ERR_X86_ATT   // X86 AT&T syntax is unsupported (opt-out at compile time)
	CS_ERR_X86_INTEL = C.CS_ERR_X86_INTEL // X86 Intel syntax is unsupported (opt-out at compile time)
	CS_ERR_X86_MASM  = C.CS_ERR_X86_MASM  // X86 Intel syntax is unsupported (opt-out at compile time)
)

// Common instruction operand types - to be consistent across all architectures.
const (
	CS_OP_INVALID = C.CS_OP_INVALID // uninitialized/invalid operand.
	CS_OP_REG     = C.CS_OP_REG     // Register operand.
	CS_OP_IMM     = C.CS_OP_IMM     // Immediate operand.
	CS_OP_MEM     = C.CS_OP_MEM     // Memory operand.
	CS_OP_FP      = C.CS_OP_FP      // Floating-Point operand.
)

// Common instruction operand access types - to be consistent across all architectures.
// It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
const (
	CS_AC_INVALID = C.CS_AC_INVALID // Uninitialized/invalid access type.
	CS_AC_READ    = C.CS_AC_READ    // Operand read from memory or register.
	CS_AC_WRITE   = C.CS_AC_WRITE   // Operand write to memory or register.
)

// Common instruction groups - to be consistent across all architectures.
const (
	CS_GRP_INVALID         = C.CS_GRP_INVALID         // uninitialized/invalid group.
	CS_GRP_JUMP            = C.CS_GRP_JUMP            // all jump instructions (conditional+direct+indirect jumps)
	CS_GRP_CALL            = C.CS_GRP_CALL            // all call instructions
	CS_GRP_RET             = C.CS_GRP_RET             // all return instructions
	CS_GRP_INT             = C.CS_GRP_INT             // all interrupt instructions (int+syscall)
	CS_GRP_IRET            = C.CS_GRP_IRET            // all interrupt return instructions
	CS_GRP_PRIVILEGE       = C.CS_GRP_PRIVILEGE       ///< all privileged instructions
	CS_GRP_BRANCH_RELATIVE = C.CS_GRP_BRANCH_RELATIVE ///< all relative branching instructions
)

const CS_SUPPORT_DIET = C.CS_SUPPORT_DIET

const CS_SUPPORT_X86_REDUCE = C.CS_SUPPORT_X86_REDUCE
