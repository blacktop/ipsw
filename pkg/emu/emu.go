//go:build unicorn

package emu

//go:generate go tool stringer -type=interrupt,branchType,pstateMode -tags=unicorn -output emu_string.go

import (
	"fmt"
	"reflect"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/dyld"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

const (
	stack_address      = 0x7ffcf0000000
	stack_size         = 0x19a00000
	vmmap_trap_address = 0x4000000f4000
	mmap_address       = 0x7ffbf0100000
	heap_address       = 0x500000000
	heap_size          = 0x5000000

	STACK_BASE   = 0x60000000
	STACK_GUARD  = STACK_BASE + 0x1000
	STACK_DATA   = STACK_GUARD + 0x1000
	STACK_SIZE   = 0x800000
	UC_MEM_ALIGN = 0x1000
)

type branchType uint8

const (
	DIRCALL   branchType = iota + 1 // Direct Branch with link
	INDCALL                         // Indirect Branch with link
	ERET                            // Exception return (indirect)
	DBGEXIT                         // Exit from Debug state
	RET                             // Indirect branch with function return hint
	DIR                             // Direct branch
	INDIR                           // Indirect branch
	EXCEPTION                       // Exception entry
	RESET                           // Reset
	UNKNOWN                         // Other
)

type pstateMode uint8

const (
	EL3h pstateMode = 13
	EL3t pstateMode = 12
	EL2h pstateMode = 9
	EL2t pstateMode = 8
	EL1h pstateMode = 5
	EL1t pstateMode = 4
	EL0t pstateMode = 0
)

type interrupt uint32

const (
	EXCP_UNDEFINED_INSTRUCTION interrupt = 1 /* undefined instruction */
	EXCP_SOFTWARE_INTRPT       interrupt = 2 /* software interrupt */
	EXCP_PREFETCH_ABORT        interrupt = 3
	EXCP_DATA_ABORT            interrupt = 4
	EXCP_IRQ                   interrupt = 5
	EXCP_FIQ                   interrupt = 6
	EXCP_BKPT                  interrupt = 7
	EXCP_EXCEPTION_EXIT        interrupt = 8  /* Return from v7M exception.  */
	EXCP_KERNEL_TRAP           interrupt = 9  /* Jumped to kernel code page.  */
	EXCP_HVC                   interrupt = 11 /* HyperVisor Call */
	EXCP_HYP_TRAP              interrupt = 12
	EXCP_SMC                   interrupt = 13 /* Secure Monitor Call */
	EXCP_VIRQ                  interrupt = 14
	EXCP_VFIQ                  interrupt = 15
	EXCP_SEMIHOST              interrupt = 16 /* semihosting call */
	EXCP_NOCP                  interrupt = 17 /* v7M NOCP UsageFault */
	EXCP_INVSTATE              interrupt = 18 /* v7M INVSTATE UsageFault */
	EXCP_STKOF                 interrupt = 19 /* v8M STKOF UsageFault */
	EXCP_LAZYFP                interrupt = 20 /* v7M fault during lazy FP stacking */
	EXCP_LSERR                 interrupt = 21 /* v8M LSERR SecureFault */
	EXCP_UNALIGNED             interrupt = 22 /* v7M UNALIGNED UsageFault */
)

// Config is a emulation configuration object
type Config struct {
	Verbose bool
}

// Emulation is a dyld emulation object
type Emulation struct {
	mu    uc.Unicorn
	cache *dyld.File
	conf  *Config
	// init
	startAddr uint64
	count     uint64
	code      []byte
	instr     []byte
	// state
	regs            Registers
	stack_chk_guard uint64
}

// NewEmulation creates a new emuluation instance
func NewEmulation(cache *dyld.File, conf *Config) (*Emulation, error) {
	var err error

	e := &Emulation{
		cache: cache,
		conf:  conf,
		regs:  InitRegisters(),
	}

	e.mu, err = uc.NewUnicorn(uc.ARCH_ARM64, uc.MODE_ARM)
	if err != nil {
		return nil, fmt.Errorf("failed to create new unicorn instance: %v", err)
	}
	if err := e.mu.SetCPUModel(uc.CPU_ARM64_MAX); err != nil {
		return nil, fmt.Errorf("failed to set cpu model to CPU_AARCH64_MAX: %v", err)
	}
	if err := e.mu.RegWrite(uc.ARM64_REG_PSTATE, 0); err != nil {
		return nil, fmt.Errorf("failed to init PSTATE register: %v", err)
	}
	if err := e.mu.RegWrite(uc.ARM64_REG_TPIDRRO_EL0, STACK_DATA); err != nil {
		return nil, fmt.Errorf("failed to init tpidrro_el0 register: %v", err)
	}
	// enable vfp
	cpacrEL1, err := e.mu.RegRead(uc.ARM64_REG_CPACR_EL1)
	if err != nil {
		return nil, fmt.Errorf("failed to read cpacr_el1 register: %v", err)
	}
	if err := e.mu.RegWrite(uc.ARM64_REG_CPACR_EL1, cpacrEL1|0x300000); err != nil {
		return nil, fmt.Errorf("failed to enable vfp: %v", err)
	}
	return e, nil
}

func (e *Emulation) Close() error {
	return e.mu.Close()
}

// InitStack initialize stack to 8MBs
func (e *Emulation) InitStack() error {

	if err := e.mu.MemMap(STACK_BASE, STACK_SIZE); err != nil {
		return fmt.Errorf("failed to memmap stack at %#x: %v", STACK_BASE, err)
	}
	if err := e.mu.RegWrite(uc.ARM64_REG_SP, STACK_BASE+STACK_SIZE); err != nil {
		return fmt.Errorf("failed to set SP register to %#x: %v", STACK_BASE+STACK_SIZE, err)
	}
	if err := e.PutPointer(STACK_GUARD, GetRandomUint64(), 8); err != nil {
		return fmt.Errorf("failed to write random ___stack_chk_guard @ %#x: %v", STACK_GUARD, err)
	}

	stack_chk_guardAddr, libsystemC, err := e.cache.GetSymbolAddress("___stack_chk_guard") // "libsystem_c.dylib"
	if err != nil {
		return fmt.Errorf("failed to get address of ___stack_chk_guard: %v", err)
	}

	e.stack_chk_guard = stack_chk_guardAddr

	lsC, err := libsystemC.GetPartialMacho()
	if err != nil {
		return err
	}
	defer lsC.Close()

	for _, seg := range lsC.Segments() {
		if seg.Memsz == 0 || seg.Name != "__DATA_DIRTY" {
			continue
		}
		a, s := Align(seg.Addr, seg.Memsz, true)
		if err := e.mu.MemMap(a, s); err != nil {
			return fmt.Errorf("failed to memmap libsystem_c.dylib segment %s at %#x: %v", seg.Name, a, err)
		}
		off, err := lsC.GetOffset(seg.Addr)
		if err != nil {
			return fmt.Errorf("failed to get offset for %s: %v", seg.Name, err)
		}
		segData := make([]byte, seg.Filesz)
		if _, err := lsC.ReadAt(segData, int64(off)); err != nil {
			return fmt.Errorf("failed to read libsystem_c.dylib segment %s data: %v", seg.Name, err)
		}
		if err := e.mu.MemWrite(seg.Addr, segData); err != nil {
			return fmt.Errorf("failed to write libsystem_c.dylib segment %s data: %v", seg.Name, err)
		}
	}
	if err := e.PutPointer(e.stack_chk_guard, STACK_GUARD, 8); err != nil { // 0x1da0b1c78 ??
		return fmt.Errorf("failed to write ___stack_chk_guard ptr @ %#x: %v", e.stack_chk_guard, err)
	}

	return nil
}

// SetupHooks adds all the unicorn hooks
func (e *Emulation) SetupHooks() error {
	//********************************
	//* HOOK_MEM_READ|HOOK_MEM_WRITE *
	//********************************
	if _, err := e.mu.HookAdd(uc.HOOK_MEM_READ|uc.HOOK_MEM_WRITE, func(mu uc.Unicorn, access int, addr64 uint64, size int, value int64) {
		switch access {
		case uc.MEM_READ:
			fmt.Print(colorHook("[MEM_READ]"))
			if ptr, err := e.cache.ReadPointerAtAddress(addr64); err == nil {
				if ptr != e.cache.SlideInfo.SlidePointer(ptr) { // FIXME: this could fail when reading NON-pointers (we should use slide-info)
					e.PutPointer(addr64, e.cache.SlideInfo.SlidePointer(ptr), 8)
				}
			}
			if addr64 == e.stack_chk_guard { // repair stack guard if it's been overwritten for some reason
				if err := e.PutPointer(e.stack_chk_guard, STACK_GUARD, 8); err != nil {
					log.Errorf("failed to write ___stack_chk_guard ptr @ %#x: %v", e.stack_chk_guard, err)
				}
			}
		case uc.MEM_WRITE:
			fmt.Print(colorHook("[MEM_WRITE]"))
		}
		fmt.Printf(colorDetails(" addr: %#x, size: %d, value: %#x\n", addr64, size, value))
	}, 1, 0); err != nil {
		return fmt.Errorf("failed to register r/w hook: %v", err)
	}
	//***********************************************************************
	//* HOOK_MEM_READ_INVALID|HOOK_MEM_WRITE_INVALID|HOOK_MEM_FETCH_INVALID *
	//***********************************************************************
	if _, err := e.mu.HookAdd(uc.HOOK_MEM_READ_INVALID|uc.HOOK_MEM_WRITE_INVALID|uc.HOOK_MEM_FETCH_INVALID,
		func(mu uc.Unicorn, access int, addr uint64, size int, value int64) bool {
			switch access {
			case uc.MEM_WRITE_UNMAPPED:
				fmt.Print(colorHook("[MEM_WRITE_UNMAPPED]"))
			case uc.MEM_WRITE_PROT:
				fmt.Print(colorHook("[MEM_WRITE_PROT]"))
			case uc.MEM_READ_UNMAPPED:
				fmt.Print(colorHook("[MEM_READ_UNMAPPED]"))
				addr = e.cache.SlideInfo.SlidePointer(addr)
				uuid, off, err := e.cache.GetOffset(e.cache.SlideInfo.SlidePointer(addr))
				if err != nil {
					if ptr, err := e.cache.ReadPointerAtAddress(addr); err == nil { // try as a pointer
						uuid, off, err = e.cache.GetOffset(e.cache.SlideInfo.SlidePointer(ptr))
						if err != nil {
							log.Errorf("failed to map memory for address %#x (or pointer %#x): %v", addr, ptr, err)
						}
						addr = ptr
					}
					return false
				}
				dat, err := e.cache.ReadBytesForUUID(uuid, int64(off), UC_MEM_ALIGN)
				if err != nil {
					log.Errorf(err.Error())
					return false
				}
				a, sz := Align(addr, uint64(len(dat)), true)
				if err := e.mu.MemMap(a, sz); err != nil {
					log.Errorf("failed to memmap at %#x: %v", a, err)
					return false
				}
				if err := e.mu.MemWrite(addr, dat); err != nil {
					log.Errorf("failed to mem write at %#x: %v", addr, err)
					return false
				}
				image, err := e.cache.GetImageContainingVMAddr(addr)
				if err != nil {
					if ptr, err := e.cache.ReadPointerAtAddress(addr); err == nil { // try as a pointer
						addr = e.cache.SlideInfo.SlidePointer(ptr)
						image, err = e.cache.GetImageContainingVMAddr(addr)
						if err != nil {
							log.Errorf("failed to get image for address %#x (or pointer %#x): %v", addr, ptr, err)
							return false
						}
					}
				}
				sinfo, err := image.GetSlideInfo()
				if err != nil {
					log.Errorf(err.Error())
					return false
				}
				for where, target := range sinfo {
					if where > addr && where <= addr+0x2000 {
						e.PutPointer(where, target, 8)
					}
				}
				return true
			case uc.MEM_READ_PROT:
				fmt.Print(colorHook("[MEM_READ_PROT]"))
			case uc.MEM_FETCH_UNMAPPED:
				fmt.Print(colorHook("[MEM_FETCH_UNMAPPED]"))
				uuid, off, err := e.cache.GetOffset(e.cache.SlideInfo.SlidePointer(addr))
				if err != nil {
					log.Errorf(err.Error())
					return false
				}
				dat, err := e.cache.ReadBytesForUUID(uuid, int64(off), UC_MEM_ALIGN)
				if err != nil {
					log.Errorf(err.Error())
					return false
				}
				a, sz := Align(addr, uint64(len(dat)), true)
				if err := e.mu.MemMap(a, sz); err != nil {
					log.Errorf("failed to memmap at %#x: %v", a, err)
					return false
				}
				if err := e.mu.MemWrite(addr, dat); err != nil {
					log.Errorf("failed to mem write at %#x: %v", addr, err)
					return false
				}
				return true
			case uc.MEM_FETCH_PROT:
				fmt.Print(colorHook("[MEM_FETCH_PROT]"))
			default:
				fmt.Printf(colorHook("[MEM_INVALID]") + colorDetails(" unknown memory error: %d\n", access))
			}
			fmt.Print(colorDetails(" @ %#x, size=%d, value: %#x\n", addr, size, value))
			return false
		}, 1, 0); err != nil {
		return fmt.Errorf("failed to register mem invalid read/write/fetch hook: %v", err)
	}
	//**************
	//* HOOK_BLOCK *
	//**************
	if _, err := e.mu.HookAdd(uc.HOOK_BLOCK, func(mu uc.Unicorn, addr uint64, size uint32) {
		if e.conf.Verbose {
			fmt.Printf(colorHook("[BLOCK]") + colorDetails(" addr: %#x, size: %d\n", addr, size))
		} else {
			fmt.Println()
		}
	}, 1, 0); err != nil {
		return fmt.Errorf("failed to register block hook: %v", err)
	}
	//*************
	//* HOOK_CODE *
	//*************
	if _, err := e.mu.HookAdd(uc.HOOK_CODE, func(mu uc.Unicorn, addr uint64, size uint32) {
		// read instruction data
		uuid, off, err := e.cache.GetOffset(addr)
		if err != nil {
			log.Errorf(err.Error())
			return
		}
		code, err := e.cache.ReadBytesForUUID(uuid, int64(off), uint64(size))
		if err != nil {
			log.Errorf(err.Error())
			return
		}
		if err := e.GetState(); err != nil {
			log.Errorf("failed to register state: %v", err)
		}
		if e.conf.Verbose {
			fmt.Println(e.regs.Changed())
			// fmt.Println(e.regs.AllChanged())
		}
		// disassemble code
		diss(addr, code)
		e.instr = code
	}, 1, 0); err != nil {
		return fmt.Errorf("failed to register code hook: %v", err)
	}
	//*************
	//* HOOK_INTR *
	//*************
	if _, err := e.mu.HookAdd(uc.HOOK_INTR, func(mu uc.Unicorn, intno uint32) {
		fmt.Printf(colorHook("[INTERRUPT]") + colorInterrupt(" %s\n", interrupt(intno)))
		switch interrupt(intno) {
		case EXCP_UNDEFINED_INSTRUCTION:
			if reflect.DeepEqual(e.instr, []byte{0xc0, 0x03, 0x5f, 0xd6}) { // skip over ret
				if lr, err := e.mu.RegRead(uc.ARM64_REG_LR); err == nil {
					e.mu.RegWrite(uc.ARM64_REG_PC, lr)
				}
				return
			}
			if err := e.GetState(); err != nil {
				log.Errorf("failed to register state: %v", err)
			}
			fmt.Printf(colorHook("[REGISTERS]\n"))
			fmt.Println(e.regs.Changed())
			fmt.Printf(colorHook("\n[MEM_REGIONS]\n"))
			e.DumpMemRegions()
			fmt.Printf(colorHook("\n[STACK]\n"))
			e.DumpMem(e.regs[uc.ARM64_REG_SP].Value-0x50, 0x50)
			fmt.Printf(colorHook("SP>\n"))
			e.DumpMem(e.regs[uc.ARM64_REG_SP].Value, min((STACK_BASE+STACK_SIZE)-e.regs[uc.ARM64_REG_SP].Value, 0x50))
			// cont := false
			// prompt := &survey.Confirm{
			// 	Message: "Continue?",
			// }
			// survey.AskOne(prompt, &cont)
			// if cont {
			// 	if pc, err := e.mu.RegRead(uc.ARM64_REG_PC); err == nil {
			// 		e.mu.RegWrite(uc.ARM64_REG_PC, pc+4)
			// 	}
			// } else {
			log.Fatal("UNHANDLED INTERRUPT")
			// }
		}
	}, 1, 0); err != nil {
		return fmt.Errorf("failed to register interrupt hook: %v", err)
	}

	return nil
}

// SetCode initializes the emulation code
func (e *Emulation) SetCode(start uint64, count uint64, code []byte) error {
	e.startAddr = start
	e.count = count
	e.code = code

	addr, sz := Align(start, uint64(len(code)), true)
	if err := e.mu.MemMap(addr, sz); err != nil {
		return fmt.Errorf("failed to memmap for code at %#x: %v", addr, err)
	}
	if err := e.mu.MemWrite(start, code); err != nil {
		return fmt.Errorf("failed to write code at %#x: %v", start, err)
	}

	return nil
}

// Start starts the unicorn emulation engine
func (e *Emulation) Start() error {
	if err := e.mu.Start(e.startAddr, e.startAddr+(e.count*4)); err != nil {
		fmt.Printf(colorHook("[REGISTERS]\n"))
		fmt.Println(e.regs.Changed())
		fmt.Printf(colorHook("\n[MEM_REGIONS]\n"))
		e.DumpMemRegions()
		fmt.Printf(colorHook("\n[STACK]\n"))
		e.DumpMem(e.regs[uc.ARM64_REG_SP].Value-0x50, 0x50)
		fmt.Printf(colorHook("SP>\n"))
		e.DumpMem(e.regs[uc.ARM64_REG_SP].Value, min((STACK_BASE+STACK_SIZE)-e.regs[uc.ARM64_REG_SP].Value, 0x50))
		return fmt.Errorf("failed to emulate: %v", err)
	}
	if err := e.GetState(); err != nil {
		return fmt.Errorf("failed to register state: %v", err)
	}
	fmt.Println(e.regs)

	return nil
}
