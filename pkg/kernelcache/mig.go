package kernelcache

//go:generate go tool stringer -type=SubsystemStart -output mig_string.go

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/arm64-cgo/disassemble"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/blacktop/ipsw/pkg/disass"
)

type SubsystemStart uint32

const (
	arcade_register_subsystem  SubsystemStart = 0xC90F
	catch_exc_subsystem        SubsystemStart = 0x961
	catch_mach_exc_subsystem   SubsystemStart = 0x965
	clock_subsystem            SubsystemStart = 0x3E8
	host_priv_subsystem        SubsystemStart = 0x190
	is_iokit_subsystem         SubsystemStart = 0xAF0
	mach_eventlink_subsystem   SubsystemStart = 0xAEDA8
	mach_host_subsystem        SubsystemStart = 0xC8
	mach_port_subsystem        SubsystemStart = 0xC80
	mach_vm_subsystem          SubsystemStart = 0x12c0
	mach_voucher_subsystem     SubsystemStart = 0x1518
	memory_entry_subsystem     SubsystemStart = 0x1324
	processor_set_subsystem    SubsystemStart = 0xFA0
	processor_subsystem        SubsystemStart = 0xBB8
	task_restartable_subsystem SubsystemStart = 0x1F40
	task_subsystem             SubsystemStart = 0xD48
	thread_act_subsystem       SubsystemStart = 0xE10
	UNDReply_subsystem         SubsystemStart = 0x1838
	vm32_map_subsystem         SubsystemStart = 0xED8
)

type MigHash struct {
	Num           int
	KObjIdx       int
	KRoutine      uint64 /* Kernel server routine */
	KReplySize    uint32 /* Size of kernel reply msg */
	KReplyDescCnt uint32 /* Number of descs in kernel reply msg */
}

type MachMsgHeader struct {
	MsghBits        uint32
	MsghSize        uint32
	MsghRemotePort  uint32
	MsghLocalPort   uint32
	MsghVoucherPort uint32
	MsghId          uint32
}

type KernRoutineDescriptor struct {
	ImplRoutine     uint64 /* Server work func pointer */
	KStubRoutine    uint64 /* Unmarshalling func pointer */
	ArgC            uint32 /* Number of argument words */
	DescrCount      uint32 /* Number complex descriptors */
	ReplyDescrCount uint32 /* Number descriptors in reply */
	MaxReplyMsg     uint32 /* Max size for reply msg */
}

type migKernSubsystemHdr struct {
	KServer  uint64         /* pointer to kernel demux routine */
	Start    SubsystemStart /* Min routine number */
	End      uint32         /* Max routine number + 1 */
	Maxsize  uint32         /* Max reply message size */
	_        uint32         // padding
	Reserved uint64         /* reserved for MIG use */

}

type MigKernSubsystem struct {
	migKernSubsystemHdr
	Routines []KernRoutineDescriptor /* Kernel routine descriptor array */
}

func (m MigKernSubsystem) LookupRoutineName(idx int) string {
	switch m.Start {
	case mach_vm_subsystem:
		if idx >= len(machVmSubsystemFuncs) {
			return "<unknown>"
		} else {
			return machVmSubsystemFuncs[idx]
		}
	case mach_port_subsystem:
		if idx >= len(machPortSubsystemFuncs) {
			return "<unknown>"
		} else {
			return machPortSubsystemFuncs[idx]
		}
	case mach_host_subsystem:
		if idx >= len(machHostSubsystemFuncs) {
			return "<unknown>"
		} else {
			return machHostSubsystemFuncs[idx]
		}
	case host_priv_subsystem:
		if idx >= len(hostPrivSubsystemFuncs) {
			return "<unknown>"
		} else {
			return hostPrivSubsystemFuncs[idx]
		}
	case clock_subsystem:
		if idx >= len(clockSubsystemFuncs) {
			return "<unknown>"
		} else {
			return clockSubsystemFuncs[idx]
		}
	case processor_subsystem:
		if idx >= len(processorSubsystemFuncs) {
			return "<unknown>"
		} else {
			return processorSubsystemFuncs[idx]
		}
	case processor_set_subsystem:
		if idx >= len(processorSetSubsystemFuncs) {
			return "<unknown>"
		} else {
			return processorSetSubsystemFuncs[idx]
		}
	case is_iokit_subsystem:
		if idx >= len(isIokitSubsystemProcessorSetSubsystemFuncs) {
			return "<unknown>"
		} else {
			return isIokitSubsystemProcessorSetSubsystemFuncs[idx]
		}
	case task_subsystem:
		if idx >= len(taskSubsystemFuncs) {
			return "<unknown>"
		} else {
			return taskSubsystemFuncs[idx]
		}
	case thread_act_subsystem:
		if idx >= len(threadActSubsystemFuncs) {
			return "<unknown>"
		} else {
			return threadActSubsystemFuncs[idx]
		}
	case vm32_map_subsystem:
		if idx >= len(vm32MapSubsystemFuncs) {
			return "<unknown>"
		} else {
			return vm32MapSubsystemFuncs[idx]
		}
	case UNDReply_subsystem:
		if idx >= len(undReplySubsystemFuncs) {
			return "<unknown>"
		} else {
			return undReplySubsystemFuncs[idx]
		}
	case mach_voucher_subsystem:
		if idx >= len(machVoucherSubsystemFuncs) {
			return "<unknown>"
		} else {
			return machVoucherSubsystemFuncs[idx]
		}
	case memory_entry_subsystem:
		if idx >= len(memoryEntrySubsystemFuncs) {
			return "<unknown>"
		} else {
			return memoryEntrySubsystemFuncs[idx]
		}
	case task_restartable_subsystem:
		if idx >= len(taskRestartableSubsystemFuncs) {
			return "<unknown>"
		} else {
			return taskRestartableSubsystemFuncs[idx]
		}
	case catch_exc_subsystem:
		if idx >= len(catchExcSubsystemFuncs) {
			return "<unknown>"
		} else {
			return catchExcSubsystemFuncs[idx]
		}
	case catch_mach_exc_subsystem:
		if idx >= len(catch_mach_exc_subsystem_Funcs) {
			return "<unknown>"
		} else {
			return catch_mach_exc_subsystem_Funcs[idx]
		}
	case arcade_register_subsystem:
		if idx >= len(arcade_register_subsystem_Funcs) {
			return "<unknown>"
		} else {
			return arcade_register_subsystem_Funcs[idx]
		}
	case mach_eventlink_subsystem:
		if idx >= len(mach_eventlink_subsystem_Funcs) {
			return "<unknown>"
		} else {
			return mach_eventlink_subsystem_Funcs[idx]
		}
	default:
		return "<unknown>"
	}
}

func (m MigKernSubsystem) String() string {
	var out string
	out += fmt.Sprintf("%s: %s\t%s=%d %s=%d %s=%d\n",
		colorAddr("%#x", m.KServer),
		colorSubSystem(m.Start.String()),
		colorField("start"), m.Start,
		colorField("end"), m.End,
		colorField("max_sz"), m.Maxsize,
	)
	for idx, r := range m.Routines {
		if r.KStubRoutine == 0 {
			continue // skip empty routines
		}
		out += fmt.Sprintf("    %s: ", colorAddr("%#x", r.KStubRoutine))
		out += colorBold(m.LookupRoutineName(idx))
		out += fmt.Sprintf("\t%s=%02d %s=%#x %s=%02d %s=%d %s=%d %s=%d\n",
			colorName("num"), idx+int(m.Start),
			colorName("impl"), r.ImplRoutine,
			colorName("argc"), r.ArgC,
			colorName("descr"), r.DescrCount,
			colorName("reply_descr"), r.ReplyDescrCount,
			colorName("max_reply_msg"), r.MaxReplyMsg,
		)
	}
	return out
}

func getMigInitFunc(m *macho.File) (*types.Function, error) {
	var ref uint64

	cstrs, err := m.GetCStrings()
	if err != nil {
		return nil, err
	}

	found := false
	for str, addr := range cstrs["__TEXT.__cstring"] {
		if strings.Contains(str, "mig_e") {
			ref = addr
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("failed to find 'mig_e' anchor")
	}

	text := m.Section("__TEXT_EXEC", "__text")
	if text == nil {
		return nil, fmt.Errorf("failed to find __TEXT_EXEC.__text section")
	}
	data, err := text.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to get data from __TEXT_EXEC.__text section: %v", err)
	}

	engine := disass.NewMachoDisass(m, &disass.Config{
		Data:         data,
		StartAddress: text.Addr,
		Quite:        true,
	})
	if err := engine.Triage(); err != nil {
		return nil, fmt.Errorf("first pass triage failed: %v", err)
	}

	if ok, loc := engine.Contains(ref); ok {
		migInit, err := m.GetFunctionForVMAddr(loc)
		if err != nil {
			return nil, fmt.Errorf("failed to get function with xref to 'mig_e' anchor: %v", err)
		}
		return &migInit, nil
	}

	return nil, fmt.Errorf("failed to find 'mig_init' address")
}

func getMigE(r *bytes.Reader, migInit *types.Function) (uint64, uint64, error) {
	var migE uint64
	var sizeOfMigE uint64

	var instrValue uint32
	var results [1024]byte
	var prevInstr *disassemble.Instruction

	startAddr := migInit.StartAddr

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, 0, fmt.Errorf("failed to read instruction @ %#x: %v", startAddr, err)
		}

		instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			startAddr += uint64(binary.Size(uint32(0)))
			continue
		}

		if strings.Contains(instruction.Encoding.String(), "loadlit") {
			migE = uint64(instruction.Operands[1].Immediate)
			break
		} else if (prevInstr != nil && prevInstr.Operation == disassemble.ARM64_ADRP) &&
			(instruction.Operation == disassemble.ARM64_ADD ||
				instruction.Operation == disassemble.ARM64_LDR ||
				instruction.Operation == disassemble.ARM64_LDRB ||
				instruction.Operation == disassemble.ARM64_LDRSW) {
			adrpRegister := prevInstr.Operands[0].Registers[0]
			adrpImm := prevInstr.Operands[1].Immediate
			if instruction.Operation == disassemble.ARM64_LDR && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[1].Immediate
			} else if instruction.Operation == disassemble.ARM64_LDRB && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[1].Immediate
			} else if instruction.Operation == disassemble.ARM64_ADD && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[2].Immediate
			} else if instruction.Operation == disassemble.ARM64_LDRSW && adrpRegister == instruction.Operands[1].Registers[0] {
				adrpImm += instruction.Operands[1].Immediate
			}
			migE = adrpImm
			break
		}
		// fmt.Printf("%#08x:  %s\t%s\n", uint64(startAddr), disassemble.GetOpCodeByteString(instrValue), instruction)

		prevInstr = instruction
		startAddr += uint64(binary.Size(uint32(0)))
	}

	// find RET instruction

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, 0, fmt.Errorf("failed to read instruction @ %#x: %v", startAddr, err)
		}
		instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			startAddr += uint64(binary.Size(uint32(0)))
			continue
		}
		if strings.Contains(instruction.Encoding.String(), "RET") {
			break
		}
		startAddr += uint64(binary.Size(uint32(0)))
	}

	// search backwards for the size of the migE struct via CMP (from for loop stop condition)
	startAddr -= uint64(binary.Size(uint64(0)))
	r.Seek(-int64(binary.Size(uint64(0))), io.SeekCurrent)

	for {
		err := binary.Read(r, binary.LittleEndian, &instrValue)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, 0, fmt.Errorf("failed to read instruction @ %#x: %v", startAddr, err)
		}
		instruction, err := disassemble.Decompose(startAddr, instrValue, &results)
		if err != nil {
			startAddr += uint64(binary.Size(uint32(0)))
			continue
		}
		if strings.Contains(instruction.Encoding.String(), "CMP") {
			if len(instruction.Operands) < 2 {
				return 0, 0, fmt.Errorf("failed to find size of migE struct")
			}
			sizeOfMigE = uint64(instruction.Operands[1].Immediate)
			break
		}
		startAddr -= uint64(binary.Size(uint32(0)))
		r.Seek(-int64(binary.Size(uint64(0))), io.SeekCurrent)
	}

	return migE, sizeOfMigE, nil
}

func GetMigSubsystems(m *macho.File) ([]MigKernSubsystem, error) {
	if m.FileTOC.FileHeader.Type == types.MH_FILESET {
		var err error
		m, err = m.GetFileSetFileByName("com.apple.kernel")
		if err != nil {
			return nil, fmt.Errorf("failed to get fileset entry 'com.apple.kernel': %v", err)
		}
	}

	migInit, err := getMigInitFunc(m)
	if err != nil {
		return nil, err
	}
	data, err := m.GetFunctionData(*migInit)
	if err != nil {
		return nil, err
	}

	migEAddr, sizeOfMigE, err := getMigE(bytes.NewReader(data), migInit)
	if err != nil {
		return nil, err
	}

	log.WithField("mig_kern_subsystem table", fmt.Sprintf("%#x", migEAddr)).Infof("Found")

	var subsystems []uint64
	for i := uint64(0); i < sizeOfMigE; i++ {
		ptr, err := m.GetPointerAtAddress(migEAddr + i*uint64(binary.Size(uint64(0))))
		if err != nil {
			return nil, err
		}
		subsystems = append(subsystems, ptr)
	}

	dataConst := m.Section("__DATA_CONST", "__const")
	if dataConst == nil {
		return nil, macho.ErrMachOSectionNotFound
	}
	dataConstData, err := dataConst.Data()
	if err != nil {
		return nil, err
	}

	r := bytes.NewReader(dataConstData)

	var migs []MigKernSubsystem

	for i := range subsystems {
		r.Seek(int64(subsystems[i]-dataConst.Addr), io.SeekStart)

		var mig MigKernSubsystem
		if err := binary.Read(r, binary.LittleEndian, &mig.migKernSubsystemHdr); err != nil {
			return nil, err
		}
		mig.migKernSubsystemHdr.KServer = m.SlidePointer(mig.migKernSubsystemHdr.KServer)
		mig.Routines = make([]KernRoutineDescriptor, mig.End-uint32(mig.Start))
		if err := binary.Read(r, binary.LittleEndian, &mig.Routines); err != nil {
			return nil, err
		}
		for i, routine := range mig.Routines {
			routine.ImplRoutine = m.SlidePointer(routine.ImplRoutine)
			routine.KStubRoutine = m.SlidePointer(routine.KStubRoutine)
			mig.Routines[i] = routine
		}

		migs = append(migs, mig)
	}

	return migs, nil
}
