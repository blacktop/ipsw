package vtable

import (
	"github.com/blacktop/arm64-cgo/emulate"
	"github.com/blacktop/arm64-cgo/emulate/core"
)

// EmulatorAdapter provides a future-proof wrapper around the ARM64 emulator
// This allows us to easily adapt to new emulator API changes without breaking vtable code
type EmulatorAdapter struct {
	engine *emulate.Engine
}

// NewEmulatorAdapter creates a new emulator adapter with default settings
func NewEmulatorAdapter() *EmulatorAdapter {
	engine := emulate.NewEngine()
	engine.SetMaxInstructions(100) // Conservative limit for alloc function analysis
	engine.SetTrace(false)         // Disable tracing by default for performance
	engine.StopOnError = true      // Stop on errors to prevent hanging

	return &EmulatorAdapter{
		engine: engine,
	}
}

// NewEmulatorAdapterWithState creates an adapter with custom initial state
func NewEmulatorAdapterWithState(state core.State) *EmulatorAdapter {
	engine := emulate.NewEngineWithState(state)
	engine.SetMaxInstructions(100) // Conservative limit
	engine.SetTrace(false)
	engine.StopOnError = true // Stop on errors to prevent hanging

	return &EmulatorAdapter{
		engine: engine,
	}
}

// SetMaxInstructions sets the maximum number of instructions to execute
func (ea *EmulatorAdapter) SetMaxInstructions(limit int) {
	ea.engine.SetMaxInstructions(limit)
}

// SetTrace enables or disables instruction tracing
func (ea *EmulatorAdapter) SetTrace(enable bool) {
	ea.engine.SetTrace(enable)
}

// GetState returns the current emulator state
func (ea *EmulatorAdapter) GetState() core.State {
	return ea.engine.GetState()
}

// SetState sets a new emulator state
func (ea *EmulatorAdapter) SetState(state core.State) {
	ea.engine.SetState(state)
}

// ExecuteInstruction executes a single instruction
func (ea *EmulatorAdapter) ExecuteInstruction(pc uint64, instr uint32) error {
	return ea.engine.ExecuteInstruction(pc, instr)
}

// RunAt executes instructions starting from a specific address
func (ea *EmulatorAdapter) RunAt(startPC uint64) error {
	return ea.engine.RunAt(startPC)
}

// Run executes instructions from the current PC until a stop condition is met
func (ea *EmulatorAdapter) Run() error {
	return ea.engine.Run()
}

// StepOver executes a single instruction and advances PC
func (ea *EmulatorAdapter) StepOver() error {
	return ea.engine.StepOver()
}

// GetRegister returns the value of a register by index
func (ea *EmulatorAdapter) GetRegister(index int) uint64 {
	return ea.engine.GetRegister(index)
}

// SetRegister sets the value of a register by index
func (ea *EmulatorAdapter) SetRegister(index int, value uint64) {
	ea.engine.SetRegister(index, value)
}

// GetPC returns the current program counter
func (ea *EmulatorAdapter) GetPC() uint64 {
	return ea.engine.GetPC()
}

// SetPC sets the program counter
func (ea *EmulatorAdapter) SetPC(pc uint64) {
	ea.engine.SetPC(pc)
}

// GetSP returns the stack pointer
func (ea *EmulatorAdapter) GetSP() uint64 {
	return ea.engine.GetSP()
}

// SetSP sets the stack pointer
func (ea *EmulatorAdapter) SetSP(sp uint64) {
	ea.engine.SetSP(sp)
}

// IsRegisterValid checks if a register contains valid data
// Note: The new modular engine doesn't track register validity, so we assume all registers are valid
func (ea *EmulatorAdapter) IsRegisterValid(index int) bool {
	// In the new modular system, all registers are considered valid
	// This maintains compatibility with existing vtable code
	return index >= 0 && index < 31
}

// SetMemory writes data to memory at the specified address
func (ea *EmulatorAdapter) SetMemory(addr uint64, data []byte) error {
	return ea.engine.SetMemory(addr, data)
}

// GetMemory reads data from memory at the specified address
func (ea *EmulatorAdapter) GetMemory(addr uint64, size int) ([]byte, error) {
	return ea.engine.GetMemory(addr, size)
}

// SetMemoryUint64 writes a 64-bit value to memory
func (ea *EmulatorAdapter) SetMemoryUint64(addr uint64, value uint64) error {
	return ea.engine.SetMemoryUint64(addr, value)
}

// GetMemoryUint64 reads a 64-bit value from memory
func (ea *EmulatorAdapter) GetMemoryUint64(addr uint64) (uint64, error) {
	return ea.engine.GetMemoryUint64(addr)
}

// SetMemoryUint32 writes a 32-bit value to memory
func (ea *EmulatorAdapter) SetMemoryUint32(addr uint64, value uint32) error {
	return ea.engine.SetMemoryUint32(addr, value)
}

// GetMemoryUint32 reads a 32-bit value from memory
func (ea *EmulatorAdapter) GetMemoryUint32(addr uint64) (uint32, error) {
	return ea.engine.GetMemoryUint32(addr)
}

// GetInstructionCount returns the current instruction count
func (ea *EmulatorAdapter) GetInstructionCount() int {
	return ea.engine.GetInstructionCount()
}

// Reset resets the engine state
func (ea *EmulatorAdapter) Reset() {
	ea.engine.Reset()
}

// GetTrace returns the instruction trace if tracing is enabled
func (ea *EmulatorAdapter) GetTrace() []core.InstructionInfo {
	return ea.engine.GetTrace()
}

// GetLastError returns the last error encountered during emulation
func (ea *EmulatorAdapter) GetLastError() error {
	return ea.engine.LastError
}

// SetupForAllocFunction configures the emulator for analyzing alloc functions
func (ea *EmulatorAdapter) SetupForAllocFunction(classSize uint64) {
	state := ea.GetState()

	// Set up typical alloc function parameters
	state.SetX(0, 0x1000000000000000) // Mock object address (this pointer)
	state.SetX(1, classSize)          // Size parameter

	// Set up kernel-style stack pointer
	state.SetSP(0xfffffe0007ff0000)

	// Enable error continuation for robustness
	ea.engine.StopOnError = false
}

// SetupMemoryReadHandler sets a custom memory read handler for kernelcache access
func (ea *EmulatorAdapter) SetupMemoryReadHandler(handler core.MemoryReadHandler) {
	state := ea.GetState()
	state.SetMemoryReadHandler(handler)
}

// EmulateWithWriteTracking emulates code while tracking memory writes for vtable detection
func (ea *EmulatorAdapter) EmulateWithWriteTracking(code []byte, startAddr uint64, writeHandler func(uint64, uint64, int)) error {
	state := ea.GetState()

	// Set up memory to contain the code
	state.WriteMemory(startAddr, code)

	// Set starting PC
	ea.SetPC(startAddr)

	// Set conservative limits to prevent hanging
	ea.SetMaxInstructions(100) // Very conservative limit for alloc functions
	ea.engine.StopOnError = true // Stop on errors to prevent infinite loops

	// Enable tracing for write detection
	originalTraceLen := len(ea.GetTrace())
	ea.SetTrace(true)

	// Run emulation with timeout protection
	err := ea.Run()

	// Process trace to find writes (with safety limits)
	trace := ea.GetTrace()
	newTrace := trace[originalTraceLen:]
	
	// Limit trace processing to prevent excessive computation
	maxTraceEntries := 500
	if len(newTrace) > maxTraceEntries {
		newTrace = newTrace[:maxTraceEntries]
	}

	for _, instrInfo := range newTrace {
		// Check if this instruction is a store operation
		if ea.isStoreInstruction(instrInfo.Value) {
			// Extract store details and call handler
			addr, value, size := ea.extractStoreDetails(instrInfo, state)
			if addr != 0 {
				writeHandler(addr, value, size)
			}
		}
	}

	return err
}

// isStoreInstruction checks if an instruction is a store operation
func (ea *EmulatorAdapter) isStoreInstruction(instrValue uint32) bool {
	// Fast bitmask checks for store instructions
	// STR (immediate): 0xF9000000 mask 0xFFC00000
	// STP: 0xA9000000 mask 0xFFC00000
	// STUR: 0xF8000000 mask 0xFFC00000
	return (instrValue&0xFFC00000) == 0xF9000000 || // STR immediate
		(instrValue&0xFFC00000) == 0xA9000000 || // STP
		(instrValue&0xFFC00000) == 0xF8000000 // STUR
}

// extractStoreDetails extracts store operation details from instruction
func (ea *EmulatorAdapter) extractStoreDetails(instrInfo core.InstructionInfo, state core.State) (addr, value uint64, size int) {
	// This is a simplified implementation
	// In practice, you'd need to decode the instruction operands properly

	// Extract register operands from instruction
	instrValue := instrInfo.Value

	// For STR immediate: decode Rt, Rn, imm
	if (instrValue & 0xFFC00000) == 0xF9000000 { // STR X immediate
		rt := instrValue & 0x1F           // Source register
		rn := (instrValue >> 5) & 0x1F    // Base register
		imm := (instrValue >> 10) & 0xFFF // Immediate offset

		if rn < 31 && rt < 31 {
			baseAddr := state.GetX(int(rn))
			storeAddr := baseAddr + uint64(imm*8) // Scale by 8 for 64-bit stores
			storeValue := state.GetX(int(rt))
			return storeAddr, storeValue, 8
		}
	}

	// For other store types, return zeros for now
	return 0, 0, 0
}

// ValidateVtableAddress checks if an address looks like a valid vtable
func (ea *EmulatorAdapter) ValidateVtableAddress(addr uint64) bool {
	// Heuristic checks for valid vtable addresses
	if addr == 0 {
		return false
	}

	// Check if address is properly aligned (8-byte aligned for pointers)
	if addr&0x7 != 0 {
		return false
	}

	// Check if address is in a reasonable range
	// Kernel addresses typically start with 0xFFFF or high userspace with 0x0001
	if addr < 0x1000 {
		return false // Too low, likely null or invalid
	}

	return true
}

// CreateMockKernelState creates a realistic kernel execution state for testing
func CreateMockKernelState() core.State {
	config := emulate.DefaultEngineConfig()
	config.InitialSP = 0xfffffe0007ff0000
	config.InitialPC = 0

	engine := emulate.NewEngineWithConfig(config)
	state := engine.GetState()

	// Clear all registers (typical kernel entry state)
	for i := 0; i < 31; i++ {
		state.SetX(i, 0)
	}

	return state
}

// CreateMockAllocState creates a state configured for alloc function analysis
func CreateMockAllocState(classSize uint64) core.State {
	state := CreateMockKernelState()

	// Set up alloc function parameters
	state.SetX(0, 0x1000000000000000) // Mock object address
	state.SetX(1, classSize)          // Class size

	return state
}
