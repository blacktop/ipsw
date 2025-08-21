/*
Copyright © 2018-2025 blacktop

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package cmd

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/blacktop/arm64-cgo/emulate"
	"github.com/blacktop/arm64-cgo/emulate/core"
	"github.com/blacktop/arm64-cgo/emulate/state"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/disass"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(emuCmd)
}

// emuCmd represents the emulator command
var emuCmd = &cobra.Command{
	Use:           "emu <macho_file> <address> [count]",
	Short:         "ARM64 instruction emulator with TUI debugger",
	Args:          cobra.ExactArgs(2),
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// Parse arguments
		machoPath := args[0]

		// Parse address (support both hex and decimal)
		addrStr := strings.TrimPrefix(args[1], "0x")
		address, err := strconv.ParseUint(addrStr, 16, 64)
		if err != nil {
			// Try decimal if hex parsing fails
			address, err = strconv.ParseUint(args[1], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid address format: %s", args[1])
			}
		}

		// Parse instruction count (default to 50 for interactive session)
		count := 50
		if len(args) == 3 {
			count, err = strconv.Atoi(args[2])
			if err != nil {
				return fmt.Errorf("invalid instruction count: %s", args[2])
			}
		}

		m, err := macho.Open(machoPath)
		if err != nil {
			return fmt.Errorf("failed to open file: %v", err)
		}
		defer m.Close()

		fn, err := m.GetFunctionForVMAddr(address)
		if err != nil {
			return fmt.Errorf("failed to get function for address 0x%x: %v", address, err)
		}
		count = int(fn.EndAddr-fn.StartAddr) / 4

		instrs := make([]byte, count*4)
		if _, err := m.ReadAtAddr(instrs, address); err != nil {
			return fmt.Errorf("failed to read instructions: %v", err)
		}

		// Initialize the TUI debugger
		debugger := newDebugger(instrs, m.GetBaseAddress(), address, m)

		// Start the TUI
		program := tea.NewProgram(debugger, tea.WithAltScreen())
		if _, err := program.Run(); err != nil {
			return fmt.Errorf("failed to start TUI: %v", err)
		}

		return nil
	},
}

// registerChangeState tracks when a register was last changed
type registerChangeState struct {
	lastValue uint64
	changeAge int // 0 = just changed, 1 = one step ago, 2 = two steps ago, 3+ = normal
}

// debuggerModel represents the state of our TUI debugger
type debuggerModel struct {
	instructions []byte
	baseAddr     uint64
	startAddr    uint64
	binary       *macho.File

	// Emulator state
	engine    *emulate.Engine
	state     core.State
	currentPC uint64
	stepCount int

	// UI state
	width   int
	height  int
	focused string // "registers", "instructions", "memory"

	// Instruction disassembly cache
	disassembly  []instructionInfo
	currentInstr int

	// Register change tracking
	regChangeState map[string]*registerChangeState
	prevState      core.State
}

type instructionInfo struct {
	address     uint64
	bytes       []byte
	disassembly string
	executed    bool
}

// newDebugger creates a new debugger model
func newDebugger(instructions []byte, baseAddr, startAddr uint64, binary *macho.File) *debuggerModel {
	armState := state.NewState() // Already initializes SP to 0x7ffff0000000 with 1MB stack
	armState.SetPC(startAddr)

	// Load instructions into memory at the start address (critical for emulation)
	armState.WriteMemory(startAddr, instructions)

	// Create emulation engine
	engine := emulate.NewEngineWithState(armState)

	// Initialize register change tracking
	regChangeState := make(map[string]*registerChangeState)

	// Initialize change state for all registers
	for i := 0; i < 31; i++ {
		regChangeState[fmt.Sprintf("X%d", i)] = &registerChangeState{lastValue: 0, changeAge: 3}
	}
	regChangeState["SP"] = &registerChangeState{lastValue: armState.GetSP(), changeAge: 3}
	regChangeState["PC"] = &registerChangeState{lastValue: startAddr, changeAge: 3}
	regChangeState["FLAGS"] = &registerChangeState{lastValue: 0, changeAge: 3}

	model := &debuggerModel{
		instructions:   instructions,
		baseAddr:       baseAddr,
		startAddr:      startAddr,
		binary:         binary,
		engine:         engine,
		state:          armState,
		currentPC:      startAddr,
		stepCount:      0,
		focused:        "instructions",
		disassembly:    make([]instructionInfo, 0),
		currentInstr:   0,
		regChangeState: regChangeState,
		prevState:      state.NewState(), // Copy initial state
	}

	// Set initial prevState values to match current state
	model.prevState.SetPC(startAddr)
	model.prevState.SetSP(armState.GetSP())

	return model
}

// Init implements the bubbletea Model interface
func (m *debuggerModel) Init() tea.Cmd {
	return nil
}

// Update implements the bubbletea Model interface
func (m *debuggerModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			return m, tea.Quit
		case "n", " ":
			// Step to next instruction
			return m, m.stepInstruction()
		case "r":
			// Reset emulator state
			newState := state.NewState() // Already has proper SP at 0x7ffff0000000
			newState.SetPC(m.startAddr)
			// Reload instructions into memory
			newState.WriteMemory(m.startAddr, m.instructions)

			m.state = newState
			m.engine = emulate.NewEngineWithState(newState)
			m.currentPC = m.startAddr
			m.stepCount = 0
			m.currentInstr = 0

			// Reset execution markers
			for i := range m.disassembly {
				m.disassembly[i].executed = false
			}
			// Reset register change tracking
			for _, changeState := range m.regChangeState {
				changeState.changeAge = 3 // Set to normal (no highlighting)
			}
			// Reset previous state
			m.prevState = state.NewState()
			m.prevState.SetPC(m.startAddr)
			m.prevState.SetSP(m.state.GetSP())
		case "tab":
			// Switch focus between panels
			switch m.focused {
			case "registers":
				m.focused = "instructions"
			case "instructions":
				m.focused = "memory"
			case "memory":
				m.focused = "registers"
			}
		}
	case stepExecutedMsg:
		// Update model with step execution results
		m.stepCount = msg.stepCount
		if msg.err != nil {
			// Handle error but don't crash
			return m, nil
		}

		// Update current PC
		m.currentPC = msg.newPC

		// Track register changes
		m.updateRegisterChangeTracking()

		// Update current instruction pointer
		if m.currentInstr < len(m.disassembly) {
			m.disassembly[m.currentInstr].executed = true
		}

		// Find next instruction
		for i, instr := range m.disassembly {
			if instr.address == m.currentPC {
				m.currentInstr = i
				break
			}
		}

		return m, nil
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

// stepExecutedMsg is a message indicating a step was executed
type stepExecutedMsg struct {
	newPC     uint64
	stepCount int
	err       error
}

// stepInstruction executes the next instruction and returns a command
func (m *debuggerModel) stepInstruction() tea.Cmd {
	return func() tea.Msg {
		// Calculate offset from current PC relative to start address
		offset := m.currentPC - m.startAddr
		if offset >= uint64(len(m.instructions)) {
			return stepExecutedMsg{newPC: m.currentPC, stepCount: m.stepCount + 1, err: nil}
		}

		// Execute single instruction
		instrBytes := m.instructions[offset : offset+4]
		if len(instrBytes) < 4 {
			return stepExecutedMsg{newPC: m.currentPC, stepCount: m.stepCount + 1, err: nil}
		}

		// Convert bytes to uint32 instruction (little endian)
		instruction := uint32(instrBytes[0]) | uint32(instrBytes[1])<<8 | uint32(instrBytes[2])<<16 | uint32(instrBytes[3])<<24

		// Emulate one instruction
		err := m.engine.ExecuteInstruction(m.currentPC, instruction)
		if err != nil {
			return stepExecutedMsg{newPC: m.currentPC, stepCount: m.stepCount + 1, err: err}
		}

		// Get the new PC from the engine state
		newPC := m.state.GetPC()
		return stepExecutedMsg{newPC: newPC, stepCount: m.stepCount + 1, err: nil}
	}
}

// updateRegisterChangeTracking tracks register changes and ages existing changes
func (m *debuggerModel) updateRegisterChangeTracking() {
	// Age all existing changes first
	for _, changeState := range m.regChangeState {
		if changeState.changeAge < 3 {
			changeState.changeAge++
		}
	}

	// Check for new changes and update
	// X registers
	for i := 0; i < 31; i++ {
		regName := fmt.Sprintf("X%d", i)
		currentValue := m.state.GetX(i)
		prevValue := m.prevState.GetX(i)

		if currentValue != prevValue {
			m.regChangeState[regName].changeAge = 0
			m.regChangeState[regName].lastValue = currentValue
		}

		m.prevState.SetX(i, currentValue)
	}

	// SP register
	if m.state.GetSP() != m.prevState.GetSP() {
		m.regChangeState["SP"].changeAge = 0
		m.regChangeState["SP"].lastValue = m.state.GetSP()
	}
	m.prevState.SetSP(m.state.GetSP())

	// PC register
	if m.state.GetPC() != m.prevState.GetPC() {
		m.regChangeState["PC"].changeAge = 0
		m.regChangeState["PC"].lastValue = m.state.GetPC()
	}
	m.prevState.SetPC(m.state.GetPC())

	// FLAGS register (combine NZCV flags into a single value for tracking)
	currentFlags := uint64(0)
	if m.state.GetN() {
		currentFlags |= 8
	}
	if m.state.GetZ() {
		currentFlags |= 4
	}
	if m.state.GetC() {
		currentFlags |= 2
	}
	if m.state.GetV() {
		currentFlags |= 1
	}

	prevFlags := uint64(0)
	if m.prevState.GetN() {
		prevFlags |= 8
	}
	if m.prevState.GetZ() {
		prevFlags |= 4
	}
	if m.prevState.GetC() {
		prevFlags |= 2
	}
	if m.prevState.GetV() {
		prevFlags |= 1
	}

	if currentFlags != prevFlags {
		m.regChangeState["FLAGS"].changeAge = 0
		m.regChangeState["FLAGS"].lastValue = currentFlags
	}

	// Update previous flags
	m.prevState.SetN(m.state.GetN())
	m.prevState.SetZ(m.state.GetZ())
	m.prevState.SetC(m.state.GetC())
	m.prevState.SetV(m.state.GetV())
}

// getRegisterStyle returns the lipgloss style for a register based on its change age
func (m *debuggerModel) getRegisterStyle(regName string) lipgloss.Style {
	changeState := m.regChangeState[regName]
	if changeState == nil {
		return lipgloss.NewStyle() // Default style
	}

	switch changeState.changeAge {
	case 0:
		// Just changed - bright green background
		return lipgloss.NewStyle().Background(lipgloss.Color("46")).Foreground(lipgloss.Color("0")).Bold(true)
	case 1:
		// One step ago - dimmer green background
		return lipgloss.NewStyle().Background(lipgloss.Color("42")).Foreground(lipgloss.Color("0"))
	case 2:
		// Two steps ago - very dim green background
		return lipgloss.NewStyle().Background(lipgloss.Color("28")).Foreground(lipgloss.Color("15"))
	default:
		// Normal - no special styling
		return lipgloss.NewStyle()
	}
}

// View implements the bubbletea Model interface
func (m *debuggerModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	// Initialize disassembly if needed
	if len(m.disassembly) == 0 {
		m.initializeDisassembly()
	}

	// Define styles
	borderStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(1)
	focusedStyle := borderStyle.Copy().BorderForeground(lipgloss.Color("62"))    // Blue
	unfocusedStyle := borderStyle.Copy().BorderForeground(lipgloss.Color("240")) // Gray

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14")) // Cyan

	// Calculate panel dimensions - new layout: Instructions(left) | Registers(right) over Memory(bottom)
	topPanelHeight := (m.height - 12) / 2 // Split vertically, leave space for title and help
	bottomPanelHeight := m.height - topPanelHeight - 12

	instrWidth := (m.width * 2) / 3      // Instructions get 2/3 of width
	regWidth := m.width - instrWidth - 6 // Registers get remaining width

	// Build instruction panel (main focus - left side)
	instrStyle := unfocusedStyle
	if m.focused == "instructions" {
		instrStyle = focusedStyle
	}
	instrPanel := m.buildInstructionPanel(instrWidth-4, topPanelHeight-2)
	instructions := instrStyle.Render(instrPanel)

	// Build register panel (right side)
	registerStyle := unfocusedStyle
	if m.focused == "registers" {
		registerStyle = focusedStyle
	}
	registerPanel := m.buildRegisterPanel(regWidth-4, topPanelHeight-2)
	registers := registerStyle.Render(registerPanel)

	// Build memory panel (bottom, full width)
	memStyle := unfocusedStyle
	if m.focused == "memory" {
		memStyle = focusedStyle
	}
	memPanel := m.buildMemoryPanel(m.width-4, bottomPanelHeight-2)
	memory := memStyle.Render(memPanel)

	// Combine top panels horizontally
	topPanels := lipgloss.JoinHorizontal(lipgloss.Top, instructions, registers)

	// Combine top and bottom panels vertically
	panels := lipgloss.JoinVertical(lipgloss.Left, topPanels, memory)

	// Add title and help
	title := titleStyle.Render("🔧 ARM64 Emulator Debugger")
	help := "Keys: [n/space] Step • [r] Reset • [tab] Switch Panel • [q] Quit"

	return fmt.Sprintf("%s\n\n%s\n\n%s", title, panels, help)
}

// initializeDisassembly pre-disassembles instructions for display
func (m *debuggerModel) initializeDisassembly() {
	// Create disassembler engine
	engine := disass.NewMachoDisass(m.binary, &disass.Config{
		Data:         m.instructions,
		StartAddress: m.startAddr,
		Quiet:        true,
		Color:        false,
	})

	// Disassemble all instructions
	asmOutput := disass.Disassemble(engine)

	// Parse the assembly output string to extract individual instructions
	lines := strings.Split(strings.TrimSpace(asmOutput), "\n")

	for i := 0; i < len(m.instructions); i += 4 {
		if i+4 > len(m.instructions) {
			break
		}

		addr := m.startAddr + uint64(i)
		bytes := m.instructions[i : i+4]

		// Find matching disassembly line
		var disasmStr string
		for _, line := range lines {
			if strings.Contains(line, fmt.Sprintf("%x:", addr)) {
				// Parse line format: "0x100000460:  ff 03 01 d1   sub      sp, sp, #0x40"
				parts := strings.SplitN(line, "   ", 2)
				if len(parts) == 2 {
					disasmStr = strings.TrimSpace(parts[1])
					break
				}
			}
		}

		// Fallback if no disassembly found
		if disasmStr == "" {
			// Check if bytes are all zero
			if bytes[0] == 0 && bytes[1] == 0 && bytes[2] == 0 && bytes[3] == 0 {
				disasmStr = "udf      #0" // This matches what we're seeing
			} else {
				disasmStr = fmt.Sprintf("DATA     0x%02x%02x%02x%02x", bytes[0], bytes[1], bytes[2], bytes[3])
			}
		}

		m.disassembly = append(m.disassembly, instructionInfo{
			address:     addr,
			bytes:       bytes,
			disassembly: disasmStr,
			executed:    false,
		})
	}

	// Set current instruction pointer to match starting PC
	for i, instr := range m.disassembly {
		if instr.address == m.currentPC {
			m.currentInstr = i
			break
		}
	}
}

// buildRegisterPanel creates the register display panel with change highlighting
func (m *debuggerModel) buildRegisterPanel(width, height int) string {
	var parts []string

	parts = append(parts, "📋 REGISTERS")
	parts = append(parts, strings.Repeat("─", width))

	// Display general purpose registers in 2 columns with highlighting
	for i := 0; i < 31; i += 2 {
		val1 := m.state.GetX(i)
		reg1Name := fmt.Sprintf("X%d", i)
		reg1Style := m.getRegisterStyle(reg1Name)
		reg1Str := fmt.Sprintf("X%-2d: ", i) + reg1Style.Render(fmt.Sprintf("%016x", val1))

		var reg2Str string
		if i+1 < 31 {
			val2 := m.state.GetX(i + 1)
			reg2Name := fmt.Sprintf("X%d", i+1)
			reg2Style := m.getRegisterStyle(reg2Name)
			reg2Str = "  " + fmt.Sprintf("X%-2d: ", i+1) + reg2Style.Render(fmt.Sprintf("%016x", val2))
		}

		line := reg1Str + reg2Str
		parts = append(parts, line)
	}

	// Add special registers with highlighting
	parts = append(parts, strings.Repeat("─", width))

	spStyle := m.getRegisterStyle("SP")
	spLine := "SP:  " + spStyle.Render(fmt.Sprintf("%016x", m.state.GetSP()))
	parts = append(parts, spLine)

	pcStyle := m.getRegisterStyle("PC")
	pcLine := "PC:  " + pcStyle.Render(fmt.Sprintf("%016x", m.state.GetPC()))
	parts = append(parts, pcLine)

	// Add condition flags with highlighting
	parts = append(parts, strings.Repeat("─", width))
	flags := ""
	if m.state.GetN() {
		flags += "N"
	} else {
		flags += "-"
	}
	if m.state.GetZ() {
		flags += "Z"
	} else {
		flags += "-"
	}
	if m.state.GetC() {
		flags += "C"
	} else {
		flags += "-"
	}
	if m.state.GetV() {
		flags += "V"
	} else {
		flags += "-"
	}

	flagsStyle := m.getRegisterStyle("FLAGS")
	flagsLine := "FLAGS: " + flagsStyle.Render(flags)
	parts = append(parts, flagsLine)

	parts = append(parts, fmt.Sprintf("STEPS: %d", m.stepCount))

	return strings.Join(parts, "\n")
}

// buildInstructionPanel creates the instruction display panel
func (m *debuggerModel) buildInstructionPanel(width, height int) string {
	var b strings.Builder

	b.WriteString("⚙️  INSTRUCTIONS\n")
	b.WriteString(strings.Repeat("─", width) + "\n")

	// Show instructions around current PC
	startIdx := m.currentInstr - 5
	if startIdx < 0 {
		startIdx = 0
	}

	endIdx := startIdx + height - 4 // Leave space for header
	if endIdx > len(m.disassembly) {
		endIdx = len(m.disassembly)
	}

	for i := startIdx; i < endIdx; i++ {
		instr := m.disassembly[i]
		prefix := "  "

		if instr.address == m.currentPC {
			prefix = "▶️"
		} else if instr.executed {
			prefix = "✅"
		}

		// Format instruction line
		line := fmt.Sprintf("%s %08x: %02x%02x%02x%02x  %s",
			prefix,
			instr.address,
			instr.bytes[0], instr.bytes[1], instr.bytes[2], instr.bytes[3],
			instr.disassembly)

		if len(line) > width {
			line = line[:width]
		}
		b.WriteString(line + "\n")
	}

	return b.String()
}

// buildMemoryPanel creates the memory display panel showing stack memory
func (m *debuggerModel) buildMemoryPanel(width, height int) string {
	var b strings.Builder

	b.WriteString("💾 STACK MEMORY\n")
	b.WriteString(strings.Repeat("─", width) + "\n")

	// Show stack memory around current SP (stack grows downward)
	// Start from SP-64 and show memory upward to SP+64 to see both directions
	baseAddr := (m.state.GetSP() - 64) & ^uint64(0xF) // Align to 16 bytes, start below SP
	spAddr := m.state.GetSP()

	for i := 0; i < height-4; i++ { // Leave space for header
		addr := baseAddr + uint64(i*16)

		// Try to read 16 bytes from state memory
		bytes := make([]byte, 16)
		hasData := false
		for j := 0; j < 16; j++ {
			if data, err := m.state.ReadMemory(addr+uint64(j), 1); err == nil && len(data) > 0 {
				bytes[j] = data[0]
				if data[0] != 0 {
					hasData = true
				}
			}
		}

		// Skip lines that are all zeros unless they're near the SP
		if !hasData && (addr < spAddr-32 || addr > spAddr+32) {
			continue
		}

		// Format memory line with SP marker
		hexStr := fmt.Sprintf("%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
			bytes[0], bytes[1], bytes[2], bytes[3],
			bytes[4], bytes[5], bytes[6], bytes[7],
			bytes[8], bytes[9], bytes[10], bytes[11],
			bytes[12], bytes[13], bytes[14], bytes[15])

		// Create ASCII representation
		ascii := ""
		for _, b := range bytes {
			if b >= 32 && b <= 126 {
				ascii += string(b)
			} else {
				ascii += "."
			}
		}

		// Add SP marker if current SP falls within this line
		prefix := "  "
		if spAddr >= addr && spAddr < addr+16 {
			prefix = "SP"
		}

		line := fmt.Sprintf("%s %08x: %s  %s", prefix, addr, hexStr, ascii)
		if len(line) > width {
			line = line[:width]
		}
		b.WriteString(line + "\n")
	}

	return b.String()
}
