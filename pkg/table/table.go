package table

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// getTerminalSize returns the terminal width and height
func getTerminalSize() (width, height int) {
	// Try to get terminal size from stdout
	if w, h, err := term.GetSize(int(os.Stdout.Fd())); err == nil {
		return w, h
	}
	// Fallback to reasonable defaults
	return 120, 30
}

// TableStyle defines the visual styling for tables
type TableStyle struct {
	Header    lipgloss.Style
	Cell      lipgloss.Style
	Border    lipgloss.Style
	Separator string
}

// PlainTableStyle returns a plain, boring table style with no colors
func PlainTableStyle() TableStyle {
	return TableStyle{
		Header: lipgloss.NewStyle().
			Bold(true).
			PaddingLeft(1).
			PaddingRight(1),
		Cell: lipgloss.NewStyle().
			PaddingLeft(1).
			PaddingRight(1),
		Border:    lipgloss.NewStyle(),
		Separator: "|",
	}
}

// StyledTableStyle returns a colorful, styled table
func StyledTableStyle() TableStyle {
	return TableStyle{
		Header: lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			PaddingLeft(1).
			PaddingRight(1),
		Cell: lipgloss.NewStyle().
			PaddingLeft(1).
			PaddingRight(1),
		Border: lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()),
		Separator: "|",
	}
}

// DefaultTableStyle returns a plain table styling (for users who hate colors)
func DefaultTableStyle() TableStyle {
	return PlainTableStyle()
}

// Table represents a simple table renderer using lipgloss
type Table struct {
	headers     []string
	rows        [][]string
	style       TableStyle
	autoWrap    bool
	alignment   []lipgloss.Position
	columnWidth []int
}

// NewTable creates a new table with default (plain) styling
func NewTable() *Table {
	return &Table{
		style:     DefaultTableStyle(),
		autoWrap:  true,
		alignment: []lipgloss.Position{},
	}
}

// NewPlainTable creates a new table with plain styling (no colors)
func NewPlainTable() *Table {
	return &Table{
		style:     PlainTableStyle(),
		autoWrap:  true,
		alignment: []lipgloss.Position{},
	}
}

// NewStyledTable creates a new table with colorful styling
func NewStyledTable() *Table {
	return &Table{
		style:     StyledTableStyle(),
		autoWrap:  true,
		alignment: []lipgloss.Position{},
	}
}

// NewTableWithStyle creates a new table with custom styling
func NewTableWithStyle(style TableStyle) *Table {
	return &Table{
		style:     style,
		autoWrap:  true,
		alignment: []lipgloss.Position{},
	}
}

// SetHeaders sets the table headers
func (t *Table) SetHeaders(headers []string) {
	t.headers = headers
	// Initialize alignment slice if not set
	if len(t.alignment) == 0 {
		t.alignment = make([]lipgloss.Position, len(headers))
		for i := range t.alignment {
			t.alignment[i] = lipgloss.Left
		}
	}
}

// SetAlignment sets the alignment for each column
func (t *Table) SetAlignment(align lipgloss.Position) {
	for i := range t.alignment {
		t.alignment[i] = align
	}
}

// AppendRow adds a single row to the table
func (t *Table) AppendRow(row []string) {
	t.rows = append(t.rows, row)
}

// AppendBulk adds multiple rows to the table
func (t *Table) AppendBulk(rows [][]string) {
	t.rows = append(t.rows, rows...)
}

// SetAutoWrapText sets whether text should auto-wrap
func (t *Table) SetAutoWrapText(wrap bool) {
	t.autoWrap = wrap
}

// SetStyle changes the table style
func (t *Table) SetStyle(style TableStyle) {
	t.style = style
}

// UsePlainStyle switches to plain (boring) styling
func (t *Table) UsePlainStyle() {
	t.style = PlainTableStyle()
}

// UseStyledStyle switches to colorful styling
func (t *Table) UseStyledStyle() {
	t.style = StyledTableStyle()
}

// calculateColumnWidths determines the optimal width for each column
func (t *Table) calculateColumnWidths() {
	if len(t.headers) == 0 {
		return
	}

	t.columnWidth = make([]int, len(t.headers))

	// Start with header widths
	for i, header := range t.headers {
		t.columnWidth[i] = len(header)
	}

	// Check all rows for maximum width
	for _, row := range t.rows {
		for i, cell := range row {
			if i < len(t.columnWidth) && len(cell) > t.columnWidth[i] {
				t.columnWidth[i] = len(cell)
			}
		}
	}

	// Add padding for better appearance
	for i := range t.columnWidth {
		t.columnWidth[i] += 2 // Account for padding
	}
}

// renderRow renders a single row with proper alignment and styling
func (t *Table) renderRow(row []string, isHeader bool) string {
	var cells []string

	for i, cell := range row {
		width := t.columnWidth[i]
		align := lipgloss.Left
		if i < len(t.alignment) {
			align = t.alignment[i]
		}

		var style lipgloss.Style
		if isHeader {
			style = t.style.Header
		} else {
			style = t.style.Cell
		}

		// Apply width and alignment
		renderedCell := style.Width(width).Align(align).Render(cell)
		cells = append(cells, renderedCell)
	}

	return strings.Join(cells, t.style.Separator)
}

// Render generates the complete table as a string
func (t *Table) Render() string {
	if len(t.headers) == 0 && len(t.rows) == 0 {
		return ""
	}

	t.calculateColumnWidths()

	var output strings.Builder

	// Render headers if they exist
	if len(t.headers) > 0 {
		headerRow := t.renderRow(t.headers, true)
		output.WriteString(headerRow)
		output.WriteString("\n")

		// Add separator line under headers
		var separators []string
		for _, width := range t.columnWidth {
			separators = append(separators, strings.Repeat("-", width))
		}
		separatorRow := strings.Join(separators, "+")
		output.WriteString(separatorRow)
		output.WriteString("\n")
	}

	// Render data rows
	for _, row := range t.rows {
		dataRow := t.renderRow(row, false)
		output.WriteString(dataRow)
		output.WriteString("\n")
	}

	return strings.TrimRight(output.String(), "\n")
}

// RenderToWriter writes the table output to any writer (maintains tablewriter compatibility)
func (t *Table) RenderToWriter(w fmt.State, verb rune) {
	fmt.Fprint(w, t.Render())
}

// NewStringBuilderTable creates a table that writes to a strings.Builder
func NewStringBuilderTable(sb *strings.Builder) *Table {
	return NewTable()
}

// Custom table that writes directly to strings.Builder
type StringBuilderTable struct {
	*Table
	builder *strings.Builder
}

// NewStringBuilderTableWriter creates a table that writes to a strings.Builder
func NewStringBuilderTableWriter(sb *strings.Builder) *StringBuilderTable {
	return &StringBuilderTable{
		Table:   NewTable(),
		builder: sb,
	}
}

// SetHeader sets the headers and maintains compatibility
func (sbt *StringBuilderTable) SetHeader(headers []string) {
	sbt.Table.SetHeaders(headers)
}

// SetBorders is a no-op for compatibility
func (sbt *StringBuilderTable) SetBorders(border any) {
	// No-op for compatibility
}

// SetCenterSeparator sets the separator
func (sbt *StringBuilderTable) SetCenterSeparator(sep string) {
	sbt.style.Separator = sep
}

// SetAlignment sets alignment
func (sbt *StringBuilderTable) SetAlignment(align int) {
	var lipglossAlign lipgloss.Position
	switch align {
	case 1: // ALIGN_LEFT
		lipglossAlign = lipgloss.Left
	case 2: // ALIGN_CENTER
		lipglossAlign = lipgloss.Center
	case 3: // ALIGN_RIGHT
		lipglossAlign = lipgloss.Right
	default:
		lipglossAlign = lipgloss.Left
	}
	sbt.Table.SetAlignment(lipglossAlign)
}

// Render writes the table directly to the strings.Builder
func (sbt *StringBuilderTable) Render() {
	output := sbt.Table.Render()
	sbt.builder.WriteString(output)
}

// BubbleTable wraps the advanced bubbles/table component
type BubbleTable struct {
	table  table.Model
	data   [][]string
	styled bool
}

// NewBubbleTable creates a new interactive table using bubbles/table with terminal-aware sizing
func NewBubbleTable(headers []string, styled bool) *BubbleTable {
	termWidth, termHeight := getTerminalSize()

	// Calculate initial column widths based on terminal width
	availableWidth := termWidth - 4 // Account for borders and padding
	defaultColWidth := availableWidth / len(headers)
	if defaultColWidth < 8 {
		defaultColWidth = 8
	} else if defaultColWidth > 25 {
		defaultColWidth = 25
	}

	columns := make([]table.Column, len(headers))
	for i, header := range headers {
		columns[i] = table.Column{
			Title: header,
			Width: defaultColWidth,
		}
	}

	// Always use styled tables for BubbleTable - it looks much better
	tableStyle := table.DefaultStyles()
	if styled {
		// Enhanced colorful styling
		tableStyle.Header = tableStyle.Header.
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")).
			BorderBottom(true).
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4"))
		tableStyle.Selected = tableStyle.Selected.
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#F25D94")).
			Bold(true)
	} else {
		// Clean but styled appearance
		tableStyle.Header = tableStyle.Header.
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")).
			BorderBottom(true).
			Bold(true)
		tableStyle.Selected = tableStyle.Selected.
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("57")).
			Bold(false)
	}

	// Calculate table height to use most of the terminal
	// Account for: title (2 lines) + filter area (2 lines) + help (1 line) + margins (2 lines) = 7 lines
	tableHeight := max(termHeight-7, 5) // 5 is minimum height for usability

	t := table.New(
		table.WithColumns(columns),
		table.WithFocused(true),
		table.WithHeight(tableHeight),
		// Don't force width - let it size based on content
	)
	t.SetStyles(tableStyle)

	return &BubbleTable{
		table:  t,
		styled: styled,
	}
}

// SetData sets the table data and auto-adjusts column widths based on content
func (bt *BubbleTable) SetData(data [][]string) {
	bt.data = data

	// Calculate optimal column widths based on content (not terminal width)
	columns := bt.table.Columns()
	if len(data) > 0 && len(columns) > 0 {
		for colIdx := range columns {
			maxWidth := len(columns[colIdx].Title) // Start with header width
			for _, row := range data {
				if colIdx < len(row) {
					cellWidth := len(row[colIdx])
					if cellWidth > maxWidth {
						maxWidth = cellWidth
					}
				}
			}

			// Apply only reasonable limits, not terminal width constraints
			if maxWidth > 50 {
				maxWidth = 50 // Cap very long content
			} else if maxWidth < 8 {
				maxWidth = 8 // Minimum for readability
			}

			columns[colIdx].Width = maxWidth
		}

		bt.table.SetColumns(columns)
	}

	rows := make([]table.Row, len(data))
	for i, row := range data {
		rows[i] = table.Row(row)
	}
	bt.table.SetRows(rows)
}

// AppendData adds rows to the table
func (bt *BubbleTable) AppendData(data [][]string) {
	bt.data = append(bt.data, data...)
	bt.SetData(bt.data)
}

// GetModel returns the underlying bubbles/table model for use in bubbletea apps
func (bt *BubbleTable) GetModel() table.Model {
	return bt.table
}

// RenderStatic renders the table as a static string (non-interactive)
func (bt *BubbleTable) RenderStatic() string {
	return bt.table.View()
}

// InteractiveTableModel implements tea.Model for interactive table display
type InteractiveTableModel struct {
	table        *BubbleTable
	originalData [][]string
	filteredData [][]string
	filterMode   bool
	filterText   string
	headers      []string
	title        string
}

// NewInteractiveTable creates a new interactive table model
func NewInteractiveTable(headers []string, data [][]string, styled bool) *InteractiveTableModel {
	return NewInteractiveTableWithTitle("📱 iOS Device List", headers, data, styled)
}

// NewInteractiveTableWithTitle creates a new interactive table model with custom title
func NewInteractiveTableWithTitle(title string, headers []string, data [][]string, styled bool) *InteractiveTableModel {
	bt := NewBubbleTable(headers, styled)
	bt.SetData(data)
	return &InteractiveTableModel{
		table:        bt,
		originalData: data,
		filteredData: data,
		headers:      headers,
		filterMode:   false,
		filterText:   "",
		title:        title,
	}
}

func (m *InteractiveTableModel) Init() tea.Cmd {
	return nil
}

func (m *InteractiveTableModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.filterMode {
			// Handle filter mode
			switch msg.String() {
			case "enter", "esc":
				// Exit filter mode
				m.filterMode = false
				if msg.String() == "esc" {
					// Clear filter on escape
					m.filterText = ""
					m.filteredData = m.originalData
					m.table.SetData(m.filteredData)
				}
			case "backspace":
				// Remove last character
				if len(m.filterText) > 0 {
					m.filterText = m.filterText[:len(m.filterText)-1]
					m.applyFilter()
				}
			case "ctrl+c":
				return m, tea.Quit
			default:
				// Add character to filter
				if len(msg.String()) == 1 {
					m.filterText += msg.String()
					m.applyFilter()
				}
			}
		} else {
			// Handle normal navigation mode
			switch msg.String() {
			case "ctrl+c", "q":
				return m, tea.Quit
			case "esc":
				// Clear any active filter
				if m.filterText != "" {
					m.filterText = ""
					m.filteredData = m.originalData
					m.table.SetData(m.filteredData)
				}
			case "/":
				// Enter filter mode
				m.filterMode = true
			default:
				// Pass other keys to table for navigation
				m.table.table, cmd = m.table.table.Update(msg)
			}
		}
	}

	return m, cmd
}

// applyFilter filters the data based on the current filter text
func (m *InteractiveTableModel) applyFilter() {
	if m.filterText == "" {
		m.filteredData = m.originalData
	} else {
		m.filteredData = [][]string{}
		filterLower := strings.ToLower(m.filterText)

		for _, row := range m.originalData {
			// Search in all columns
			found := false
			for _, cell := range row {
				if strings.Contains(strings.ToLower(cell), filterLower) {
					found = true
					break
				}
			}
			if found {
				m.filteredData = append(m.filteredData, row)
			}
		}
	}

	// Update the table with filtered data
	m.table.SetData(m.filteredData)
}

func (m *InteractiveTableModel) View() string {
	var b strings.Builder

	// Title with filter status
	title := m.title
	if m.filterText != "" {
		title += fmt.Sprintf(" (filtered: %d/%d)", len(m.filteredData), len(m.originalData))
	}
	b.WriteString(title + "\n\n")

	// Table
	b.WriteString(m.table.table.View())
	b.WriteString("\n")

	// Filter input
	if m.filterMode {
		filterStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("86")).
			Bold(true)
		b.WriteString("\n" + filterStyle.Render("Filter: /"+m.filterText+"█"))
		b.WriteString("\n")
	} else if m.filterText != "" {
		filterStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Italic(true)
		b.WriteString("\n" + filterStyle.Render("Active filter: "+m.filterText+" (press esc to clear)"))
		b.WriteString("\n")
	}

	// Help text
	helpStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	if m.filterMode {
		b.WriteString(helpStyle.Render("enter: apply filter • esc: cancel • backspace: delete • ctrl+c: quit"))
	} else {
		b.WriteString(helpStyle.Render("↑/↓: navigate • /: filter • esc: clear filter • q/ctrl+c: quit"))
	}

	return b.String()
}
