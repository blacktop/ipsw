package tui

import (
	"charm.land/bubbles/v2/list"
	"charm.land/bubbles/v2/viewport"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// CrashlogItem is one report shown in the browser: a list entry (Name/Desc) and
// the pre-rendered report text shown full-screen when it is opened.
type CrashlogItem struct {
	Name    string
	Desc    string
	Content string
}

func (c CrashlogItem) Title() string       { return c.Name }
func (c CrashlogItem) Description() string { return c.Desc }
func (c CrashlogItem) FilterValue() string { return c.Name }

var (
	clBorderColor = lipgloss.Color("#7D56F4")
	clMutedColor  = lipgloss.Color("#626262")
	clAccentColor = lipgloss.Color("#04B575")

	clPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(clBorderColor)

	clHintStyle = lipgloss.NewStyle().
			Foreground(clMutedColor).
			PaddingLeft(1)

	clNoticeStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(clAccentColor).
			Padding(1, 3).
			Align(lipgloss.Center)
)

// crashlogBrowser is a two-mode TUI: a full-screen list of crash reports, and a
// full-screen scrollable view of the selected report (entered with enter/→,
// left with esc/←) so each report gets the whole terminal.
type crashlogBrowser struct {
	list   list.Model
	vp     viewport.Model
	detail bool   // true = showing the full-screen report; false = the list
	notice string // a one-time pop-up shown until the first key press
	width  int
	height int
	ready  bool
}

func newCrashlogBrowser(items []CrashlogItem, notice string) *crashlogBrowser {
	listItems := make([]list.Item, len(items))
	for i, it := range items {
		listItems[i] = it
	}
	l := list.New(listItems, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Crash Reports"
	l.SetShowHelp(false)
	return &crashlogBrowser{list: l, vp: viewport.New(), notice: notice}
}

func (m *crashlogBrowser) Init() tea.Cmd { return nil }

func (m *crashlogBrowser) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// a visible notice swallows the first key press to dismiss itself
	if m.notice != "" {
		if _, ok := msg.(tea.KeyPressMsg); ok {
			m.notice = ""
			return m, nil
		}
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		// The panel is rendered at Width(width-2)/Height(height-3); in lipgloss v2
		// that block size INCLUDES the rounded border, so its content area is two
		// cols / two rows smaller. Size the inner components to that area so they
		// don't overflow and word-wrap off-screen.
		innerW, innerH := msg.Width-4, msg.Height-5
		m.list.SetSize(innerW, innerH)
		m.vp.SetWidth(innerW)
		m.vp.SetHeight(innerH)
		m.ready = true
		return m, nil
	case tea.KeyPressMsg:
		if m.detail {
			return m.updateDetail(msg)
		}
		return m.updateList(msg)
	}

	// non-key messages flow to whichever component is active
	var cmd tea.Cmd
	if m.detail {
		m.vp, cmd = m.vp.Update(msg)
	} else {
		m.list, cmd = m.list.Update(msg)
	}
	return m, cmd
}

// updateList handles keys while the report list is showing.
func (m *crashlogBrowser) updateList(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if m.list.FilterState() != list.Filtering {
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "enter", "right", "l":
			if it, ok := m.list.SelectedItem().(CrashlogItem); ok {
				m.vp.SetContent(it.Content)
				m.vp.GotoTop()
				m.detail = true
			}
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

// updateDetail handles keys while a full-screen report is showing.
func (m *crashlogBrowser) updateDetail(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc", "left", "h", "backspace":
		m.detail = false
		return m, nil
	}
	var cmd tea.Cmd
	m.vp, cmd = m.vp.Update(msg)
	return m, cmd
}

func (m *crashlogBrowser) View() tea.View {
	if !m.ready {
		return tea.NewView("Loading…")
	}

	var body string
	switch {
	case m.detail:
		title := "Crash Report"
		if it, ok := m.list.SelectedItem().(CrashlogItem); ok {
			title = it.Name
		}
		hint := "↑/↓ scroll • esc/← back • q quit"
		report := clPanelStyle.Width(m.width - 2).Height(m.height - 3).Render(m.vp.View())
		body = report + "\n" + clHintStyle.Render(title+"  —  "+hint)
	default:
		hint := "↑/↓ select • enter/→ view • / filter • q quit"
		listView := clPanelStyle.Width(m.width - 2).Height(m.height - 3).Render(m.list.View())
		body = listView + "\n" + clHintStyle.Render(hint)
	}

	// a one-time notice takes over the screen as a centered pop-up
	if m.notice != "" {
		body = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, clNoticeStyle.Render(m.notice))
	}

	v := tea.NewView(body)
	v.AltScreen = true
	return v
}

// RunCrashlogBrowser launches the crash-report browser over items. notice, when
// non-empty, is shown as a one-time centered pop-up dismissed by any key.
func RunCrashlogBrowser(items []CrashlogItem, notice string) error {
	_, err := tea.NewProgram(newCrashlogBrowser(items, notice)).Run()
	return err
}
