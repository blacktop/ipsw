package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	zone "github.com/lrstanley/bubblezone"
)

var (
	subtle    = lipgloss.AdaptiveColor{Light: "#D9DCCF", Dark: "#383838"}
	highlight = lipgloss.AdaptiveColor{Light: "#874BFD", Dark: "#7D56F4"}
	special   = lipgloss.AdaptiveColor{Light: "#43BF6D", Dark: "#73F59F"}

	divider = lipgloss.NewStyle().
		SetString("•").
		Padding(0, 1).
		Foreground(subtle).
		String()
)

var (
	listStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), false, true, false, false).
			BorderForeground(subtle).
			MarginRight(2)

	listHeader = lipgloss.NewStyle().
			BorderStyle(lipgloss.NormalBorder()).
			BorderBottom(true).
			BorderForeground(subtle).
			MarginRight(2).
			Render

	listItemStyle = lipgloss.NewStyle().PaddingLeft(2).Render

	checkMark = lipgloss.NewStyle().SetString("✓").
			Foreground(special).
			PaddingRight(1).
			String()

	listDoneStyle = func(s string) string {
		return checkMark + lipgloss.NewStyle().
			Strikethrough(true).
			Foreground(lipgloss.AdaptiveColor{Light: "#969B86", Dark: "#696969"}).
			Render(s)
	}
)

type ListItem struct {
	Name string
	Done bool
}

type List struct {
	ID     string
	Height int
	Width  int

	Title string
	Items []ListItem
}

func (m List) Init() tea.Cmd {
	return nil
}

func (m List) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
	case tea.MouseMsg:
		if msg.Type != tea.MouseLeft {
			return m, nil
		}

		for i, item := range m.Items {
			// Check each item to see if it's in bounds.
			if zone.Get(m.ID + item.Name).InBounds(msg) {
				m.Items[i].Done = !m.Items[i].Done
				break
			}
		}

		return m, nil
	}
	return m, nil
}

func (m List) View() string {
	out := []string{listHeader(m.Title)}

	for _, item := range m.Items {
		if item.Done {
			out = append(out, zone.Mark(m.ID+item.Name, listDoneStyle(item.Name)))
			continue
		}

		out = append(out, zone.Mark(m.ID+item.Name, listItemStyle(item.Name)))
	}

	return listStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left, out...),
	)
}
