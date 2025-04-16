package tui

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/pkg/wallpaper"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	selectedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	downloadedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42")).Bold(true)
	headerStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("245"))
	titleStyle      = lipgloss.NewStyle().Bold(true).
			Foreground(lipgloss.Color("81")).
			Background(lipgloss.Color("236")).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("81")).
			Padding(0, 2).
			Margin(1, 0).
			Align(lipgloss.Center)
)

func gradientText(s string) string {
	colors := []string{"81", "117", "123", "159", "81"}
	runes := []rune(s)
	var out strings.Builder
	for i, r := range runes {
		c := colors[i%len(colors)]
		out.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Render(string(r)))
	}
	return out.String()
}

type keyMap struct {
	Up     key.Binding
	Down   key.Binding
	Enter  key.Binding
	Quit   key.Binding
	Search key.Binding
	Latest key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Up, k.Down, k.Enter, k.Search, k.Latest, k.Quit}
}
func (k keyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.Enter},
		{k.Search, k.Latest, k.Quit},
	}
}

var keys = keyMap{
	Up:     key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:   key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Enter:  key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "download")),
	Search: key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
	Latest: key.NewBinding(key.WithKeys("l"), key.WithHelp("l", "download latest")),
	Quit:   key.NewBinding(key.WithKeys("q", "esc", "ctrl+c"), key.WithHelp("q/esc", "quit")),
}

type model struct {
	table    table.Model
	help     help.Model
	spinner  spinner.Model
	loading  bool
	search   string
	assets   []wallpaper.WallpaperAsset
	download map[int]bool // row index -> downloaded
	quitting bool
	status   string
}

func NewWallpaperTUI(ctx context.Context) (*model, error) {
	m := &model{
		help:     help.New(),
		spinner:  spinner.New(),
		loading:  true,
		download: make(map[int]bool),
		status:   "Fetching wallpapers...",
	}
	m.spinner.Spinner = spinner.Dot

	// Fetch assets to determine column widths
	wp, err := wallpaper.FetchWallpaperPlist()
	if err != nil {
		return m, err
	}
	m.assets = wp.Assets

	// Preload rows for width calculation
	rows := make([]table.Row, len(m.assets))
	for i, a := range m.assets {
		rows[i] = table.Row{
			a.WallpaperName,
			a.WallpaperLogicalScreenClass,
			a.Build,
			fmt.Sprintf("%d", a.ContentVersion),
			formatSize(a.DownloadSize),
			"", // Downloaded
		}
	}

	columns := []table.Column{
		{Title: "Name", Width: 20},
		{Title: "Device", Width: 23},
		{Title: "Build", Width: 10},
		{Title: "Version", Width: 8},
		{Title: "Size", Width: 10},
		{Title: "Downloaded", Width: 12},
	}
	m.table = table.New(table.WithColumns(columns), table.WithFocused(true))
	styles := table.DefaultStyles()
	headerStyle := styles.Header.Bold(true).Foreground(lipgloss.Color("245"))
	styles.Header = headerStyle
	m.table.SetStyles(styles)
	m.table.SetRows(rows)
	m.status = fmt.Sprintf("Loaded %d wallpapers", len(m.assets))

	return m, nil
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, fetchWallpapersCmd)
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch {
		case key.Matches(msg, keys.Quit):
			m.quitting = true
			return m, tea.Quit
		case key.Matches(msg, keys.Up):
			m.table.MoveUp(1)
		case key.Matches(msg, keys.Down):
			m.table.MoveDown(1)
		case key.Matches(msg, keys.Enter):
			row := m.table.Cursor()
			if !m.download[row] {
				m.status = "Downloading..."
				return m, downloadWallpaperCmd(m.assets[row], row)
			}
		case key.Matches(msg, keys.Latest):
			// Download N most recent (let's use 5 for now)
			N := min(len(m.assets), 5)
			cmds := make([]tea.Cmd, 0, N)
			for i := range N {
				if !m.download[i] {
					cmds = append(cmds, downloadWallpaperCmd(m.assets[i], i))
				}
			}
			m.status = "Downloading latest..."
			return m, tea.Batch(cmds...)
		}
	case spinner.TickMsg:
		if m.loading {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
	case wallpapersMsg:
		m.loading = false
		m.assets = msg.assets
		rows := make([]table.Row, len(msg.assets))
		for i, a := range msg.assets {
			rows[i] = table.Row{
				a.WallpaperName,
				a.WallpaperLogicalScreenClass,
				a.Build,
				fmt.Sprintf("%d", a.ContentVersion),
				formatSize(a.DownloadSize),
				"",
			}
		}
		m.table.SetRows(rows)
		m.status = fmt.Sprintf("Loaded %d wallpapers", len(msg.assets))
	case downloadResultMsg:
		if msg.err != nil {
			m.status = "Download failed: " + msg.err.Error()
		} else {
			m.download[msg.row] = true
			rows := m.table.Rows()
			if msg.row < len(rows) && len(rows[msg.row]) > 5 {
				rows[msg.row][5] = "✅"
				m.table.SetRows(rows)
			}
			m.status = "Downloaded: " + msg.name
		}
	}
	return m, nil
}

func (m *model) View() string {
	if m.quitting {
		return "Goodbye!"
	}
	var b strings.Builder
	if m.loading {
		b.WriteString(m.spinner.View() + " " + m.status + "\n")
		return b.String()
	}
	// Center the title above the table, add gradient
	tableWidth := m.table.Width()
	title := "Apple Wallpapers"
	title = gradientText(title)
	if tableWidth > 0 {
		title = lipgloss.PlaceHorizontal(tableWidth, lipgloss.Center, title)
	}
	b.WriteString(titleStyle.Render(title) + "\n")
	b.WriteString(m.table.View() + "\n")
	b.WriteString(m.status + "\n")
	b.WriteString(m.help.View(keys))
	return b.String()
}

// --- Msgs and Cmds ---
type wallpapersMsg struct{ assets []wallpaper.WallpaperAsset }

func fetchWallpapersCmd() tea.Msg {
	wp, err := wallpaper.FetchWallpaperPlist()
	if err != nil {
		return wallpapersMsg{assets: nil}
	}
	return wallpapersMsg{assets: wp.Assets}
}

func formatSize(sz int64) string {
	if sz > 1<<20 {
		return fmt.Sprintf("%.1f MB", float64(sz)/(1<<20))
	}
	if sz > 1<<10 {
		return fmt.Sprintf("%.1f KB", float64(sz)/(1<<10))
	}
	return fmt.Sprintf("%d B", sz)
}

// --- Download logic ---
type downloadResultMsg struct {
	row  int
	name string
	err  error
}

func downloadWallpaperCmd(asset wallpaper.WallpaperAsset, row int) tea.Cmd {
	return func() tea.Msg {
		log.Debugf("%#v", asset)
		url := asset.BaseURL + asset.RelativePath
		resp, err := http.Get(url)
		if err != nil {
			return downloadResultMsg{row: row, name: asset.WallpaperName, err: err}
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return downloadResultMsg{row: row, name: asset.WallpaperName, err: fmt.Errorf("bad status: %s", resp.Status)}
		}
		fname := fmt.Sprintf("%s_%s.zip", strings.ReplaceAll(asset.WallpaperName, " ", "_"), asset.WallpaperLogicalScreenClass)
		out, err := os.Create(fname)
		if err != nil {
			return downloadResultMsg{row: row, name: asset.WallpaperName, err: err}
		}
		defer out.Close()
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return downloadResultMsg{row: row, name: asset.WallpaperName, err: err}
		}
		return downloadResultMsg{row: row, name: asset.WallpaperName, err: nil}
	}
}
