package tui

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-termimg"
	"github.com/blacktop/ipsw/pkg/wallpaper"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// wallpaperItem represents a wallpaper in the list
type wallpaperItem struct {
	asset      wallpaper.WallpaperAsset
	downloaded bool
	index      int
}

func (w wallpaperItem) FilterValue() string { return w.asset.WallpaperName }
func (w wallpaperItem) Title() string       { return w.asset.WallpaperName }
func (w wallpaperItem) Description() string {
	status := ""
	if w.downloaded {
		status = "✅ "
	}
	return fmt.Sprintf("%s%s • %s • %s", status, w.asset.WallpaperLogicalScreenClass, w.asset.Build, formatSize(w.asset.DownloadSize))
}

var (
	// Color palette
	primaryColor   = lipgloss.Color("#7D56F4")
	secondaryColor = lipgloss.Color("#F25D94")
	accentColor    = lipgloss.Color("#04B575")
	textColor      = lipgloss.Color("#FAFAFA")
	mutedColor     = lipgloss.Color("#626262")
	errorColor     = lipgloss.Color("#FF5F87")

	// Title style
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(textColor).
			Background(primaryColor).
			PaddingLeft(2).
			PaddingRight(2).
			MarginBottom(1)

	// Panel border styles
	panelBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(primaryColor).
				Padding(1)

	// List styles
	itemStyle = lipgloss.NewStyle().
			PaddingLeft(1).
			Foreground(textColor)

	selectedItemStyle = lipgloss.NewStyle().
				PaddingLeft(1).
				Foreground(textColor).
				Background(primaryColor).
				Bold(true)

	// Error style
	errorStyle = lipgloss.NewStyle().
			Foreground(errorColor).
			Bold(true)

	// Info style
	infoStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Italic(true)

	// Legend styles
	legendStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			Background(lipgloss.Color("#1A1A1A")).
			PaddingLeft(1).
			PaddingRight(1).
			MarginTop(1)

	legendKeyStyle = lipgloss.NewStyle().
			Foreground(accentColor).
			Bold(true)
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


type model struct {
	list           list.Model
	help           help.Model
	spinner        spinner.Model
	viewport       viewport.Model
	loading        bool
	loadingPreview bool
	assets         []wallpaper.WallpaperAsset
	download       map[int]bool // index -> downloaded
	quitting       bool
	status         string
	imageWidget    *termimg.ImageWidget
	widgetCache    map[string]*termimg.ImageWidget
	termWidth      int
	termHeight     int
	lastImageID    string
	imageError     error
	virtualMode    bool
}

func NewWallpaperTUI(ctx context.Context) (*model, error) {
	// Fetch wallpapers first
	wp, err := wallpaper.FetchWallpaperPlist()
	if err != nil {
		return nil, err
	}

	// Create list items from wallpaper assets
	var items []list.Item
	for i, asset := range wp.Assets {
		items = append(items, wallpaperItem{
			asset: asset,
			downloaded: false,
			index: i,
		})
	}

	// Create list with custom styling
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = ""
	l.SetShowStatusBar(false)
	l.SetShowPagination(false)
	l.SetShowHelp(false)
	l.SetFilteringEnabled(false)

	// Customize the list delegate
	delegate := list.NewDefaultDelegate()
	delegate.Styles.SelectedTitle = selectedItemStyle
	delegate.Styles.SelectedDesc = selectedItemStyle.Foreground(mutedColor)
	delegate.Styles.NormalTitle = itemStyle
	delegate.Styles.NormalDesc = itemStyle.Foreground(mutedColor)
	l.SetDelegate(delegate)

	m := &model{
		list:        l,
		help:        help.New(),
		spinner:     spinner.New(),
		viewport:    viewport.New(0, 0),
		loading:     false,
		assets:      wp.Assets,
		download:    make(map[int]bool),
		widgetCache: make(map[string]*termimg.ImageWidget),
		status:      fmt.Sprintf("Loaded %d wallpapers", len(wp.Assets)),
	}
	m.spinner.Spinner = spinner.Dot

	return m, nil
}

func (m *model) Init() tea.Cmd {
	return nil
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q", "esc":
			// Clear images when using virtual mode
			if m.virtualMode {
				for _, widget := range m.widgetCache {
					widget.Clear()
				}
			}
			m.quitting = true
			return m, tea.Quit
		case "v":
			// Toggle virtual mode (Kitty only)
			if termimg.KittySupported() {
				m.virtualMode = !m.virtualMode
				// Clear cache to force re-render
				for _, widget := range m.widgetCache {
					widget.Clear()
				}
				m.widgetCache = make(map[string]*termimg.ImageWidget)
				m.lastImageID = ""
			}
		case "enter":
			if item, ok := m.list.SelectedItem().(wallpaperItem); ok {
				if !m.download[item.index] {
					m.status = "Downloading..."
					return m, downloadWallpaperCmd(item.asset, item.index)
				}
			}
		case "p":
			if item, ok := m.list.SelectedItem().(wallpaperItem); ok {
				wallpaperID := fmt.Sprintf("%s_%s", item.asset.WallpaperName, item.asset.WallpaperLogicalScreenClass)
				// If already showing this preview, clear it
				if m.imageWidget != nil && m.lastImageID == wallpaperID {
					termimg.ClearAll()
					m.imageWidget = nil
					m.loadingPreview = false
					m.status = "Preview cleared"
				} else {
					// Check cache first
					if widget, found := m.widgetCache[wallpaperID]; found {
						// For cached images, only clear after we're ready to show the new one
						termimg.ClearAll()
						m.imageWidget = widget
						m.lastImageID = wallpaperID
						m.loadingPreview = false
						m.status = "Preview loaded (cached)"
					} else {
						// For non-cached images, start loading but keep current image visible
						m.loadingPreview = true
						m.status = "Loading preview for " + item.asset.WallpaperName + "..."
						return m, previewWallpaperCmd(item.asset, item.index)
					}
				}
			}
		case "l":
			N := min(len(m.assets), 5)
			cmds := make([]tea.Cmd, 0, N)
			for i := range N {
				if !m.download[i] {
					cmds = append(cmds, downloadWallpaperCmd(m.assets[i], i))
				}
			}
			m.status = "Downloading latest..."
			return m, tea.Batch(cmds...)
		default:
			// Let the list handle all other key events (navigation, etc.)
			m.list, cmd = m.list.Update(msg)
		}
	case tea.WindowSizeMsg:
		m.termWidth = msg.Width
		m.termHeight = msg.Height
		// Account for title, borders, and legend
		availableHeight := msg.Height - 6
		m.viewport.Width = (msg.Width / 2) - 4
		m.viewport.Height = availableHeight
		
		// Update list size for the left panel
		leftPanelWidth := (msg.Width / 2) - 4
		m.list.SetWidth(leftPanelWidth)
		m.list.SetHeight(availableHeight - 2) // Account for borders
	case downloadResultMsg:
		if msg.err != nil {
			m.status = "Download failed: " + msg.err.Error()
		} else {
			m.download[msg.row] = true
			// Update the list item to show downloaded status
			items := m.list.Items()
			if msg.row < len(items) {
				if item, ok := items[msg.row].(wallpaperItem); ok {
					item.downloaded = true
					items[msg.row] = item
					m.list.SetItems(items)
				}
			}
			m.status = "Downloaded: " + msg.name
		}
	case previewResultMsg:
		m.loadingPreview = false // Always clear loading state
		if msg.err != nil {
			m.status = "Preview failed: " + msg.err.Error()
			m.imageError = msg.err
			// Don't clear current image on error - keep it visible
		} else {
			m.status = "Preview loaded"
			m.imageError = nil
			
			// Create proper wallpaper ID from asset info
			if msg.row < len(m.assets) {
				asset := m.assets[msg.row]
				wallpaperID := fmt.Sprintf("%s_%s", asset.WallpaperName, asset.WallpaperLogicalScreenClass)
				
				var newWidget *termimg.ImageWidget
				if widget, found := m.widgetCache[wallpaperID]; found {
					newWidget = widget
				} else {
					// Create new image widget from bytes
					img, err := termimg.From(bytes.NewReader(msg.imgBytes))
					if err != nil {
						m.imageError = err
						// Don't clear current image on error - keep it visible
						return m, cmd
					} else {
						widget := termimg.NewImageWidget(img)
						if m.virtualMode && termimg.KittySupported() {
							widget.SetProtocol(termimg.Kitty).SetVirtual(true)
						}
						newWidget = widget
						m.widgetCache[wallpaperID] = widget
					}
				}
				
				// Only clear previous image when new one is successfully created
				if newWidget != nil {
					termimg.ClearAll()
					m.imageWidget = newWidget
					m.lastImageID = wallpaperID
				}
			}
		}
	}

	// Don't update lastImageID during navigation - only update it when actually previewing
	// This prevents confusion between "selected item" and "previewed item"

	// Update the image widget's size and viewport content
	if m.imageWidget != nil {
		m.imageWidget.SetSizeWithCorrection(m.viewport.Width, m.viewport.Height)
		// Don't set viewport content when displaying an image
	}
	
	// Set viewport content for when there's no image to show
	if m.imageWidget == nil {
		if m.loadingPreview {
			m.viewport.SetContent(infoStyle.Render("🔄 Loading preview..."))
		} else if m.imageError != nil {
			m.viewport.SetContent(errorStyle.Render("❌ " + m.imageError.Error()))
		} else {
			// Show minimal message instead of redundant legend
			m.viewport.SetContent(infoStyle.Render("Select a wallpaper and press 'p' to preview"))
		}
	}

	return m, cmd
}

func (m *model) View() string {
	if m.quitting {
		return "Goodbye! 👋"
	}

	if m.termWidth == 0 || m.termHeight == 0 {
		return "Loading..."
	}

	var b strings.Builder

	// Title bar
	title := fmt.Sprintf("Apple Wallpapers - %d available", len(m.list.Items()))
	if m.virtualMode {
		title += " [VIRTUAL MODE]"
	}
	b.WriteString(titleStyle.Width(m.termWidth).Render(title))
	b.WriteString("\n")

	// Calculate panel dimensions
	leftPanelWidth := m.termWidth/2 - 2
	rightPanelWidth := m.termWidth/2 - 2
	panelHeight := m.termHeight - 6 // Account for title and legend

	// File list panel using the list component
	leftPanel := panelBorderStyle.
		Width(leftPanelWidth).
		Height(panelHeight).
		Render(m.list.View())

	// Image preview panel
	var rightPanelContent string
	if m.imageWidget != nil {
		// When showing an image, we don't need any viewport content
		// The image will be drawn over the empty panel
		rightPanelContent = ""
	} else {
		// For non-images, errors, or loading states, use the viewport
		rightPanelContent = m.viewport.View()
	}
	
	rightPanel := panelBorderStyle.
		Width(rightPanelWidth).
		Height(panelHeight).
		Render(rightPanelContent)

	// Combine panels horizontally
	panels := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, rightPanel)
	b.WriteString(panels)

	// Append the image rendering commands AFTER the text UI has been built
	b.WriteString(m.viewImage())

	// Navigation legend  
	legend := []string{
		legendKeyStyle.Render("↑/k") + " up",
		legendKeyStyle.Render("↓/j") + " down",
		legendKeyStyle.Render("p") + " preview",
		legendKeyStyle.Render("enter") + " download",
		legendKeyStyle.Render("l") + " latest",
	}

	if termimg.KittySupported() {
		legend = append(legend, legendKeyStyle.Render("v")+" virtual")
	}
	legend = append(legend, legendKeyStyle.Render("q/esc")+" quit")

	legendText := "Navigation: " + strings.Join(legend, " • ")
	b.WriteString("\n")
	b.WriteString(legendStyle.Width(m.termWidth).Render(legendText))

	return b.String()
}

// viewImage renders the image using virtual positioning to avoid layout corruption
func (m *model) viewImage() string {
	if m.imageWidget == nil || m.imageError != nil {
		return ""
	}

	// Get the position of the right panel to draw the image over it
	// Title(1) + Margin(1) + Panel Border(1) + Panel Padding(1) = 4
	imageY := 4
	// Left Panel Width + Spacing(1) + Panel Border(1) + Panel Padding(1) = m.termWidth/2 + 3
	imageX := m.termWidth/2 + 3

	var finalCmd strings.Builder

	// 2. Save the cursor position
	finalCmd.WriteString("\033[s")

	// 3. Move the cursor to the correct position inside the right panel
	finalCmd.WriteString(fmt.Sprintf("\033[%d;%dH", imageY, imageX))

	// 4. Render the image
	if imageStr, err := m.imageWidget.Render(); err == nil && imageStr != "" {
		finalCmd.WriteString(imageStr)
	}

	// 5. Restore the cursor position to prevent layout corruption
	finalCmd.WriteString("\033[u")

	return finalCmd.String()
}

// --- Msgs and Cmds ---

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

type previewResultMsg struct {
	row      int
	imgBytes []byte
	err      error
}

func previewWallpaperCmd(asset wallpaper.WallpaperAsset, row int) tea.Cmd {
	return func() tea.Msg {
		log.Debugf("Previewing wallpaper: %s", asset.WallpaperName)
		url := asset.BaseURL + asset.RelativePath

		// Download and extract thumbnail
		imgBytes, err := wallpaper.ExtractThumbnailBytes(url, "", false)
		if err != nil {
			return previewResultMsg{row: row, err: fmt.Errorf("failed to extract thumbnail: %w", err)}
		}

		if len(imgBytes) == 0 {
			return previewResultMsg{row: row, err: fmt.Errorf("thumbnail not found in wallpaper")}
		}

		return previewResultMsg{row: row, imgBytes: imgBytes, err: nil}
	}
}
