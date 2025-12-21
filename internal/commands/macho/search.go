package macho

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/apex/log"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/magic"
	"github.com/blacktop/ipsw/internal/search"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pkg/errors"
)

// MTE scan TUI primitives
type mteResult struct {
	Dmg   string
	Path  string
	Image string
	Addr  uint64
}

type dmgProgress struct {
	name      string
	current   int
	total     int
	completed bool
	mounting  bool
	progress  progress.Model
}

type mteScanModel struct {
	dmgs    []dmgProgress
	results []mteResult
	done    bool
	err     error
	mu      sync.Mutex
}

type dmgStartMsg struct{ name string }
type dmgMountingMsg struct{ name string }
type dmgProgressMsg struct {
	name   string
	result *mteResult
}
type dmgCompleteMsg struct {
	name  string
	total int
}
type scanCompleteMsg struct{}

func (m mteScanModel) Init() tea.Cmd { return nil }

func (m mteScanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.done && msg.String() == "q" {
			return m, tea.Quit
		}

	case dmgStartMsg:
		m.mu.Lock()
		prog := progress.New(progress.WithDefaultGradient(), progress.WithWidth(40))
		m.dmgs = append(m.dmgs, dmgProgress{name: msg.name, progress: prog})
		m.mu.Unlock()
		return m, nil

	case dmgMountingMsg:
		m.mu.Lock()
		for i := range m.dmgs {
			if m.dmgs[i].name == msg.name {
				m.dmgs[i].mounting = true
				break
			}
		}
		m.mu.Unlock()
		return m, nil

	case dmgProgressMsg:
		m.mu.Lock()
		for i := range m.dmgs {
			if m.dmgs[i].name == msg.name {
				m.dmgs[i].current++
				if m.dmgs[i].total > 0 && m.dmgs[i].current >= m.dmgs[i].total {
					m.dmgs[i].completed = true
				}
				break
			}
		}
		if msg.result != nil {
			m.results = append(m.results, *msg.result)
		}
		m.mu.Unlock()
		return m, nil

	case dmgCompleteMsg:
		m.mu.Lock()
		for i := range m.dmgs {
			if m.dmgs[i].name == msg.name {
				m.dmgs[i].total = msg.total
				if m.dmgs[i].current >= msg.total {
					m.dmgs[i].completed = true
				}
				break
			}
		}
		m.mu.Unlock()
		return m, nil

	case scanCompleteMsg:
		m.done = true
		return m, tea.Quit

	case progress.FrameMsg:
		m.mu.Lock()
		cmds := make([]tea.Cmd, len(m.dmgs))
		for i := range m.dmgs {
			pm, cmd := m.dmgs[i].progress.Update(msg)
			m.dmgs[i].progress = pm.(progress.Model)
			cmds[i] = cmd
		}
		m.mu.Unlock()
		return m, tea.Batch(cmds...)
	}
	return m, nil
}

func (m mteScanModel) View() string {
	if m.err != nil {
		return fmt.Sprintf("Error: %v\n", m.err)
	}

	var s strings.Builder
	pad := lipgloss.NewStyle().PaddingLeft(2)
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4")).MarginBottom(1)
	s.WriteString(pad.Render(title.Render("🔍 Scanning IPSW for MTE Instructions")))
	s.WriteString("\n\n")

	m.mu.Lock()
	dmgs := make([]dmgProgress, len(m.dmgs))
	copy(dmgs, m.dmgs)
	resultsCount := len(m.results)
	m.mu.Unlock()

	totalScanned := 0
	for _, d := range dmgs {
		totalScanned += d.current
		status := "○"
		switch {
		case d.completed:
			status = "✓"
		case d.current > 0:
			status = "⋯"
		case d.mounting:
			status = "↻"
		}
		nameStyle := lipgloss.NewStyle().Bold(true)
		switch {
		case d.completed:
			nameStyle = nameStyle.Foreground(lipgloss.Color("42"))
		case d.current > 0:
			nameStyle = nameStyle.Foreground(lipgloss.Color("yellow"))
		case d.mounting:
			nameStyle = nameStyle.Foreground(lipgloss.Color("cyan"))
		default:
			nameStyle = nameStyle.Foreground(lipgloss.Color("240"))
		}
		s.WriteString(pad.Render(fmt.Sprintf("%s %s", status, nameStyle.Render(d.name))))
		s.WriteString("\n")
		if d.total > 0 {
			pct := float64(d.current) / float64(d.total)
			if pct > 1 {
				pct = 1
			} else if pct < 0 {
				pct = 0
			}
			s.WriteString(pad.Render(fmt.Sprintf("  %s %d/%d", d.progress.ViewAs(pct), d.current, d.total)))
		} else if d.current > 0 {
			s.WriteString(pad.Render(fmt.Sprintf("  %s %d binaries", d.progress.ViewAs(0), d.current)))
		} else if d.mounting {
			s.WriteString(pad.Render(fmt.Sprintf("  %s mounting...", d.progress.ViewAs(0))))
		} else {
			s.WriteString(pad.Render(fmt.Sprintf("  %s pending", d.progress.ViewAs(0))))
		}
		s.WriteString("\n\n")
	}

	statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	s.WriteString(pad.Render(statusStyle.Render(fmt.Sprintf("Total: %d scanned • Found: %d MTE-enabled", totalScanned, resultsCount))))
	s.WriteString("\n\n")

	if m.done {
		stats := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F25D94")).MarginTop(1).MarginBottom(1)
		var pct float64
		if totalScanned > 0 {
			pct = float64(resultsCount) / float64(totalScanned) * 100
		}
		s.WriteString(pad.Render(stats.Render(fmt.Sprintf("✨ STATISTICS: %d/%d = %.2f%% MTE-enabled", resultsCount, totalScanned, pct))))
		s.WriteString("\n\n")

		if resultsCount > 0 {
			var t strings.Builder
			t.WriteString(fmt.Sprintf("%-12s %s %s\n", "DMG", "ADDRESS", "PATH"))
			t.WriteString(strings.Repeat("-", 100) + "\n")
			m.mu.Lock()
			for _, r := range m.results {
				t.WriteString(fmt.Sprintf("%-12s %#x %s\n", r.Dmg, r.Addr, r.Path))
			}
			m.mu.Unlock()
			s.WriteString(pad.Render(t.String()))
			s.WriteString("\n\n")
		} else {
			s.WriteString(pad.Render(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true).Render("No MTE-enabled binaries found")))
			s.WriteString("\n\n")
		}
		s.WriteString(pad.Render(lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render("Press q to quit")))
	}
	return s.String()
}

// RunMTEScanIPSW mounts each DMG once, counts Mach-Os, then scans cached paths.
func RunMTEScanIPSW(ipswPath, pemDB string) error {
	oldLevel := log.Log.(*log.Logger).Level
	log.SetLevel(log.WarnLevel)
	defer log.SetLevel(oldLevel)

	model := mteScanModel{dmgs: []dmgProgress{}, results: []mteResult{}}
	p := tea.NewProgram(model)

	go func() {
		i, err := info.Parse(ipswPath)
		if err != nil {
			log.Errorf("failed to parse IPSW: %v", err)
			p.Send(scanCompleteMsg{})
			return
		}

		type dmgInfo struct{ name, path string }
		var dmgs []dmgInfo
		if fsOS, err := i.GetFileSystemOsDmg(); err == nil {
			dmgs = append(dmgs, dmgInfo{"FileSystem", fsOS})
		}
		if systemOS, err := i.GetSystemOsDmg(); err == nil {
			dmgs = append(dmgs, dmgInfo{"SystemOS", systemOS})
		}
		if appOS, err := i.GetAppOsDmg(); err == nil {
			dmgs = append(dmgs, dmgInfo{"AppOS", appOS})
		}
		if excOS, err := i.GetExclaveOSDmg(); err == nil {
			dmgs = append(dmgs, dmgInfo{"ExclaveOS", excOS})
		}

		for _, d := range dmgs {
			p.Send(dmgStartMsg{name: d.name})
		}

		for _, d := range dmgs {
			pathCache := make(map[string]bool)

			countHandler := func(mountPoint, filePath string) error {
				if ok, _ := magic.IsMachO(filePath); ok {
					pathCache[filePath] = true
				}
				return nil
			}

			scanHandler := func(mountPoint, filePath string) error {
				if !pathCache[filePath] {
					return nil
				}
				delete(pathCache, filePath)

				var result *mteResult

				var m *macho.File
				if fat, err := macho.OpenFat(filePath); err == nil {
					defer fat.Close()
					m = fat.Arches[len(fat.Arches)-1].File
				} else if errors.Is(err, macho.ErrNotFat) {
					mf, openErr := macho.Open(filePath)
					if openErr != nil {
						p.Send(dmgProgressMsg{name: d.name, result: nil})
						return nil
					}
					defer mf.Close()
					m = mf
				} else {
					p.Send(dmgProgressMsg{name: d.name, result: nil})
					return nil
				}

				rel := filePath
				if _, rest, ok := strings.Cut(filePath, mountPoint); ok {
					rel = rest
				}

				hasMTE, addr := utils.HasMTEInstructions(m)
				if hasMTE {
					result = &mteResult{Dmg: d.name, Path: rel, Image: filepath.Base(rel), Addr: addr}
				}

				p.Send(dmgProgressMsg{name: d.name, result: result})
				return nil
			}

			between := func(idx int) {
				if idx == 0 {
					p.Send(dmgCompleteMsg{name: d.name, total: len(pathCache)})
				}
			}

			p.Send(dmgMountingMsg{name: d.name})
			if err := search.ScanDmgWithMultipleHandlersAndCallback(ipswPath, d.path, d.name, pemDB, between, countHandler, scanHandler); err != nil {
				log.Errorf("failed to scan %s: %v", d.name, err)
				continue
			}
		}
		p.Send(scanCompleteMsg{})
	}()

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running MTE scanner: %w", err)
	}
	return nil
}
