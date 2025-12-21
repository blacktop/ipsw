/*
Copyright © 2025 blacktop

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
package dyld

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// mteResult holds MTE scan results
type mteResult struct {
	Image string
	Addr  uint64
}

// scanJob represents a single image scan task
type scanJob struct {
	index int
	image *dyld.CacheImage
}

// scanWorkerResult holds the result from a worker with its original index
type scanWorkerResult struct {
	index  int
	result *mteResult
}

// mteScanModel is the Bubble Tea model for MTE scanning with progress
type mteScanModel struct {
	progress progress.Model
	results  []mteResult
	current  int
	total    int
	done     bool
	err      error
}

type scanProgressMsg struct {
	current int
	image   string
	result  *mteResult
}

type scanCompleteMsg struct{}

func (m mteScanModel) Init() tea.Cmd {
	return nil
}

func (m mteScanModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.done && msg.String() == "q" {
			return m, tea.Quit
		}

	case scanProgressMsg:
		m.current = msg.current
		if msg.result != nil {
			m.results = append(m.results, *msg.result)
		}
		if m.current >= m.total {
			m.done = true
			return m, tea.Quit
		}
		return m, nil

	case scanCompleteMsg:
		m.done = true
		return m, tea.Quit

	case progress.FrameMsg:
		progressModel, cmd := m.progress.Update(msg)
		m.progress = progressModel.(progress.Model)
		return m, cmd
	}

	return m, nil
}

func (m mteScanModel) View() string {
	if m.err != nil {
		return fmt.Sprintf("Error: %v\n", m.err)
	}

	var s strings.Builder

	// Add consistent left padding to all content
	contentStyle := lipgloss.NewStyle().PaddingLeft(2)

	// Title
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#7D56F4")).
		MarginBottom(1)
	s.WriteString(contentStyle.Render(titleStyle.Render("🔍 Scanning dyld_shared_cache for MTE Instructions")))
	s.WriteString("\n\n")

	// Progress bar
	percent := float64(m.current) / float64(m.total)
	s.WriteString(contentStyle.Render(m.progress.ViewAs(percent)))
	s.WriteString("\n\n")

	// Status text
	statusStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	s.WriteString(contentStyle.Render(statusStyle.Render(fmt.Sprintf("Scanned: %d/%d images • Found: %d MTE-enabled", m.current, m.total, len(m.results)))))
	s.WriteString("\n\n")

	if m.done {
		// Statistics
		statsStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F25D94")).
			MarginTop(1).
			MarginBottom(1)
		percentage := float64(len(m.results)) / float64(m.total) * 100
		s.WriteString(contentStyle.Render(statsStyle.Render(fmt.Sprintf("✨ STATISTICS: %d/%d = %.2f%% MTE-enabled", len(m.results), m.total, percentage))))
		s.WriteString("\n\n")

		// Results table - use simple ASCII table
		if len(m.results) > 0 {
			var tableStr strings.Builder
			tableStr.WriteString(fmt.Sprintf("%-60s %s\n", "IMAGE", "ADDRESS"))
			tableStr.WriteString(strings.Repeat("-", 80) + "\n")
			for _, r := range m.results {
				tableStr.WriteString(fmt.Sprintf("%-60s %#x\n", r.Image, r.Addr))
			}
			s.WriteString(contentStyle.Render(tableStr.String()))
			s.WriteString("\n\n")
		} else {
			noResultsStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("241")).
				Italic(true)
			s.WriteString(contentStyle.Render(noResultsStyle.Render("No MTE-enabled images found")))
			s.WriteString("\n\n")
		}

		helpStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
		s.WriteString(contentStyle.Render(helpStyle.Render("Press q to quit")))
	}

	return s.String()
}

// runMTEScan performs MTE scanning with a progress bar and displays results in a table
func runMTEScan(f *dyld.File) error {
	// Check if we have a TTY - if not, use simple output
	_, err := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	useTUI := err == nil && os.Getenv("CI") == ""

	if !useTUI {
		// Simple text output without TUI with parallel scanning
		fmt.Println("🔍 Scanning dyld_shared_cache for MTE Instructions (IRG, STG, ST2G)")
		fmt.Println()

		// Setup worker pool
		numWorkers := runtime.NumCPU()
		jobs := make(chan scanJob, len(f.Images))
		resultsChan := make(chan scanWorkerResult, len(f.Images))

		var completed atomic.Int32
		var wg sync.WaitGroup

		// Start workers using Go 1.25's WaitGroup.Go
		for range numWorkers {
			wg.Go(func() {
				for job := range jobs {
					m, err := job.image.GetMacho()
					if err != nil {
						completed.Add(1)
						continue
					}

					hasMTE, addr := utils.HasMTEInstructions(m)
					var result *mteResult
					if hasMTE {
						result = &mteResult{
							Image: filepath.Base(job.image.Name),
							Addr:  addr,
						}
					}

					resultsChan <- scanWorkerResult{
						index:  job.index,
						result: result,
					}

					// Progress reporting
					count := completed.Add(1)
					if count%100 == 0 {
						fmt.Printf("Scanned: %d/%d images\n", count, len(f.Images))
					}
				}
			})
		}

		// Send jobs
		for i, img := range f.Images {
			jobs <- scanJob{index: i, image: img}
		}
		close(jobs)

		// Collect results in background
		allResults := make([]scanWorkerResult, 0, len(f.Images))
		done := make(chan struct{})
		go func() {
			for result := range resultsChan {
				allResults = append(allResults, result)
			}
			close(done)
		}()

		// Wait for workers and close results
		wg.Wait()
		close(resultsChan)
		<-done

		// Sort by original index and filter non-nil results
		slices.SortFunc(allResults, func(a, b scanWorkerResult) int {
			return a.index - b.index
		})

		var results []mteResult
		for _, wr := range allResults {
			if wr.result != nil {
				results = append(results, *wr.result)
			}
		}

		fmt.Println()
		percentage := float64(len(results)) / float64(len(f.Images)) * 100
		fmt.Printf("✨ STATISTICS: %d/%d = %.2f%% MTE-enabled\n\n", len(results), len(f.Images), percentage)

		if len(results) > 0 {
			fmt.Printf("%-60s %s\n", "IMAGE", "ADDRESS")
			fmt.Println(strings.Repeat("-", 80))
			for _, r := range results {
				fmt.Printf("%-60s %#x\n", r.Image, r.Addr)
			}
		} else {
			fmt.Println("No MTE-enabled images found")
		}

		return nil
	}

	// We have a TTY - use Bubble Tea TUI with parallel scanning
	prog := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(60),
	)

	model := mteScanModel{
		progress: prog,
		total:    len(f.Images),
		results:  []mteResult{},
	}

	p := tea.NewProgram(model)

	// Start parallel scanning with workers
	go func() {
		// Use fewer workers to leave CPU for UI rendering
		numWorkers := max(1, runtime.NumCPU()/2)

		jobs := make(chan scanJob, len(f.Images))
		resultsChan := make(chan scanWorkerResult, numWorkers*2)

		var wg sync.WaitGroup

		// Start workers using Go 1.25's WaitGroup.Go
		for range numWorkers {
			wg.Go(func() {
				for job := range jobs {
					m, err := job.image.GetMacho()
					var result *mteResult

					if err == nil {
						hasMTE, addr := utils.HasMTEInstructions(m)
						if hasMTE {
							result = &mteResult{
								Image: filepath.Base(job.image.Name),
								Addr:  addr,
							}
						}
					}

					// Send result immediately
					resultsChan <- scanWorkerResult{
						index:  job.index,
						result: result,
					}
				}
			})
		}

		// Result aggregator - collects and sends to UI in real-time
		go func() {
			allResults := make([]scanWorkerResult, 0, len(f.Images))
			nextToSend := 0

			for result := range resultsChan {
				allResults = append(allResults, result)

				// Sort to maintain order
				slices.SortFunc(allResults, func(a, b scanWorkerResult) int {
					return a.index - b.index
				})

				// Send any consecutive results that are ready
				for nextToSend < len(allResults) && allResults[nextToSend].index == nextToSend {
					wr := allResults[nextToSend]
					p.Send(scanProgressMsg{
						current: nextToSend + 1,
						image:   "",
						result:  wr.result,
					})
					nextToSend++
				}
			}

			// Signal completion
			p.Send(scanCompleteMsg{})
		}()

		// Send jobs
		for i, img := range f.Images {
			jobs <- scanJob{index: i, image: img}
		}
		close(jobs)

		// Wait for workers then close results
		wg.Wait()
		close(resultsChan)
	}()

	// Run the program
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("error running MTE scanner: %w", err)
	}

	return nil
}

func init() {
	DyldCmd.AddCommand(dyldSearchCmd)

	dyldSearchCmd.Flags().StringP("load-command", "l", "", "Search for specific load command regex")
	dyldSearchCmd.Flags().StringP("import", "i", "", "Search for specific import regex")
	dyldSearchCmd.Flags().StringP("section", "x", "", "Search for specific section regex")
	dyldSearchCmd.Flags().StringP("uuid", "u", "", "Search for dylib by UUID")
	dyldSearchCmd.Flags().Bool("mte", false, "Search for dylibs with MTE (Memory Tagging Extension) instructions")
	viper.BindPFlag("dyld.search.load-command", dyldSearchCmd.Flags().Lookup("load-command"))
	viper.BindPFlag("dyld.search.import", dyldSearchCmd.Flags().Lookup("import"))
	viper.BindPFlag("dyld.search.section", dyldSearchCmd.Flags().Lookup("section"))
	viper.BindPFlag("dyld.search.uuid", dyldSearchCmd.Flags().Lookup("uuid"))
	viper.BindPFlag("dyld.search.mte", dyldSearchCmd.Flags().Lookup("mte"))
}

// dyldSearchCmd represents the search command
var dyldSearchCmd = &cobra.Command{
	Use:     "search <DSC>",
	Aliases: []string{"sr"},
	Short:   "Find Dylib files for given search criteria",
	Args:    cobra.ExactArgs(1),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getDSCs(toComplete), cobra.ShellCompDirectiveDefault
	},
	SilenceErrors: true,
	RunE: func(cmd *cobra.Command, args []string) error {

		// flags
		loadCmdReStr := viper.GetString("dyld.search.load-command")
		importReStr := viper.GetString("dyld.search.import")
		sectionReStr := viper.GetString("dyld.search.section")
		uuidStr := viper.GetString("dyld.search.uuid")
		searchMTE := viper.GetBool("dyld.search.mte")
		// verify flags
		if loadCmdReStr == "" && importReStr == "" && sectionReStr == "" && uuidStr == "" && !searchMTE {
			return fmt.Errorf("must specify a search criteria via one of the flags")
		}

		dscPath := filepath.Clean(args[0])

		fileInfo, err := os.Lstat(dscPath)
		if err != nil {
			return fmt.Errorf("file %s does not exist", dscPath)
		}

		// Check if file is a symlink
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			symlinkPath, err := os.Readlink(dscPath)
			if err != nil {
				return fmt.Errorf("failed to read symlink %s: %v", dscPath, err)
			}
			// TODO: this seems like it would break
			linkParent := filepath.Dir(dscPath)
			linkRoot := filepath.Dir(linkParent)

			dscPath = filepath.Join(linkRoot, symlinkPath)
		}

		f, err := dyld.Open(dscPath)
		if err != nil {
			return fmt.Errorf("failed to open dyld shared cache %s: %w", dscPath, err)
		}

		// Special handling for MTE search with progress bar and table
		if searchMTE {
			return runMTEScan(f)
		}

		// Standard search for other criteria
		var m *macho.File

		for _, img := range f.Images {
			if loadCmdReStr != "" {
				// Need full macho for load commands
				m, err = img.GetMacho()
				if err != nil {
					return err
				}
			} else {
				// use partial macho for speed
				m, err = img.GetPartialMacho()
				if err != nil {
					return err
				}
			}

			if uuidStr != "" {
				if strings.EqualFold(img.UUID.String(), uuidStr) {
					fmt.Printf("%s\t%s=%s\n", colorImage(filepath.Base(img.Name)), colorField("uuid"), img.UUID)
				}
			}
			if loadCmdReStr != "" {
				re, err := regexp.Compile(loadCmdReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", loadCmdReStr, err)
				}
				for _, lc := range m.Loads {
					if re.MatchString(lc.Command().String()) {
						fmt.Printf("%s\t%s=%s\n", colorImage(filepath.Base(img.Name)), colorField("load"), lc.Command())
						fmt.Printf("\t%s\n", lc)
					}
				}
			}
			if importReStr != "" {
				re, err := regexp.Compile(importReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", importReStr, err)
				}
				for _, imp := range m.ImportedLibraries() {
					if re.MatchString(imp) {
						fmt.Printf("%s\t%s=%s\n", colorImage(filepath.Base(img.Name)), colorField("import"), imp)
						break
					}
				}
			}
			if sectionReStr != "" {
				re, err := regexp.Compile(sectionReStr)
				if err != nil {
					return fmt.Errorf("invalid regex '%s': %w", sectionReStr, err)
				}
				for _, sec := range m.Sections {
					if re.MatchString(fmt.Sprintf("%s.%s", sec.Seg, sec.Name)) {
						fmt.Printf("%-55s%s=%s\n", colorImage(filepath.Base(img.Name)), colorField("load"), fmt.Sprintf("%s.%s", sec.Seg, sec.Name))
					}
				}
			}
		}

		return nil
	},
}
