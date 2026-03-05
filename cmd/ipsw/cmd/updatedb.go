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
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"sort"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/ota/types"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type mergeStats struct {
	AddedDevices    int
	AddedBoards     int
	FilledFields    int
	DeviceConflicts int
	BoardConflicts  int
}

type deviceAddEntry struct {
	Product string
}

type boardAddEntry struct {
	Product string
	Board   string
}

type fieldFillEntry struct {
	Product string
	Field   string
	Value   string
}

type deviceConflictEntry struct {
	Product  string
	Field    string
	Existing string
	Incoming string
}

type boardConflictEntry struct {
	Product  string
	Board    string
	Existing info.Board
	Incoming info.Board
}

type mergeReport struct {
	Stats                mergeStats
	AddedDeviceEntries   []deviceAddEntry
	AddedBoardEntries    []boardAddEntry
	FilledFieldEntries   []fieldFillEntry
	DeviceConflictEvents []deviceConflictEntry
	BoardConflictEvents  []boardConflictEntry
}

func (s mergeStats) HasAdditiveChanges() bool {
	return s.AddedDevices > 0 || s.AddedBoards > 0 || s.FilledFields > 0
}

func (r mergeReport) HasAdditiveChanges() bool {
	return r.Stats.HasAdditiveChanges()
}

func (r *mergeReport) sort() {
	sort.Slice(r.AddedDeviceEntries, func(i, j int) bool {
		return r.AddedDeviceEntries[i].Product < r.AddedDeviceEntries[j].Product
	})
	sort.Slice(r.AddedBoardEntries, func(i, j int) bool {
		if r.AddedBoardEntries[i].Product == r.AddedBoardEntries[j].Product {
			return r.AddedBoardEntries[i].Board < r.AddedBoardEntries[j].Board
		}
		return r.AddedBoardEntries[i].Product < r.AddedBoardEntries[j].Product
	})
	sort.Slice(r.FilledFieldEntries, func(i, j int) bool {
		if r.FilledFieldEntries[i].Product == r.FilledFieldEntries[j].Product {
			return r.FilledFieldEntries[i].Field < r.FilledFieldEntries[j].Field
		}
		return r.FilledFieldEntries[i].Product < r.FilledFieldEntries[j].Product
	})
	sort.Slice(r.DeviceConflictEvents, func(i, j int) bool {
		if r.DeviceConflictEvents[i].Product == r.DeviceConflictEvents[j].Product {
			return r.DeviceConflictEvents[i].Field < r.DeviceConflictEvents[j].Field
		}
		return r.DeviceConflictEvents[i].Product < r.DeviceConflictEvents[j].Product
	})
	sort.Slice(r.BoardConflictEvents, func(i, j int) bool {
		if r.BoardConflictEvents[i].Product == r.BoardConflictEvents[j].Product {
			return r.BoardConflictEvents[i].Board < r.BoardConflictEvents[j].Board
		}
		return r.BoardConflictEvents[i].Product < r.BoardConflictEvents[j].Product
	})
}

func cloneDevice(d info.Device) info.Device {
	clone := d
	if d.Boards != nil {
		clone.Boards = make(map[string]info.Board, len(d.Boards))
		maps.Copy(clone.Boards, d.Boards)
	}
	return clone
}

func mergeStringField(productType, fieldName string, existing *string, incoming string, report *mergeReport) {
	if len(incoming) == 0 {
		return
	}
	if len(*existing) == 0 {
		*existing = incoming
		report.Stats.FilledFields++
		report.FilledFieldEntries = append(report.FilledFieldEntries, fieldFillEntry{
			Product: productType,
			Field:   fieldName,
			Value:   incoming,
		})
		return
	}
	if *existing != incoming {
		report.Stats.DeviceConflicts++
		report.DeviceConflictEvents = append(report.DeviceConflictEvents, deviceConflictEntry{
			Product:  productType,
			Field:    fieldName,
			Existing: *existing,
			Incoming: incoming,
		})
	}
}

func mergeUint64Field(productType, fieldName string, existing *uint64, incoming uint64, report *mergeReport) {
	if incoming == 0 {
		return
	}
	if *existing == 0 {
		*existing = incoming
		report.Stats.FilledFields++
		report.FilledFieldEntries = append(report.FilledFieldEntries, fieldFillEntry{
			Product: productType,
			Field:   fieldName,
			Value:   fmt.Sprintf("%d", incoming),
		})
		return
	}
	if *existing != incoming {
		report.Stats.DeviceConflicts++
		report.DeviceConflictEvents = append(report.DeviceConflictEvents, deviceConflictEntry{
			Product:  productType,
			Field:    fieldName,
			Existing: fmt.Sprintf("%d", *existing),
			Incoming: fmt.Sprintf("%d", incoming),
		})
	}
}

func mergeExistingDevice(productType string, existing *info.Device, incoming info.Device, report *mergeReport) {
	mergeStringField(productType, "name", &existing.Name, incoming.Name, report)
	mergeStringField(productType, "desc", &existing.Description, incoming.Description, report)
	mergeStringField(productType, "sdk", &existing.SDKPlatform, incoming.SDKPlatform, report)
	mergeStringField(productType, "type", &existing.Type, incoming.Type, report)
	mergeUint64Field(productType, "mem_class", &existing.MemClass, incoming.MemClass, report)

	if existing.Boards == nil {
		existing.Boards = make(map[string]info.Board)
	}
	for boardID, incomingBoard := range incoming.Boards {
		if existingBoard, ok := existing.Boards[boardID]; ok {
			if existingBoard != incomingBoard {
				report.Stats.BoardConflicts++
				report.BoardConflictEvents = append(report.BoardConflictEvents, boardConflictEntry{
					Product:  productType,
					Board:    boardID,
					Existing: existingBoard,
					Incoming: incomingBoard,
				})
			}
			continue
		}

		existing.Boards[boardID] = incomingBoard
		report.Stats.AddedBoards++
		report.AddedBoardEntries = append(report.AddedBoardEntries, boardAddEntry{
			Product: productType,
			Board:   boardID,
		})
	}
}

func mergeDeviceMaps(existing *info.Devices, discovered info.Devices) mergeReport {
	var report mergeReport

	if *existing == nil {
		*existing = make(info.Devices)
	}

	for productType, discoveredDevice := range discovered {
		existingDevice, ok := (*existing)[productType]
		if !ok {
			(*existing)[productType] = cloneDevice(discoveredDevice)
			report.Stats.AddedDevices++
			report.AddedDeviceEntries = append(report.AddedDeviceEntries, deviceAddEntry{
				Product: productType,
			})
			continue
		}

		merged := cloneDevice(existingDevice)
		mergeExistingDevice(productType, &merged, discoveredDevice, &report)
		(*existing)[productType] = merged
	}

	report.sort()

	return report
}

func boardSummary(b info.Board) string {
	parts := make([]string, 0, 5)
	if len(b.CPU) > 0 {
		parts = append(parts, "cpu="+b.CPU)
	}
	if len(b.Platform) > 0 {
		parts = append(parts, "platform="+b.Platform)
	}
	if len(b.ChipID) > 0 {
		parts = append(parts, "cpuid="+b.ChipID)
	}
	if len(b.BoardID) > 0 {
		parts = append(parts, "board_id="+b.BoardID)
	}
	if len(parts) == 0 {
		return "<empty>"
	}
	return strings.Join(parts, ", ")
}

func renderDryRunReport(report mergeReport, discoveredCount int, dbPath string) {
	title := color.New(color.Bold, color.FgCyan).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	muted := color.New(color.Faint).SprintFunc()

	fmt.Println(title("updatedb dry-run preview"))
	if len(dbPath) > 0 {
		fmt.Printf("%s %s\n", muted("target:"), dbPath)
	} else {
		fmt.Printf("%s %s\n", muted("target:"), "stdout")
	}

	fmt.Printf(
		"%s discovered=%d added_devices=%d added_boards=%d filled_fields=%d device_conflicts=%d board_conflicts=%d\n",
		title("summary:"),
		discoveredCount,
		report.Stats.AddedDevices,
		report.Stats.AddedBoards,
		report.Stats.FilledFields,
		report.Stats.DeviceConflicts,
		report.Stats.BoardConflicts,
	)

	if len(report.AddedDeviceEntries) > 0 {
		fmt.Println()
		fmt.Println(title("new devices:"))
		for _, entry := range report.AddedDeviceEntries {
			fmt.Printf("  %s %s\n", green("+"), entry.Product)
		}
	}

	if len(report.AddedBoardEntries) > 0 {
		fmt.Println()
		fmt.Println(title("new boards:"))
		for _, entry := range report.AddedBoardEntries {
			fmt.Printf("  %s %s.%s\n", green("+"), entry.Product, entry.Board)
		}
	}

	if len(report.FilledFieldEntries) > 0 {
		fmt.Println()
		fmt.Println(title("filled missing fields:"))
		for _, entry := range report.FilledFieldEntries {
			fmt.Printf("  %s %s.%s=%s\n", yellow("~"), entry.Product, entry.Field, entry.Value)
		}
	}

	if len(report.DeviceConflictEvents) > 0 {
		fmt.Println()
		fmt.Println(title("device conflicts (existing kept):"))
		for _, conflict := range report.DeviceConflictEvents {
			fmt.Printf("  %s %s.%s existing=%q incoming=%q\n", red("!"), conflict.Product, conflict.Field, conflict.Existing, conflict.Incoming)
		}
	}

	if len(report.BoardConflictEvents) > 0 {
		fmt.Println()
		fmt.Println(title("board conflicts (existing kept):"))
		for _, conflict := range report.BoardConflictEvents {
			fmt.Printf("  %s %s.%s existing={%s} incoming={%s}\n",
				red("!"),
				conflict.Product,
				conflict.Board,
				boardSummary(conflict.Existing),
				boardSummary(conflict.Incoming),
			)
		}
	}

	if !report.HasAdditiveChanges() {
		fmt.Println()
		fmt.Println(green("no additive DB changes detected"))
	}
}

func logMergeConflicts(report mergeReport) {
	for _, conflict := range report.DeviceConflictEvents {
		log.WithFields(log.Fields{
			"product":  conflict.Product,
			"field":    conflict.Field,
			"existing": conflict.Existing,
			"incoming": conflict.Incoming,
		}).Warn("discovered device field differs from existing; keeping existing value")
	}
	for _, conflict := range report.BoardConflictEvents {
		log.WithFields(log.Fields{
			"product":  conflict.Product,
			"board":    conflict.Board,
			"existing": boardSummary(conflict.Existing),
			"incoming": boardSummary(conflict.Incoming),
		}).Warn("discovered board differs from existing; keeping existing board value")
	}
}

func mergeDevicesFromRemoteURL(remoteURL string, devices *info.Devices) error {
	zr, err := download.NewRemoteZipReader(remoteURL, &download.RemoteConfig{})
	if err != nil {
		return fmt.Errorf("failed to create remote zip reader: %w", err)
	}

	i, err := info.ParseZipFiles(zr.File)
	if err != nil {
		return fmt.Errorf("failed to parse remote zip: %w", err)
	}

	if i.Plists.Type != "OTA" {
		if err := i.GetDevices(devices); err != nil {
			return fmt.Errorf("failed to get devices: %w", err)
		}
		return nil
	}

	foundMap := false
	for _, f := range zr.File {
		lowerName := strings.ToLower(f.Name)
		if !strings.HasSuffix(lowerName, ".plist") || !strings.Contains(lowerName, "device_map.plist") {
			continue
		}
		foundMap = true

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("failed to open file within zip: %w", err)
		}

		dat, err := io.ReadAll(rc)
		if closeErr := rc.Close(); closeErr != nil {
			if err != nil {
				return fmt.Errorf("failed to read device map from zip: %w (close failed: %v)", err, closeErr)
			}
			return fmt.Errorf("failed to close file within zip: %w", closeErr)
		}
		if err != nil {
			return fmt.Errorf("failed to read device map from zip: %w", err)
		}

		dmap, err := types.ParseDeviceMap(dat)
		if err != nil {
			return fmt.Errorf("failed to parse device map: %w", err)
		}

		if err := i.GetDevicesFromMap(dmap, devices); err != nil {
			return fmt.Errorf("failed to get devices from map: %w", err)
		}
	}

	if !foundMap {
		if err := i.GetDevices(devices); err != nil {
			return fmt.Errorf("failed to get devices: %w", err)
		}
	}

	return nil
}

func init() {
	rootCmd.AddCommand(updateDBCmd)
	updateDBCmd.Flags().StringP("urls", "u", "", "Path to file containing list of URLs to scan (one per line)")
	updateDBCmd.Flags().StringP("remote", "r", "", "Remote IPSW/OTA URL to parse")
	updateDBCmd.Flags().StringP("path", "p", "", "Path to map")
	updateDBCmd.Flags().StringP("db", "d", "", "Path to ipsw device DB JSON")
	updateDBCmd.Flags().Bool("dry-run", false, "Preview additive DB changes without writing")
	viper.BindPFlag("updatedb.urls", updateDBCmd.Flags().Lookup("urls"))
	viper.BindPFlag("updatedb.remote", updateDBCmd.Flags().Lookup("remote"))
	viper.BindPFlag("updatedb.path", updateDBCmd.Flags().Lookup("path"))
	viper.BindPFlag("updatedb.db", updateDBCmd.Flags().Lookup("db"))
	viper.BindPFlag("updatedb.dry-run", updateDBCmd.Flags().Lookup("dry-run"))
}

// updateDBCmd represents the updatedb command
var updateDBCmd = &cobra.Command{
	Use:    "updatedb",
	Short:  "Update internal device database",
	Args:   cobra.NoArgs,
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		var existingDevices info.Devices
		discoveredDevices := make(info.Devices)

		if Verbose {
			log.SetLevel(log.DebugLevel)
		}

		urlList := viper.GetString("updatedb.urls")
		remoteURL := viper.GetString("updatedb.remote")
		mapPath := viper.GetString("updatedb.path")
		dbPath := viper.GetString("updatedb.db")
		dryRun := viper.GetBool("updatedb.dry-run")

		mut := "Creating"
		if len(dbPath) > 0 {
			if _, err := os.Stat(dbPath); err == nil {
				f, err := os.Open(dbPath)
				if err != nil {
					log.WithError(err).Fatal("failed to open DB file")
				}
				defer f.Close()
				dat, err := io.ReadAll(f)
				if err != nil {
					log.WithError(err).Fatal("failed to read DB file")
				}
				if err := json.Unmarshal(dat, &existingDevices); err != nil {
					log.WithError(err).Fatal("failed to unmarshal DB JSON file")
				}
				mut = "Updating"
			} else if !os.IsNotExist(err) {
				log.WithError(err).Fatal("failed to stat DB file")
			}
		}
		if existingDevices == nil {
			existingDevices = make(info.Devices)
		}

		if len(urlList) > 0 {
			uf, err := os.Open(urlList)
			if err != nil {
				log.WithError(err).Fatal("failed to open URL list file")
			}
			defer uf.Close()

			scanner := bufio.NewScanner(uf)

			for scanner.Scan() {
				url := strings.TrimSpace(scanner.Text())
				if len(url) == 0 || strings.HasPrefix(url, "#") {
					continue
				}
				if err := mergeDevicesFromRemoteURL(url, &discoveredDevices); err != nil {
					log.WithError(err).WithField("url", url).Warn("failed to merge devices from URL")
					continue
				}
			}
			if err := scanner.Err(); err != nil {
				log.WithError(err).Fatal("failed to read line from URL list file")
			}
		} else if len(mapPath) > 0 {
			data, err := os.ReadFile(mapPath)
			if err != nil {
				log.WithError(err).Fatal("failed to read device map file")
			}
			dmap, err := types.ParseDeviceMap(data)
			if err != nil {
				log.WithError(err).Fatal("failed to parse device map")
			}
			i := &info.Info{}
			if err := i.GetDevicesFromMap(dmap, &discoveredDevices); err != nil {
				log.WithError(err).Fatal("failed to get devices")
			}
		} else if len(remoteURL) > 0 {
			if err := mergeDevicesFromRemoteURL(remoteURL, &discoveredDevices); err != nil {
				log.WithError(err).WithField("url", remoteURL).Fatal("failed to merge devices from URL")
			}
		} else { // TODO: add default "latest" URL streams here to collect new devices
			itunes, err := download.NewMacOsXML()
			if err != nil {
				log.WithError(err).Fatal("failed to create itunes API")
			}
			for _, build := range itunes.GetBuilds() {
				if err := mergeDevicesFromRemoteURL(build.URL, &discoveredDevices); err != nil {
					log.WithError(err).WithField("url", build.URL).Warn("failed to merge devices from build URL")
					continue
				}
			}
		}

		report := mergeDeviceMaps(&existingDevices, discoveredDevices)

		if dryRun {
			renderDryRunReport(report, len(discoveredDevices), dbPath)
			if len(dbPath) > 0 {
				log.WithField("path", dbPath).Info("dry-run enabled; no file written")
			}
			return
		}

		logMergeConflicts(report)
		log.WithFields(log.Fields{
			"discovered_devices": len(discoveredDevices),
			"added_devices":      report.Stats.AddedDevices,
			"added_boards":       report.Stats.AddedBoards,
			"filled_fields":      report.Stats.FilledFields,
			"device_conflicts":   report.Stats.DeviceConflicts,
			"board_conflicts":    report.Stats.BoardConflicts,
		}).Info("updatedb merge summary")

		// OUTPUT JSON
		dat, err := json.Marshal(existingDevices)
		if err != nil {
			log.WithError(err).Fatal("failed to marshal JSON")
		}
		if len(dbPath) > 0 {
			if !report.HasAdditiveChanges() {
				log.WithField("path", dbPath).Info("no additive DB changes detected; skipping write")
				return
			}
			log.Infof("%s %s", mut, dbPath)
			if err := os.WriteFile(dbPath, dat, 0660); err != nil {
				log.WithError(err).Fatalf("failed to write file %s", dbPath)
			}
		} else {
			fmt.Println(string(dat))
		}
	},
}
