package kernel

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
	"github.com/spf13/viper"
)

func TestKernelExtractResolvesCanonicalEntry(t *testing.T) {
	names := []string{
		"com.example.prefix.com.example.driver.Widget",
		"com.example.driver.Widget",
		"com.other.driver.Widget",
		"com.example.driver.ASIOKit",
		"com.other.driver.FairPlayIOKit",
	}
	input := syntheticKextFileset(t, names)
	for _, tc := range []struct {
		query, want, errorText string
		uuid                   byte
	}{
		{"com.example.driver.Widget", names[1], "", 2},
		{"COM.EXAMPLE.DRIVER.WIDGET", names[1], "", 2},
		{"ASIOKit", names[3], "", 4},
		{"IOKit", "", "not found", 0},
		{"Widget", "", "multiple KEXTs", 0},
		{"missing", "", "not found", 0},
	} {
		t.Run(tc.query, func(t *testing.T) {
			output := t.TempDir()
			for key, value := range map[string]any{"all": false, "force": false, "imports": false, "arch": "", "output": output} {
				key = "kernel.extract." + key
				previous := viper.Get(key)
				viper.Set(key, value)
				t.Cleanup(func() { viper.Set(key, previous) })
			}
			// A stale output named after an invalid selector must not hide the error.
			if tc.errorText != "" {
				if err := os.WriteFile(filepath.Join(output, tc.query), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := kerExtractCmd.RunE(kerExtractCmd, []string{input, tc.query})
			if tc.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errorText) {
					t.Fatalf("expected %q, got %v", tc.errorText, err)
				}
				entries, readErr := os.ReadDir(output)
				if readErr != nil || len(entries) != 1 {
					t.Fatalf("invalid selection wrote output: %v, %v", entries, readErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(output)
			if err != nil || len(entries) != 1 || entries[0].Name() != tc.want {
				t.Fatalf("wrong output name: %v, %v", entries, err)
			}
			path := filepath.Join(output, tc.want)
			m, err := macho.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			if m.UUID() == nil || m.UUID().UUID != (types.UUID{tc.uuid}) {
				t.Fatalf("extracted the wrong fileset entry: %v", m.UUID())
			}
			if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := kerExtractCmd.RunE(kerExtractCmd, []string{input, tc.query}); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != "keep" {
				t.Fatalf("canonical overwrite check failed: %q, %v", data, err)
			}
		})
	}
	// An arbitrary character suffix is invalid even if it has only one match.
	if _, err := resolveKext([]*macho.FilesetEntry{{EntryID: names[3]}}, "IOKit"); err == nil {
		t.Fatal("IOKit matched ASIOKit")
	}
}

func syntheticKextFileset(t *testing.T, names []string) string {
	t.Helper()
	var commands bytes.Buffer
	data := make([]byte, (len(names)+1)*0x1000)
	for i, name := range names {
		entryName := append([]byte(name), 0)
		for len(entryName)%8 != 0 {
			entryName = append(entryName, 0)
		}
		offset := uint64(i+1) * 0x1000
		entry := types.FilesetEntryCmd{LoadCmd: types.LC_FILESET_ENTRY, Len: uint32(32 + len(entryName)), FileOffset: offset, EntryIdOffset: 32}
		if err := binary.Write(&commands, binary.LittleEndian, entry); err != nil {
			t.Fatal(err)
		}
		commands.Write(entryName)
		header := types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_KEXT_BUNDLE, NCommands: 1, SizeCommands: 24}
		header.Put(data[offset:], binary.LittleEndian)
		var uuid bytes.Buffer
		if err := binary.Write(&uuid, binary.LittleEndian, types.UUIDCmd{LoadCmd: types.LC_UUID, Len: 24, UUID: types.UUID{byte(i + 1)}}); err != nil {
			t.Fatal(err)
		}
		copy(data[offset+32:], uuid.Bytes())
	}
	header := types.FileHeader{Magic: types.Magic64, CPU: types.CPUArm64, Type: types.MH_FILESET, NCommands: uint32(len(names)), SizeCommands: uint32(commands.Len())}
	header.Put(data, binary.LittleEndian)
	copy(data[32:], commands.Bytes())
	path := filepath.Join(t.TempDir(), "synthetic-kernel")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
