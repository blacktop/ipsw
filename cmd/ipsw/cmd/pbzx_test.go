package cmd

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestPBZXOutput(t *testing.T) {
	const payload = "synthetic decompressed payload"
	valid := []byte("pbzx")
	valid = binary.BigEndian.AppendUint64(valid, 0x1000000)
	valid = binary.BigEndian.AppendUint64(valid, uint64(len(payload)))
	valid = binary.BigEndian.AppendUint64(valid, uint64(len(payload)))
	valid = append(valid, payload...)
	truncated := append(bytes.Clone(valid), 0)

	for _, tc := range []struct {
		name     string
		source   []byte
		existing string
		wantErr  bool
	}{
		{"new output", valid, "", false},
		{"replace output", valid, "file", false},
		{"preserve output on failure", truncated, "file", true},
		{"remove partial new output", truncated, "", true},
		{"failed rename", valid, "directory", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "payload.pbzx")
			output := input + ".extracted"
			if err := os.WriteFile(input, tc.source, 0o644); err != nil {
				t.Fatal(err)
			}
			inputInfo, err := os.Stat(input)
			if err != nil {
				t.Fatal(err)
			}
			wantMode := inputInfo.Mode().Perm()

			previous := output
			if tc.existing == "directory" {
				if err := os.Mkdir(output, 0o700); err != nil {
					t.Fatal(err)
				}
				previous = filepath.Join(output, "previous")
			}
			if tc.existing != "" {
				if err := os.WriteFile(previous, []byte("previous output"), 0o600); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(previous)
				if err != nil {
					t.Fatal(err)
				}
				wantMode &= info.Mode().Perm()
			}

			err = pbzxCmd.RunE(pbzxCmd, []string{input})
			if (err != nil) != tc.wantErr {
				t.Fatalf("extraction error = %v, want error = %v", err, tc.wantErr)
			}
			wantEntries := 2
			switch {
			case tc.wantErr && tc.existing == "":
				wantEntries = 1
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatalf("failed extraction left an output: %v", err)
				}
			default:
				want := payload
				if tc.wantErr {
					want = "previous output"
				}
				got, err := os.ReadFile(previous)
				if err != nil || string(got) != want {
					t.Fatalf("output = %q, %v; want %q", got, err, want)
				}
			}
			if !tc.wantErr {
				info, err := os.Stat(output)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != wantMode {
					t.Errorf("output mode = %04o, want %04o", info.Mode().Perm(), wantMode)
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != wantEntries {
				t.Errorf("extraction left unexpected files: %v, %v", entries, err)
			}
		})
	}
}
