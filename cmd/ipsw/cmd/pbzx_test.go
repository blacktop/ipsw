package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/blacktop/ipsw/internal/atomicfile"
	"github.com/blacktop/ipsw/pkg/ota/pbzx"
	"github.com/spf13/cobra"
)

func pbzxTestSource(payload string) []byte {
	valid := []byte("pbzx")
	valid = binary.BigEndian.AppendUint64(valid, 0x1000000)
	valid = binary.BigEndian.AppendUint64(valid, uint64(len(payload)))
	valid = binary.BigEndian.AppendUint64(valid, uint64(len(payload)))
	return append(valid, payload...)
}

func TestPBZXOutput(t *testing.T) {
	const payload = "synthetic decompressed payload"
	valid := pbzxTestSource(payload)
	truncated := append(bytes.Clone(valid), 0)

	for _, tc := range []struct {
		name     string
		source   []byte
		existing string
		link     string
		wantErr  bool
		canceled bool
	}{
		{"new output", valid, "", "", false, false},
		{"replace output", valid, "file", "", false, false},
		{"preserve output on failure", truncated, "file", "", true, false},
		{"remove partial new output", truncated, "", "", true, false},
		{"failed rename", valid, "directory", "", true, false},
		{"canceled extraction", valid, "file", "", true, true},
		{"existing relative symlink", valid, "file", "relative", false, false},
		{"existing absolute symlink", valid, "file", "absolute", false, false},
		{"dangling symlink", valid, "", "relative", false, false},
		{"preserve symlink target on failure", truncated, "file", "relative", true, false},
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

			target := output
			link := ""
			wantEntries := map[string]int{dir: 2}
			if tc.link != "" {
				targetDir := filepath.Join(dir, "target")
				if err := os.Mkdir(targetDir, 0o700); err != nil {
					t.Fatal(err)
				}
				target = filepath.Join(targetDir, "output")
				link = filepath.Join("target", "output")
				if tc.link == "absolute" {
					link = target
				}
				if err := os.Symlink(link, output); err != nil {
					t.Fatal(err)
				}
				wantEntries[dir] = 3
				wantEntries[targetDir] = 1
			}
			previous := target
			if tc.existing == "directory" {
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				previous = filepath.Join(target, "previous")
			}
			if tc.existing != "" {
				if err := os.WriteFile(previous, []byte("previous output"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(previous, 0o764); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(previous)
				if err != nil {
					t.Fatal(err)
				}
				wantMode = info.Mode().Perm()
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.canceled {
				cancel()
			}
			cmd := &cobra.Command{}
			cmd.SetContext(ctx)
			err = pbzxCmd.RunE(cmd, []string{input})
			if (err != nil) != tc.wantErr {
				t.Fatalf("extraction error = %v, want error = %v", err, tc.wantErr)
			}
			if tc.canceled && !errors.Is(err, context.Canceled) {
				t.Fatalf("extraction error = %v, want context.Canceled", err)
			}
			switch {
			case tc.wantErr && tc.existing == "":
				wantEntries[filepath.Dir(target)]--
				if _, err := os.Stat(target); !os.IsNotExist(err) {
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
			if link != "" {
				if got, err := os.Readlink(output); err != nil || got != link {
					t.Fatalf("output symlink = %q, %v; want %q", got, err, link)
				}
			}
			if !tc.wantErr || tc.existing == "file" {
				info, err := os.Stat(output)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != wantMode {
					t.Errorf("output mode = %04o, want %04o", info.Mode().Perm(), wantMode)
				}
			}
			for path, count := range wantEntries {
				entries, err := os.ReadDir(path)
				if err != nil || len(entries) != count {
					t.Errorf("extraction left unexpected files in %s: %v, %v", path, entries, err)
				}
			}
		})
	}
}

func TestPBZXWriteFailure(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "output")
	if err := os.WriteFile(output, []byte("previous output"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := atomicfile.Write(output, 0o644, func(out *os.File) error {
		// A read-only descriptor produces a real write error from Extract.
		readOnly, err := os.Open(out.Name())
		if err != nil {
			return err
		}
		defer readOnly.Close()
		return pbzx.Extract(context.Background(), bytes.NewReader(pbzxTestSource("payload")), readOnly, 1)
	})
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || pathErr.Op != "write" {
		t.Fatalf("extraction error = %v, want a file write error", err)
	}
	if got, err := os.ReadFile(output); err != nil || string(got) != "previous output" {
		t.Fatalf("previous output = %q, %v", got, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("failed extraction left unexpected files: %v, %v", entries, err)
	}
}
