package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAttachDarwinImageBackends(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, encrypted := range []bool{false, true} {
			name := "diskutil"
			if legacy {
				name = "hdiutil"
			}
			if encrypted {
				name += "/encrypted"
			}
			t.Run(name, func(t *testing.T) {
				var password io.Reader
				if encrypted {
					password = strings.NewReader("synthetic password")
				}
				calls := 0
				err := attachDarwinImage("/tmp/image with spaces.dmg", "/tmp/mount with spaces", password, func(cmd *exec.Cmd) ([]byte, error) {
					calls++
					if calls == 1 {
						if want := []string{"/usr/sbin/diskutil", "image", "attach", "--help"}; !reflect.DeepEqual(cmd.Args, want) {
							t.Fatalf("probe = %q", cmd.Args)
						}
						if cmd.Stdin != nil {
							t.Fatal("probe received password")
						}
						if legacy {
							return []byte(`diskutil: did not recognize verb "image"; type "diskutil" for a list`), errors.New("exit status 1")
						}
						return []byte("USAGE: diskutil image attach [--mountPoint <mountPoint>]"), nil
					}
					want := []string{"/usr/sbin/diskutil", "image", "attach", "--mountPoint", "/tmp/mount with spaces"}
					if legacy {
						want = []string{"/usr/bin/hdiutil", "attach", "-noverify", "-mountpoint", "/tmp/mount with spaces"}
					}
					if encrypted {
						flag := "--stdinpassphrase"
						if legacy {
							flag = "-stdinpass"
						}
						want = append(want, flag)
						data, err := io.ReadAll(cmd.Stdin)
						if err != nil || string(data) != "synthetic password" {
							t.Fatalf("password input = %q, %v", data, err)
						}
					} else if cmd.Stdin != nil {
						t.Fatal("unexpected stdin")
					}
					want = append(want, "/tmp/image with spaces.dmg")
					if !reflect.DeepEqual(cmd.Args, want) {
						t.Fatalf("attach = %q, want %q", cmd.Args, want)
					}
					return []byte("attached"), nil
				})
				if err != nil || calls != 2 {
					t.Fatalf("error = %v, calls = %d", err, calls)
				}
			})
		}
	}
}

func TestAttachDarwinImageDoesNotFallbackOnFailure(t *testing.T) {
	failure := errors.New("exit status 1")
	for _, tc := range []struct {
		name, probe, output string
		probeErr            error
		calls               int
		busy                bool
	}{
		{name: "permission", probe: "--mountPoint", output: "Permission denied", calls: 2},
		{name: "busy", probe: "--mountPoint", output: "Resource busy", calls: 2, busy: true},
		{name: "framework", probe: "Unable to use the DiskManagement framework", probeErr: failure, calls: 1},
		{name: "unexpected help", probe: "unknown help output", calls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := attachDarwinImage("/tmp/test.dmg", "/tmp/test.mount", nil, func(cmd *exec.Cmd) ([]byte, error) {
				calls++
				if calls == 1 {
					return []byte(tc.probe), tc.probeErr
				}
				if cmd.Path != "/usr/sbin/diskutil" {
					t.Fatal("fell back after failure")
				}
				return []byte(tc.output), failure
			})
			if err == nil || calls != tc.calls {
				t.Fatalf("error = %v, calls = %d, want %d", err, calls, tc.calls)
			}
			if tc.output != "" && !strings.Contains(err.Error(), tc.output) {
				t.Fatalf("missing failure output: %v", err)
			}
			if errors.Is(err, ErrMountResourceBusy) != tc.busy {
				t.Fatalf("busy classification = %v", err)
			}
			if (tc.name == "permission" || tc.name == "framework") && !errors.Is(err, failure) {
				t.Fatalf("lost underlying error: %v", err)
			}
		})
	}
}

func TestAttachDarwinImagePreservesMultilinePassword(t *testing.T) {
	for _, password := range []string{"synthetic-password\n", "synthetic\npassword", "synthetic\rpassword"} {
		t.Run(fmt.Sprintf("%q", password), func(t *testing.T) {
			calls := 0
			err := attachDarwinImage("/tmp/test.dmg", "/tmp/test.mount", strings.NewReader(password), func(cmd *exec.Cmd) ([]byte, error) {
				calls++
				if calls == 1 {
					return []byte("--mountPoint"), nil
				}
				if cmd.Path != "/usr/bin/hdiutil" {
					t.Fatalf("multiline password sent to %s, which cannot preserve line breaks", cmd.Path)
				}
				got, err := io.ReadAll(cmd.Stdin)
				if err != nil || string(got) != password {
					t.Fatalf("password bytes changed: %q, %v", got, err)
				}
				return nil, nil
			})
			if err != nil || calls != 2 {
				t.Fatalf("error = %v, calls = %d", err, calls)
			}
		})
	}
}

func TestMountInfoMatchesExactMountPoint(t *testing.T) {
	info := HdiUtilInfo{Images: []image{
		{ImagePath: "other.dmg", SystemEntities: []systemEntry{{MountPoint: "/tmp/test.mount-extra"}}},
		{ImagePath: "target.dmg", SystemEntities: []systemEntry{{MountPoint: "/tmp/test.mount"}}},
	}}
	got := info.Mount("/tmp/test.mount")
	if got == nil || got.ImagePath != "target.dmg" {
		t.Fatalf("selected wrong backing image: %+v", got)
	}
	if got := info.Mount(""); got != nil {
		t.Fatalf("empty mount selected %+v", got)
	}
	if got := info.Mount("/tmp"); got != nil {
		t.Fatalf("parent directory selected %+v", got)
	}
}

func TestMountInfoMatchesSymlinkedMountPoint(t *testing.T) {
	root := t.TempDir()
	realMount := filepath.Join(root, "mount")
	alias := filepath.Join(root, "alias")
	if err := os.Mkdir(realMount, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realMount, alias); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(realMount)
	if err != nil {
		t.Fatal(err)
	}
	info := HdiUtilInfo{Images: []image{{ImagePath: "target.dmg", SystemEntities: []systemEntry{{MountPoint: canonical}}}}}
	if got := info.Mount(alias); got == nil || got.ImagePath != "target.dmg" {
		t.Fatalf("mount alias not resolved: %+v", got)
	}
}
