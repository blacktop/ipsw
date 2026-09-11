package mount

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/aea"
)

func TestDmgInIPSWFailureCleansOnlyCreatedImages(t *testing.T) {
	for _, preexisting := range []bool{false, true} {
		for _, imageName := range []string{"synthetic.dmg", "synthetic.dmg.aea", "malformed.dmg.aea"} {
			t.Run(fmt.Sprintf("existing=%t/%s", preexisting, imageName), func(t *testing.T) {
				data := []byte("synthetic unencrypted disk image content")
				ipsw, extractDir := writeMountTestIPSW(t, imageName, data)
				extracted := filepath.Join(extractDir, imageName)
				if preexisting {
					if err := os.WriteFile(extracted, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				called := false
				ctx, err := dmgInIPSW(ipsw, "fs", &Config{ExtractDir: extractDir}, func(path, _ string) (utils.DMGMount, error) {
					called = true
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, data) {
						t.Fatalf("extracted content = %q, error %v", got, err)
					}
					return utils.DMGMount{}, fmt.Errorf("synthetic attach: Permission denied")
				}, func(cfg *aea.DecryptConfig) (string, error) {
					if imageName == "malformed.dmg.aea" {
						return aea.Decrypt(cfg)
					}
					if cfg.Input != extracted || cfg.Output != extractDir {
						t.Fatalf("decrypt config = %+v", cfg)
					}
					path := strings.TrimSuffix(cfg.Input, ".aea")
					return path, os.WriteFile(path, data, 0600)
				})
				if ctx != nil || err == nil {
					t.Fatalf("ctx = %v, error = %v", ctx, err)
				}
				if imageName != "malformed.dmg.aea" && (!called || !strings.Contains(err.Error(), "Permission denied")) {
					t.Fatalf("did not exercise attach failure: %v", err)
				}
				if imageName == "malformed.dmg.aea" && called {
					t.Fatal("malformed AEA reached attach")
				}
				if strings.HasSuffix(imageName, ".aea") {
					if _, statErr := os.Stat(strings.TrimSuffix(extracted, ".aea")); !os.IsNotExist(statErr) {
						t.Fatalf("decrypted output survived failure: %v", statErr)
					}
				}
				got, statErr := os.ReadFile(extracted)
				if preexisting {
					if statErr != nil || !bytes.Equal(got, data) {
						t.Fatalf("preexisting file changed: %q, %v", got, statErr)
					}
				} else if !os.IsNotExist(statErr) {
					t.Fatalf("created file survived: %v", statErr)
				}
			})
		}
	}
}

func TestSessionClosePreservesPreexistingBackingImage(t *testing.T) {
	for _, preexisting := range []bool{false, true} {
		t.Run(fmt.Sprintf("existing=%t", preexisting), func(t *testing.T) {
			data := []byte("synthetic unencrypted disk image content")
			ipsw, extractDir := writeMountTestIPSW(t, "synthetic.dmg", data)
			extracted := filepath.Join(extractDir, "synthetic.dmg")
			if preexisting {
				if err := os.WriteFile(extracted, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			detached := 0
			session := NewSession(ipsw, &Config{ExtractDir: extractDir})
			session.mount = func(typ string) (*Context, error) {
				return dmgInIPSW(ipsw, typ, &session.cfg, func(path, _ string) (utils.DMGMount, error) {
					if path != extracted {
						t.Fatalf("attached unexpected path %q", path)
					}
					return utils.DMGMount{MountPoint: "/synthetic/mount", OwnsDirectory: true}, nil
				}, aea.Decrypt)
			}
			session.unmount = func(ctx *Context) error {
				if !ctx.OwnsDirectory || ctx.AlreadyMounted {
					t.Fatalf("attachment ownership lost before cleanup: %+v", ctx)
				}
				detached++
				return ctx.removeBackingFile()
			}
			if _, err := session.Root("fs"); err != nil {
				t.Fatal(err)
			}
			if err := session.Close(); err != nil {
				t.Fatal(err)
			}
			if detached != 1 {
				t.Fatalf("detached %d times", detached)
			}
			got, err := os.ReadFile(extracted)
			if preexisting {
				if err != nil || !bytes.Equal(got, data) {
					t.Fatalf("preexisting backing image not preserved: %q, %v", got, err)
				}
			} else if !os.IsNotExist(err) {
				t.Fatalf("owned backing image not removed: %v", err)
			}
		})
	}
}

func writeMountTestIPSW(t *testing.T, imageName string, data []byte) (string, string) {
	t.Helper()
	root := t.TempDir()
	ipsw := filepath.Join(root, "synthetic.ipsw")
	extractDir := filepath.Join(root, "extracted")
	if err := os.Mkdir(extractDir, 0750); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	manifest := `<?xml version="1.0"?><plist version="1.0"><dict><key>BuildIdentities</key><array><dict><key>Manifest</key><dict><key>OS</key><dict><key>Info</key><dict><key>Path</key><string>` + imageName + `</string></dict></dict></dict></dict></array></dict></plist>`
	for name, content := range map[string][]byte{"BuildManifest.plist": []byte(manifest), imageName: data} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ipsw, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return ipsw, extractDir
}

func TestContextRetainDmgSurvivesJSONRoundTrip(t *testing.T) {
	data, err := json.Marshal(Context{MountPoint: "/synthetic/mount", DmgPath: "/synthetic/image.dmg", RetainDmg: true, OwnsDirectory: true})
	if err != nil {
		t.Fatal(err)
	}
	var decoded Context
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.RetainDmg || !decoded.OwnsDirectory {
		t.Fatalf("ownership flags lost across the API boundary: %s", data)
	}
	backing := filepath.Join(t.TempDir(), "preexisting.dmg")
	if err := os.WriteFile(backing, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	decoded.DmgPath = backing
	if err := decoded.removeBackingFile(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(backing); err != nil {
		t.Fatalf("preexisting backing image removed after round trip: %v", err)
	}
}

func TestContextUnmountFailureOrdering(t *testing.T) {
	for _, failure := range []string{"", "detach"} {
		t.Run("failure="+failure, func(t *testing.T) {
			root := t.TempDir()
			backing := filepath.Join(root, "image.dmg")
			mountPoint := filepath.Join(root, "mount")
			if err := os.WriteFile(backing, []byte("synthetic backing"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(mountPoint, 0700); err != nil {
				t.Fatal(err)
			}
			ctx := Context{DmgPath: backing, MountPoint: mountPoint, OwnsDirectory: true}
			calls := 0
			err := ctx.unmount(func() error {
				calls++
				if _, err := os.Stat(backing); err != nil {
					t.Fatalf("backing removed before detach: %v", err)
				}
				switch failure {
				case "detach":
					return errors.New("synthetic busy mount")
				default:
					return os.Remove(mountPoint)
				}
			})
			wantCalls := 1
			if failure == "detach" {
				wantCalls = 3
			}
			if calls != wantCalls {
				t.Fatalf("detach calls = %d, want %d", calls, wantCalls)
			}
			if failure == "detach" {
				if !errors.Is(err, utils.ErrMountCleanup) {
					t.Fatalf("cleanup error not propagated: %v", err)
				}
				if data, err := os.ReadFile(backing); err != nil || string(data) != "synthetic backing" {
					t.Fatalf("backing not retained: %q, %v", data, err)
				}
				if _, err := os.Stat(mountPoint); err != nil {
					t.Fatalf("mount directory not retained: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(backing); !os.IsNotExist(err) {
					t.Fatalf("owned backing not removed: %v", err)
				}
			}
		})
	}
}

func TestSessionReleaseAfterSuccessfulDetach(t *testing.T) {
	backing := filepath.Join(t.TempDir(), "image.dmg")
	if err := os.WriteFile(backing, []byte("synthetic backing"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := &Context{DmgPath: backing, MountPoint: "/synthetic/mount", OwnsDirectory: true}
	s := NewSession("synthetic.ipsw", &Config{})
	s.mount = func(string) (*Context, error) { return ctx, nil }
	detaches := 0
	s.unmount = func(ctx *Context) error {
		return ctx.unmount(func() error {
			detaches++
			return nil
		})
	}
	if _, err := s.Root("sys"); err != nil {
		t.Fatal(err)
	}
	s.mounts["fs"] = &Context{MountPoint: ctx.MountPoint, AlreadyMounted: true}
	if err := s.Release("sys"); err != nil {
		t.Fatalf("Release failed: %v", err)
	}
	for _, typ := range []string{"sys", "fs"} {
		if _, cached := s.mounts[typ]; cached {
			t.Fatalf("detached alias %s was not evicted", typ)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if detaches != 1 {
		t.Fatalf("Release then Close detached %d times; want one", detaches)
	}
	if _, err := os.Stat(backing); !os.IsNotExist(err) {
		t.Fatalf("detached owned backing was retained: %v", err)
	}
}

func TestContextRetriesBackingCleanupWithoutDetaching(t *testing.T) {
	root := t.TempDir()
	backing := filepath.Join(root, "nonempty-backing")
	if err := os.Mkdir(backing, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(backing, "keep")
	if err := os.WriteFile(child, []byte("synthetic"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := &Context{DmgPath: backing, MountPoint: "/synthetic/mount"}
	detaches := 0
	detach := func() error { detaches++; return nil }
	if err := ctx.unmount(detach); err == nil {
		t.Fatal("expected nonrecursive backing cleanup to fail")
	}
	if err := os.Remove(child); err != nil {
		t.Fatal(err)
	}
	if err := ctx.unmount(detach); err != nil {
		t.Fatalf("could not retry backing cleanup: %v", err)
	}
	if detaches != 1 {
		t.Fatalf("cleanup retry detached %d times; want one", detaches)
	}
	if _, err := os.Stat(backing); !os.IsNotExist(err) {
		t.Fatalf("backing directory not removed: %v", err)
	}
}
