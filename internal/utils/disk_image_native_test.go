//go:build darwin && integration

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

// Opt in with: go test -tags integration -run TestNativeDMGMount -v ./internal/utils
// These tests create synthetic HFS+ images. Teardown identifies attachments by
// exact canonical image path, never by a basename or a broad list of devices.
func TestNativeDMGMount(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "ipsw-native-mount-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	var images, mountDirs []string
	t.Cleanup(func() { cleanupNativeDMGs(t, root, images, mountDirs) })

	makeImage := func(side string) string {
		source := filepath.Join(root, side, "source")
		if err := os.MkdirAll(source, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(source, "marker"), []byte(side), 0600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, side, "same.dmg")
		images = append(images, path)
		out, err := runCommandWithFileOutput(exec.Command("/usr/bin/hdiutil", "create", "-size", "16m", "-fs", "HFS+", "-volname", "ipsw-test-"+side, "-srcfolder", source, path))
		if err != nil {
			t.Fatalf("create synthetic image: %v: %s", err, out)
		}
		return path
	}
	paths := []string{makeImage("A"), makeImage("B")}

	t.Run("concurrent same basename", func(t *testing.T) { testConcurrentNativeDMGs(t, paths, &mountDirs) })

	t.Run("reuse does not allocate", func(t *testing.T) { testNativeReuse(t, root, paths[0], &mountDirs) })

	t.Run("explicit directory survives", func(t *testing.T) {
		path := filepath.Join(root, "explicit")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(path, "caller-owned")
		if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		m, err := MountDMG(paths[0], path)
		if err != nil {
			t.Fatal(err)
		}
		if m.OwnsDirectory || m.AlreadyMounted {
			t.Fatalf("wrong ownership: %+v", m)
		}
		checkNativeMarker(t, m, "A")
		if err := m.Unmount(false); err != nil {
			t.Fatal(err)
		}
		if stat, err := os.Stat(path); err != nil || !stat.IsDir() {
			t.Fatalf("caller directory removed: %v", err)
		}
		if data, err := os.ReadFile(marker); err != nil || string(data) != "keep" {
			t.Fatalf("caller directory contents changed: %q, %v", data, err)
		}
	})

	t.Run("failed attach removes allocation", func(t *testing.T) {
		path := filepath.Join(root, filepath.Base(root)+"-invalid.dmg")
		if err := os.WriteFile(path, []byte("not a disk image"), 0600); err != nil {
			t.Fatal(err)
		}
		images = append(images, path)
		if m, err := MountDMG(path, ""); err == nil {
			mountDirs = append(mountDirs, m.MountPoint)
			t.Fatal("invalid image attached")
		}
		matches, err := filepath.Glob(fmt.Sprintf("/tmp/%s-*.mount", filepath.Base(path)))
		if err != nil || len(matches) != 0 {
			t.Fatalf("failed attach left directories: %v, %v", matches, err)
		}
	})
}

func cleanupNativeDMGs(t *testing.T, root string, images, mountDirs []string) {
	inventory, err := MountInfo()
	if err != nil {
		t.Errorf("retaining %s: cannot inventory test attachments: %v", root, err)
		return
	}
	for _, img := range inventory.Images {
		owned := false
		for _, path := range images {
			if filepath.Clean(img.ImagePath) == path {
				owned = true
				break
			}
		}
		if !owned {
			continue
		}
		device := ""
		for _, entry := range img.SystemEntities {
			if entry.DevEntry != "" {
				device = entry.DevEntry
				break
			}
		}
		if device == "" {
			t.Errorf("retaining %s: no device for test image %s", root, img.ImagePath)
			return
		}
		if out, err := runCommandWithFileOutput(exec.Command("/usr/bin/hdiutil", "detach", device, "-force")); err != nil {
			t.Errorf("retaining %s: detach test device %s: %v: %s", root, device, err, out)
			return
		}
	}
	inventory, err = MountInfo()
	if err != nil {
		t.Errorf("retaining %s: cannot verify detach: %v", root, err)
		return
	}
	for _, img := range inventory.Images {
		for _, path := range images {
			if filepath.Clean(img.ImagePath) == path {
				t.Errorf("retaining attached test image %s", path)
				return
			}
		}
	}
	for _, dir := range mountDirs {
		if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove empty test mount directory %s: %v", dir, err)
		}
	}
	if err := os.RemoveAll(root); err != nil {
		t.Errorf("remove detached test fixtures: %v", err)
	}
}

func checkNativeMarker(t *testing.T, m DMGMount, want string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.MountPoint, "marker"))
	if err != nil || string(data) != want {
		t.Fatalf("marker at %s = %q, want %q: %v", m.MountPoint, data, want, err)
	}
}

func checkNativeGone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("mount directory remains %s: %v", path, err)
	}
}

func testConcurrentNativeDMGs(t *testing.T, paths []string, mountDirs *[]string) {
	type result struct {
		index int
		mount DMGMount
		err   error
	}
	ready := make(chan struct{})
	results := make(chan result, 2)
	for index, path := range paths {
		go func() {
			<-ready
			m, err := MountDMG(path, "")
			results <- result{index, m, err}
		}()
	}
	close(ready)
	mounts := make([]DMGMount, 2)
	for range paths {
		r := <-results
		if r.err != nil {
			t.Errorf("mount %s: %v", paths[r.index], r.err)
			continue
		}
		mounts[r.index] = r.mount
		*mountDirs = append(*mountDirs, r.mount.MountPoint)
	}
	if t.Failed() {
		return
	}
	if mounts[0].MountPoint == mounts[1].MountPoint {
		t.Fatal("same-basename mounts collide")
	}
	for index, m := range mounts {
		if m.AlreadyMounted || !m.OwnsDirectory {
			t.Fatalf("wrong ownership: %+v", m)
		}
		checkNativeMarker(t, m, string(rune('A'+index)))
	}
	if err := mounts[0].Unmount(false); err != nil {
		t.Fatal(err)
	}
	checkNativeGone(t, mounts[0].MountPoint)
	checkNativeMarker(t, mounts[1], "B")
	if err := mounts[1].Unmount(false); err != nil {
		t.Fatal(err)
	}
	checkNativeGone(t, mounts[1].MountPoint)
}

func testNativeReuse(t *testing.T, root, path string, mountDirs *[]string) {
	m, err := MountDMG(path, "")
	if err != nil {
		t.Fatal(err)
	}
	*mountDirs = append(*mountDirs, m.MountPoint)
	before, err := filepath.Glob("/tmp/same.dmg-*.mount")
	if err != nil {
		t.Fatal(err)
	}
	borrowed, err := MountDMG(path, "")
	if err != nil {
		t.Fatal(err)
	}
	after, err := filepath.Glob("/tmp/same.dmg-*.mount")
	if err != nil {
		t.Fatal(err)
	}
	actual, err := filepath.EvalSymlinks(m.MountPoint)
	if err != nil {
		t.Fatal(err)
	}
	if !borrowed.AlreadyMounted || borrowed.OwnsDirectory || borrowed.MountPoint != actual || !reflect.DeepEqual(before, after) {
		t.Fatalf("reuse allocated or lost ownership: owner=%+v borrowed=%+v before=%v after=%v", m, borrowed, before, after)
	}
	custom := filepath.Join(root, "unused-custom")
	withCustom, err := MountDMG(path, custom)
	if err != nil || withCustom != borrowed {
		t.Fatalf("reuse with custom path = %+v, %v; want %+v", withCustom, err, borrowed)
	}
	checkNativeGone(t, custom)
	checkNativeMarker(t, borrowed, "A")
	if err := m.Unmount(false); err != nil {
		t.Fatal(err)
	}
	checkNativeGone(t, m.MountPoint)
}
