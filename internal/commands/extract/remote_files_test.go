package extract

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blacktop/go-apfs/types"
	gplist "github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/pkg/aea"
	"github.com/blacktop/ipsw/pkg/plist"
	"github.com/blacktop/ipsw/pkg/remote"
)

// A small synthetic sealed APFS tree with a physical extent tree and a single
// file near the end of an otherwise unread 8 MiB volume. No Apple data is used.
func rangedFixture(t *testing.T) []byte {
	t.Helper()
	le := binary.LittleEndian
	image := make([]byte, 8<<20)
	seal := func(b []byte) { le.PutUint64(b, types.CreateChecksum(b[8:])) }
	block := func(index int) []byte { return image[index*4096 : (index+1)*4096] }
	b := block(0)
	copy(b[32:], "NXSB")
	le.PutUint32(b[36:], 4096)
	le.PutUint64(b[40:], uint64(len(image)/4096))
	le.PutUint64(b[16:], 1)
	le.PutUint64(b[160:], 1)
	le.PutUint64(b[184:], 100)
	seal(b)
	b = block(1)
	le.PutUint64(b[48:], 2)
	seal(b)
	b = block(3)
	copy(b[32:], "APSB")
	le.PutUint64(b[56:], uint64(types.APFS_INCOMPAT_SEALED_VOLUME)) // permits the header-less hashed leaf
	le.PutUint64(b[128:], 4)
	le.PutUint64(b[136:], 200)
	le.PutUint64(b[1032:], 8)
	seal(b)
	b = block(4)
	le.PutUint64(b[48:], 5)
	le.PutUint64(b[16:], 1)
	seal(b)
	type rec struct{ k, v []byte }
	pair := func(oid, physical uint64) rec {
		k := make([]byte, 16)
		le.PutUint64(k, oid)
		le.PutUint64(k[8:], 1)
		v := make([]byte, 16)
		le.PutUint64(v[8:], physical)
		return rec{k, v}
	}
	node := func(index int, flags uint16, level uint16, records []rec) {
		b := block(index)
		le.PutUint16(b[32:], flags)
		le.PutUint16(b[34:], level)
		le.PutUint32(b[36:], uint32(len(records)))
		le.PutUint16(b[42:], uint16(len(records)*8))
		kb := 56 + len(records)*8
		kp := 0
		vp := 4096
		if flags&1 != 0 {
			vp -= 40
		}
		ve := vp
		for i, r := range records {
			loc := 56 + i*8
			le.PutUint16(b[loc:], uint16(kp))
			le.PutUint16(b[loc+2:], uint16(len(r.k)))
			copy(b[kb+kp:], r.k)
			kp += len(r.k)
			vp -= len(r.v)
			copy(b[vp:], r.v)
			le.PutUint16(b[loc+4:], uint16(ve-vp))
			le.PutUint16(b[loc+6:], uint16(len(r.v)))
		}
		if flags&0x10 == 0 {
			seal(b)
		}
	}
	node(2, 3, 0, []rec{pair(100, 3)})
	node(5, 3, 0, []rec{pair(200, 6), pair(201, 7)})
	key := func(id, kind uint64, size int) []byte {
		b := make([]byte, size)
		le.PutUint64(b, id|kind<<60)
		return b
	}
	name := "fixture.loctable"
	dirkey := key(2, 9, 12+len(name)+1)
	le.PutUint32(dirkey[8:], uint32(len(name)+1))
	copy(dirkey[12:], name)
	dirval := make([]byte, 18)
	le.PutUint64(dirval, 3)
	le.PutUint16(dirval[16:], 8)
	inode := make([]byte, 92)
	le.PutUint64(inode[8:], 3)
	le.PutUint16(inode[80:], 0100755)
	le.PutUint64(inode[84:], 7)
	node(7, 0x12, 0, []rec{{dirkey, dirval}, {key(3, 3, 8), inode}})
	hash := sha256.Sum256(block(7))
	child := make([]byte, 40)
	le.PutUint64(child, 1)
	copy(child[8:], hash[:])
	node(6, 9, 1, []rec{{key(2, 9, 8), child}})
	fkey := make([]byte, 16)
	le.PutUint64(fkey, 3)
	fval := make([]byte, 16)
	le.PutUint64(fval, 7)
	le.PutUint64(fval[8:], 2047)
	node(8, 3, 0, []rec{{fkey, fval}})
	copy(block(2047), "fixture")
	return image
}
func TestRangedRemoteFilesystem(t *testing.T) {
	for _, encrypted := range []bool{false, true} {
		t.Run(fmt.Sprint("aea=", encrypted), func(t *testing.T) {
			payload := rangedFixture(t)
			key := bytes.Repeat([]byte{5}, 32)
			if encrypted {
				dir := t.TempDir()
				name := filepath.Join(dir, "system")
				os.WriteFile(name, payload, 0600)
				if err := aea.Encrypt(name, &aea.EncryptConfig{Output: dir, SymmetricKey: key}); err != nil {
					t.Fatal(err)
				}
				var err error
				payload, err = os.ReadFile(name + ".aea")
				if err != nil {
					t.Fatal(err)
				}
			}
			var archive bytes.Buffer
			zw := zip.NewWriter(&archive)
			w, err := zw.CreateHeader(&zip.FileHeader{Name: "system.dmg", Method: zip.Store})
			if err != nil {
				t.Fatal(err)
			}
			w.Write(payload)
			metadata := testKernelInfo("kernelcache.release.n66")
			metadata.Plists.BuildManifest.ProductBuildVersion = "99A1"
			metadata.Plists.BuildManifest.BuildIdentities[0].Manifest["OS"] = plist.IdentityManifest{Info: map[string]any{"Path": "system.dmg"}}
			manifest, err := gplist.Marshal(metadata.Plists.BuildManifest, gplist.XMLFormat)
			if err != nil {
				t.Fatal(err)
			}
			mw, err := zw.Create("BuildManifest.plist")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := mw.Write(manifest); err != nil {
				t.Fatal(err)
			}
			if err := zw.Close(); err != nil {
				t.Fatal(err)
			}
			data := archive.Bytes()
			var downloaded atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("ETag", `"fixture"`)
				w.Header().Set("Accept-Ranges", "bytes")
				if r.Method == "HEAD" {
					w.Header().Set("Content-Length", fmt.Sprint(len(data)))
					return
				}
				var start, end int
				if _, err := fmt.Sscanf(r.Header.Get("Range"), "bytes=%d-%d", &start, &end); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
				w.WriteHeader(206)
				downloaded.Add(int64(end - start + 1))
				w.Write(data[start : end+1])
			}))
			defer server.Close()
			destination := t.TempDir()
			config := &Config{URL: server.URL, Ranged: true, DMGs: true, Pattern: ".*", Output: destination}
			defer config.Close()
			if encrypted {
				config.AEAKey = base64.StdEncoding.EncodeToString(key)
			}
			paths, err := Search(config)
			if err != nil {
				t.Fatal(err)
			}
			if len(paths) != 1 {
				t.Fatalf("outputs: %v", paths)
			}
			got, err := os.ReadFile(paths[0])
			if err != nil || string(got) != "fixture" {
				t.Fatal(string(got), err)
			}
			if info, err := os.Stat(paths[0]); err != nil || info.Mode().Perm() != 0755 {
				t.Fatal(info, err)
			}
			if !encrypted && downloaded.Load() > int64(len(data))/4 {
				t.Fatalf("downloaded %d of %d bytes", downloaded.Load(), len(data))
			}
			// A pre-existing output symlink must never redirect writes outside the root.
			outside := filepath.Join(t.TempDir(), "victim")
			os.WriteFile(outside, []byte("unchanged"), 0600)
			os.Remove(paths[0])
			os.Symlink(outside, paths[0])
			zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := extractRemoteDMGRanged(config, zr, "system.dmg", filepath.Dir(paths[0]), "", regexp.MustCompile(`fixture`)); err != nil {
				t.Fatal(err)
			}
			got, _ = os.ReadFile(outside)
			if string(got) != "unchanged" {
				t.Fatal("followed output symlink")
			}
			// A rerun restores the image's permission bits on an existing output.
			os.Chmod(paths[0], 0600)
			if _, err := extractRemoteDMGRanged(config, zr, "system.dmg", filepath.Dir(paths[0]), "", regexp.MustCompile(`fixture`)); err != nil {
				t.Fatal(err)
			}
			if info, err := os.Lstat(paths[0]); err != nil || info.Mode() != 0755 {
				t.Fatal(info, err)
			}
		})
	}
}

func TestRangedRejectsDeflatedDMG(t *testing.T) {
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	w, err := zw.Create("system.dmg")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(rangedFixture(t))
	zw.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "image", time.Time{}, bytes.NewReader(archive.Bytes()))
	}))
	defer server.Close()
	zr, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		t.Fatal(err)
	}
	out, err := extractRemoteDMGRanged(&Config{URL: server.URL}, zr, "system.dmg", t.TempDir(), "", regexp.MustCompile(".*"))
	if len(out) != 0 || err == nil || !strings.Contains(err.Error(), "stored ZIP member") {
		t.Fatalf("unexpected fallback or error: %v %v", out, err)
	}
}

// A disk image that is not a ZIP member opens through the same chain.
func TestOpenAPFSImage(t *testing.T) {
	image := rangedFixture(t)
	filesystem, err := remote.OpenAPFS(bytes.NewReader(image), int64(len(image)), nil)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := filesystem.Lookup("fixture.loctable")
	if err != nil || entry.Type != uint16(types.DT_REG) {
		t.Fatalf("lookup: %+v %v", entry, err)
	}
}
