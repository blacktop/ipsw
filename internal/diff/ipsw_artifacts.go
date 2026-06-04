package diff

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/blacktop/ipsw/pkg/plist"
)

func (d *Diff) indexIdenticalIPSWArtifacts() {
	d.sameKernel = false
	d.sameVolumes = make(map[string]bool)
	if d.Old.InputMode != inputModeIPSW || d.New.InputMode != inputModeIPSW {
		return
	}

	d.sameKernel = ipswKernelcacheManifestDigestsEqual(d.Old.Info, d.New.Info)
	for _, typ := range ipswVolumeOrderMachos {
		if ipswVolumeManifestDigestsEqual(d.Old.Info, d.New.Info, typ) {
			d.sameVolumes[typ] = true
		}
	}
}

func (d *Diff) ipswVolumeUnchanged(typ string) bool {
	return d.sameVolumes != nil && d.sameVolumes[typ]
}

func (d *Diff) dscVolumeUnchanged() bool {
	if d.Old.InputMode != inputModeIPSW || d.New.InputMode != inputModeIPSW || !hasBuildManifest(d.Old.Info) || !hasBuildManifest(d.New.Info) {
		return false
	}
	if d.ipswVolumeUnchanged("sys") {
		return true
	}
	if volumeResolves(d.Old.Info, "sys") || volumeResolves(d.New.Info, "sys") {
		return false
	}
	return d.ipswVolumeUnchanged("fs")
}

func (d *Diff) allIPSWOSVolumesUnchanged() bool {
	if d.Old.InputMode != inputModeIPSW || d.New.InputMode != inputModeIPSW || !hasBuildManifest(d.Old.Info) || !hasBuildManifest(d.New.Info) {
		return false
	}

	var sawVolume bool
	for _, typ := range ipswVolumeOrderMachos {
		oldPresent := volumeResolves(d.Old.Info, typ)
		newPresent := volumeResolves(d.New.Info, typ)
		if oldPresent != newPresent {
			return false
		}
		if !oldPresent {
			continue
		}
		sawVolume = true
		if !d.ipswVolumeUnchanged(typ) {
			return false
		}
	}
	return sawVolume
}

func ipswKernelcacheManifestDigestsEqual(oldInfo, newInfo *info.Info) bool {
	if !hasBuildManifest(oldInfo) || !hasBuildManifest(newInfo) {
		return false
	}

	oldKCs := oldInfo.Plists.BuildManifest.GetKernelCaches()
	newKCs := newInfo.Plists.BuildManifest.GetKernelCaches()
	if len(oldKCs) == 0 || len(oldKCs) != len(newKCs) {
		return false
	}

	models := make([]string, 0, len(oldKCs))
	for model := range oldKCs {
		models = append(models, model)
	}
	slices.Sort(models)

	for _, model := range models {
		oldPaths := oldKCs[model]
		newPaths, ok := newKCs[model]
		if !ok || len(oldPaths) == 0 || len(newPaths) == 0 {
			return false
		}

		oldDigest, ok := uniqueManifestDigestForPath(oldInfo, "KernelCache", oldPaths[0])
		if !ok {
			return false
		}
		newDigest, ok := uniqueManifestDigestForPath(newInfo, "KernelCache", newPaths[0])
		if !ok {
			return false
		}
		if !bytes.Equal(oldDigest, newDigest) {
			return false
		}
	}
	return true
}

func ipswVolumeManifestDigestsEqual(oldInfo, newInfo *info.Info, typ string) bool {
	oldDigest, ok := ipswVolumeManifestDigest(oldInfo, typ)
	if !ok {
		return false
	}
	newDigest, ok := ipswVolumeManifestDigest(newInfo, typ)
	if !ok {
		return false
	}
	return bytes.Equal(oldDigest, newDigest)
}

// ipswVolumeManifestDigest resolves the BuildManifest digest for the DMG that
// backs volume typ (fs/sys/app/exc). It is the single per-volume digest source
// shared by the unchanged-volume short-circuit and machosJob/entsJob InputHash
// fingerprints, so a task's cache identity tracks the exact same artifact bytes
// the orchestrator uses to decide a volume is unchanged. ok is false when no
// BuildManifest, no manifest key, no resolvable path, or no unique digest
// exists for the volume.
func ipswVolumeManifestDigest(inf *info.Info, typ string) ([]byte, bool) {
	if !hasBuildManifest(inf) {
		return nil, false
	}
	key, ok := ipswVolumeManifestKey(typ)
	if !ok {
		return nil, false
	}
	path, err := ipswVolumePath(inf, typ)
	if err != nil {
		return nil, false
	}
	return uniqueManifestDigestForPath(inf, key, path)
}

// kernelcacheDMGInputHash digests the task-scope inputs for the kernelcache
// diff: the old and new BuildManifest KernelCache digests for every model,
// folded over sorted models, old then new. It reuses the exact digest source
// (GetKernelCaches + uniqueManifestDigestForPath under the "KernelCache" key)
// that ipswKernelcacheManifestDigestsEqual uses to decide the kernelcache is
// unchanged, so a task's cache identity tracks the same artifact bytes that
// drive the sameKernel short-circuit. A model with no resolvable digest on a
// side contributes a stable absent marker so its later appearance moves the
// hash.
func kernelcacheDMGInputHash(oldInfo, newInfo *info.Info) string {
	h := sha256.New()
	writeKernelcacheDigests(h, "old", oldInfo)
	writeKernelcacheDigests(h, "new", newInfo)
	return hex.EncodeToString(h.Sum(nil))
}

func writeKernelcacheDigests(h io.Writer, side string, inf *info.Info) {
	_, _ = h.Write([]byte(side))
	_, _ = h.Write([]byte{0})
	if !hasBuildManifest(inf) {
		_, _ = h.Write([]byte{0x00}) // absent marker
		return
	}
	kcs := inf.Plists.BuildManifest.GetKernelCaches()
	models := make([]string, 0, len(kcs))
	for model := range kcs {
		models = append(models, model)
	}
	slices.Sort(models)
	for _, model := range models {
		_, _ = h.Write([]byte(model))
		_, _ = h.Write([]byte{0})
		paths := kcs[model]
		if len(paths) == 0 {
			_, _ = h.Write([]byte{0x00}) // absent marker
			continue
		}
		digest, ok := uniqueManifestDigestForPath(inf, "KernelCache", paths[0])
		if !ok {
			_, _ = h.Write([]byte{0x00}) // absent marker
			continue
		}
		_, _ = h.Write([]byte{0x01}) // present marker
		_, _ = h.Write(digest)
		_, _ = h.Write([]byte{0})
	}
	_, _ = h.Write([]byte{0xff})
}

// ibootDMGInputHash digests the task-scope inputs for the iBoot diff: every
// "iBoot" BuildManifest entry digest, deduplicated and sorted, old then new.
// parseIBoot reads the iBoot im4p straight from the IPSW zip (the first member
// matching iBoot\..*\.im4p), so there is no single manifest path to key on;
// folding every distinct iBoot digest tracks any change to the iBoot firmware
// artifact regardless of which per-device variant the zip yields. A side with
// no resolvable iBoot digest contributes a stable absent marker.
func ibootDMGInputHash(oldInfo, newInfo *info.Info) string {
	h := sha256.New()
	writeIBootDigests(h, "old", oldInfo)
	writeIBootDigests(h, "new", newInfo)
	return hex.EncodeToString(h.Sum(nil))
}

func writeIBootDigests(h io.Writer, side string, inf *info.Info) {
	_, _ = h.Write([]byte(side))
	_, _ = h.Write([]byte{0})
	digests := ipswIBootManifestDigests(inf)
	if len(digests) == 0 {
		_, _ = h.Write([]byte{0x00}) // absent marker
		return
	}
	_, _ = h.Write([]byte{0x01}) // present marker
	for _, digest := range digests {
		_, _ = h.Write(digest)
		_, _ = h.Write([]byte{0})
	}
	_, _ = h.Write([]byte{0xff})
}

// ipswIBootManifestDigests returns every distinct "iBoot" BuildManifest entry
// digest, sorted for determinism. Multiple build identities (per device
// variant) may each carry an iBoot entry; duplicates are collapsed so the
// fingerprint is stable across identity ordering.
func ipswIBootManifestDigests(inf *info.Info) [][]byte {
	if !hasBuildManifest(inf) {
		return nil
	}
	seen := make(map[string]bool)
	var digests [][]byte
	for _, ident := range inf.Plists.BuildManifest.BuildIdentities {
		manifest, ok := ident.Manifest["iBoot"]
		if !ok || len(manifest.Digest) == 0 {
			continue
		}
		key := string(manifest.Digest)
		if seen[key] {
			continue
		}
		seen[key] = true
		digests = append(digests, append([]byte(nil), manifest.Digest...))
	}
	slices.SortFunc(digests, bytes.Compare)
	return digests
}

func ipswVolumeManifestKey(typ string) (string, bool) {
	switch typ {
	case "fs":
		return "OS", true
	case "sys":
		return "Cryptex1,SystemOS", true
	case "app":
		return "Cryptex1,AppOS", true
	case "exc":
		return "Ap,ExclaveOS", true
	default:
		return "", false
	}
}

func ipswVolumePath(inf *info.Info, typ string) (string, error) {
	if inf == nil {
		return "", info.ErrorCryptexNotFound
	}
	switch typ {
	case "fs":
		return inf.GetFileSystemOsDmg()
	case "sys":
		return inf.GetSystemOsDmg()
	case "app":
		return inf.GetAppOsDmg()
	case "exc":
		return inf.GetExclaveOSDmg()
	default:
		return "", info.ErrorCryptexNotFound
	}
}

func uniqueManifestDigestForPath(inf *info.Info, key, path string) ([]byte, bool) {
	if !hasBuildManifest(inf) {
		return nil, false
	}

	var digest []byte
	for _, ident := range inf.Plists.BuildManifest.BuildIdentities {
		manifest, ok := ident.Manifest[key]
		if !ok {
			continue
		}
		manifestPath, ok := identityManifestPath(manifest)
		if !ok || !strings.EqualFold(manifestPath, path) {
			continue
		}
		if len(manifest.Digest) == 0 {
			return nil, false
		}
		if digest == nil {
			digest = append([]byte(nil), manifest.Digest...)
			continue
		}
		if !bytes.Equal(digest, manifest.Digest) {
			return nil, false
		}
	}
	return digest, digest != nil
}

func identityManifestPath(manifest plist.IdentityManifest) (string, bool) {
	if manifest.Info == nil {
		return "", false
	}
	path, ok := manifest.Info["Path"].(string)
	if !ok || path == "" {
		return "", false
	}
	return path, true
}

func hasBuildManifest(inf *info.Info) bool {
	return inf != nil && inf.Plists != nil && inf.Plists.BuildManifest != nil
}

// volumeDMGInputHash digests the task-scope inputs shared by every job that
// reads all four IPSW OS volumes (fs/sys/app/exc). It is the InputHash source
// for machosJob, entsJob, featuresJob, and locsJob — all walk the identical
// four volumes, so they share one fingerprint. It delegates to
// volumeDMGInputHashFor with the full volume set.
func volumeDMGInputHash(oldInfo, newInfo *info.Info) string {
	return volumeDMGInputHashFor(oldInfo, newInfo, ipswVolumeOrderMachos...)
}

// volumeDMGInputHashFor digests the old and new BuildManifest DMG digests for
// the named volumes, in the order given. It is the per-volume fingerprint
// backing every OS-volume job's InputHash; callers that read all four volumes
// pass fs/sys/app/exc (via volumeDMGInputHash), while a single-volume job like
// launchdJob passes just "fs" so its cache identity ignores sys/app/exc.
//
// It reuses ipswVolumeManifestDigest, the same per-volume digest source the
// unchanged-volume short-circuit uses, so a task's cache identity tracks the
// exact artifact bytes that decide whether a volume changed. A volume with no
// resolvable digest contributes a stable absent marker so its later appearance
// changes the hash.
func volumeDMGInputHashFor(oldInfo, newInfo *info.Info, typs ...string) string {
	h := sha256.New()
	for _, typ := range typs {
		_, _ = h.Write([]byte(typ))
		_, _ = h.Write([]byte{0})
		writeVolumeDigest(h, "old", oldInfo, typ)
		writeVolumeDigest(h, "new", newInfo, typ)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func writeVolumeDigest(h io.Writer, side string, inf *info.Info, typ string) {
	_, _ = h.Write([]byte(side))
	_, _ = h.Write([]byte{0})
	digest, ok := ipswVolumeManifestDigest(inf, typ)
	if !ok {
		_, _ = h.Write([]byte{0x00}) // absent marker
		return
	}
	_, _ = h.Write([]byte{0x01}) // present marker
	_, _ = h.Write(digest)
	_, _ = h.Write([]byte{0})
}

// zipMember is one entry in an IPSW zip central directory, captured without
// decompressing any data. CRC32 and uncompressed size move when a member's
// content changes; the name moves when a member is added, removed, or renamed.
type zipMember struct {
	name string
	crc  uint32
	size uint64
}

// readZipCentralDirectory enumerates an IPSW zip's central directory and
// returns one zipMember per non-directory entry (name, CRC32, uncompressed
// size). No member data is decompressed. It is a package var so tests can
// substitute a fake listing without writing a real zip to disk: filesJob's
// InputHash must change when this listing changes even though no DMG digest
// moves.
var readZipCentralDirectory = func(ipswPath string) ([]zipMember, error) {
	zr, err := zip.OpenReader(ipswPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open IPSW zip %s: %w", ipswPath, err)
	}
	defer zr.Close()

	members := make([]zipMember, 0, len(zr.File))
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		members = append(members, zipMember{
			name: f.Name,
			crc:  f.CRC32,
			size: f.UncompressedSize64,
		})
	}
	return members, nil
}

// ipswZipListingDigest fingerprints the IPSW zip itself — every member's name,
// CRC32, and uncompressed size, sorted for determinism. It detects loose zip
// members added, removed, or changed at the zip root, which move no DMG digest
// and so are invisible to volumeDMGInputHashFor. filesJob folds this alongside
// the four DMG digests because it scans the zip (the "IPSW" pseudo-bucket) in
// addition to the mounted volumes.
func ipswZipListingDigest(ipswPath string) ([]byte, error) {
	return zipListingDigest(ipswPath, nil)
}

// ipswFirmwareZipListingDigest fingerprints the firmware artifacts firmwaresJob
// reads from the IPSW zip: every ".im4p" member's name, CRC32, and uncompressed
// size, sorted for determinism. DiffFirmwares → search.ForEachIm4pInIPSW selects
// exactly the members whose extension is ".im4p" (armfw ftab bundles, exclave
// bundles, and plain firmware payloads all match), so these loose zip members —
// not any BuildManifest DMG entry — are the firmware diff's true inputs. Folding
// them detects any firmware im4p added, removed, or changed even though no DMG
// digest moves. It reuses the readZipCentralDirectory seam so tests can substitute
// a fake listing.
func ipswFirmwareZipListingDigest(ipswPath string) ([]byte, error) {
	return zipListingDigest(ipswPath, func(m zipMember) bool {
		return filepath.Ext(m.name) == ".im4p"
	})
}

// zipListingDigest reads the zip central directory, keeps the members the
// filter accepts (nil keeps everything), and folds each kept member's
// name+CRC32+size into a sha256 in sorted-name order. Shared by the files
// (all members) and firmwares (.im4p members) InputHash computations so the
// fold format cannot drift between them.
func zipListingDigest(ipswPath string, filter func(zipMember) bool) ([]byte, error) {
	members, err := readZipCentralDirectory(ipswPath)
	if err != nil {
		return nil, err
	}
	kept := members
	if filter != nil {
		kept = make([]zipMember, 0, len(members))
		for _, m := range members {
			if filter(m) {
				kept = append(kept, m)
			}
		}
	}
	slices.SortFunc(kept, func(a, b zipMember) int {
		return strings.Compare(a.name, b.name)
	})

	h := sha256.New()
	for _, m := range kept {
		_, _ = h.Write([]byte(m.name))
		_, _ = h.Write([]byte{0})
		var b [12]byte
		binary.BigEndian.PutUint32(b[:4], m.crc)
		binary.BigEndian.PutUint64(b[4:], m.size)
		_, _ = h.Write(b[:])
	}
	return h.Sum(nil), nil
}

func filesSHA256Equal(oldPath, newPath string) (bool, error) {
	oldInfo, err := os.Stat(oldPath)
	if err != nil {
		return false, fmt.Errorf("failed to stat old file %s: %w", oldPath, err)
	}
	newInfo, err := os.Stat(newPath)
	if err != nil {
		return false, fmt.Errorf("failed to stat new file %s: %w", newPath, err)
	}
	if !oldInfo.Mode().IsRegular() || !newInfo.Mode().IsRegular() {
		return false, nil
	}
	if oldInfo.Size() != newInfo.Size() {
		return false, nil
	}

	oldHash, err := fileSHA256(oldPath)
	if err != nil {
		return false, err
	}
	newHash, err := fileSHA256(newPath)
	if err != nil {
		return false, err
	}
	return oldHash == newHash, nil
}

func fileSHA256(path string) ([sha256.Size]byte, error) {
	var sum [sha256.Size]byte
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return sum, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return sum, fmt.Errorf("failed to hash %s: %w", path, err)
	}
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// kernelcacheNoiseSegments are kernelcache segments whose bytes differ even
// when the kernel is functionally unchanged across a rebuild. Excluding them
// from the equality check lets us detect "Apple rebuilt the kernel without
// changing it" while still catching real code/data/symbol changes.
//
//   - __TEXT carries the mach_header and load commands, including LC_UUID
//     (regenerated per build).
//   - __PRELINK_INFO carries the kext bundle plist, which embeds build-root
//     paths, per-build hashes, and the build label (e.g. "23F77"). Plist-only
//     changes are also invisible to the existing kernel diff path, so skipping
//     this segment doesn't widen the blind spot.
var kernelcacheNoiseSegments = map[string]bool{
	"__TEXT":         true,
	"__PRELINK_INFO": true,
}

// kernelKeySegmentsEqual reports whether the two kernelcache Mach-Os carry the
// same bytes in every segment that holds functional content — code, constants,
// initialized data, and symbol tables — ignoring kernelcacheNoiseSegments.
// When true, no kernel code, kext code, constant data, mutable data, or symbol
// information differs even if the wrapper bytes (UUID, build-root strings,
// plist digests) do.
//
// Returns false if either side has a segment the other doesn't (after ignoring
// noise) or any checked segment is unreadable on either side; callers should
// treat that as "can't prove equal, run the full diff".
func kernelKeySegmentsEqual(oldKC, newKC *macho.File) bool {
	oldSegs := functionalSegments(oldKC)
	newSegs := functionalSegments(newKC)
	if len(oldSegs) == 0 || len(oldSegs) != len(newSegs) {
		return false
	}
	for name, oldSeg := range oldSegs {
		newSeg, ok := newSegs[name]
		if !ok {
			return false
		}
		if !segmentBytesEqual(oldSeg, newSeg) {
			return false
		}
	}
	return true
}

func functionalSegments(m *macho.File) map[string]*macho.Segment {
	out := make(map[string]*macho.Segment)
	for _, s := range m.Segments() {
		if kernelcacheNoiseSegments[s.Name] {
			continue
		}
		out[s.Name] = s
	}
	return out
}

func segmentBytesEqual(a, b *macho.Segment) bool {
	if a == nil || b == nil {
		return false
	}
	if a.Filesz != b.Filesz || a.Filesz == 0 {
		return false
	}
	da, err := a.Data()
	if err != nil || uint64(len(da)) != a.Filesz {
		return false
	}
	db, err := b.Data()
	if err != nil || uint64(len(db)) != b.Filesz {
		return false
	}
	return bytes.Equal(da, db)
}
