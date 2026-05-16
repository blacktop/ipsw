package download

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/download/pcc"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fatih/color"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

const bagURL = "https://init-kt-prod.ess.apple.com/init/getBag?ix=5&p=atresearch"

const pccLogLeavesBatchSize uint64 = 3000

const (
	cloudOSInfoAppID   = "com.apple.cloudos.cloudOSInfo"
	vreDevicePrefix    = "vresearch"
	vreResearchVariant = "Research VM"

	// VPhoneFirmwareToken is the substring that identifies vphone600
	// research-device firmware inside a PCC OS asset IPSW central
	// directory (DeviceTree, sep-firmware, kernelcache.*.vphone600).
	VPhoneFirmwareToken = "vphone600"
)

type BagResponse struct {
	UUID                          string `plist:"uuid,omitempty"`
	AtResearcherConsistencyProof  string `plist:"at-researcher-consistency-proof,omitempty"`
	AtResearcherListTrees         string `plist:"at-researcher-list-trees,omitempty"`
	AtResearcherLogHead           string `plist:"at-researcher-log-head,omitempty"`
	AtResearcherLogInclusionProof string `plist:"at-researcher-log-inclusion-proof,omitempty"`
	AtResearcherLogLeaves         string `plist:"at-researcher-log-leaves,omitempty"`
	AtResearcherPublicKeys        string `plist:"at-researcher-public-keys,omitempty"`
	BagExpiryTimestamp            int    `plist:"bag-expiry-timestamp,omitempty"`
	BagType                       string `plist:"bag-type,omitempty"`
	BuildVersion                  string `plist:"build-version,omitempty"`
	Platform                      string `plist:"platform,omitempty"`
	TtrEnabled                    int    `plist:"ttr-enabled,omitempty"`
}

type pccInstance struct {
	HttpService struct {
		Enabled bool `plist:"enabled,omitempty"`
	} `plist:"httpService,omitempty"`
	Name          string `plist:"name,omitempty"`
	ReleaseAssets []struct {
		File    string `plist:"file,omitempty"`
		Type    string `plist:"type,omitempty"`
		Variant string `plist:"variant,omitempty"`
	} `plist:"releaseAssets,omitempty"`
	ReleaseID string `plist:"releaseID,omitempty"`
}

type TransparencyExtension struct {
	Type uint8
	Size uint16
	Data []byte
}

type ATLeaf struct {
	Version         uint8
	Type            uint8
	DescriptionSize uint8
	Description     []byte
	HashSize        uint8
	Hash            []byte
	ExpiryMS        uint64
	ExtensionsSize  uint16
	Extensions      []TransparencyExtension
}

type Ticket struct {
	Raw            asn1.RawContent
	Version        int
	ApTicket       asn1.RawValue
	CryptexTickets []asn1.RawValue `asn1:"set"`
}

var colorField = color.New(color.Bold, color.FgHiBlue).SprintFunc()
var colorTypeField = color.New(color.Bold, color.FgHiMagenta).SprintFunc()
var colorHash = color.New(color.Faint).SprintfFunc()
var colorName = color.New(color.Bold).SprintfFunc()
var colorCreateTime = color.New(color.Faint, color.FgGreen).SprintFunc()
var colorExpireTime = color.New(color.Faint, color.FgRed).SprintFunc()

type PCCRelease struct {
	Index uint64
	pcc.ReleaseMetadata
	Ticket
	*ATLeaf

	// Version and VPhone are populated lazily from the IPSW central
	// directory (BuildManifest.plist version and vphone600 file presence)
	// and persisted inline in pcc_log.json so they're reused on later runs.
	Version *PCCVersion     `json:"-"`
	VPhone  *VPhoneFirmware `json:"-"`

	// cachedPrefs memoizes cloudOSPrefs across CloudOSInfo+VRE on the same
	// release. Non-nil means computed (empty map = no darwinInit prefs).
	cachedPrefs map[string]string
}

func (r *PCCRelease) ReleaseID() string {
	if r == nil {
		return ""
	}
	if digest := r.GetReleaseDigest(); len(digest) > 0 {
		return hex.EncodeToString(digest)
	}
	if r.ATLeaf == nil {
		return ""
	}
	return hex.EncodeToString(r.ATLeaf.Hash)
}

func (r *PCCRelease) ReleaseCreationTime() time.Time {
	if r == nil {
		return time.Time{}
	}
	ts := r.GetReleaseCreation()
	if ts == nil {
		return time.Time{}
	}
	return ts.AsTime()
}

// cloudOSPrefs returns com.apple.cloudos.cloudOSInfo preferences from
// darwinInit. Result is memoized per release because both CloudOSInfo and
// VRE call this, and structpb.AsMap is a recursive proto→map conversion.
func (r *PCCRelease) cloudOSPrefs() map[string]string {
	if r == nil {
		return nil
	}
	if r.cachedPrefs != nil {
		return r.cachedPrefs
	}
	out := map[string]string{}
	if di := r.GetDarwinInit(); di != nil {
		prefs, _ := di.AsMap()["preferences"].([]any)
		for _, p := range prefs {
			m, _ := p.(map[string]any)
			if m["application_id"] != cloudOSInfoAppID {
				continue
			}
			k, _ := m["key"].(string)
			v, _ := m["value"].(string)
			if k != "" {
				out[k] = v
			}
		}
	}
	r.cachedPrefs = out
	return out
}

// CloudOSInfo returns build/train/app from darwinInit's cloudOSInfo prefs,
// falling back to ReleaseMetadata.BuildVersion / Application.Name when
// darwinInit is absent (older or stripped releases).
func (r *PCCRelease) CloudOSInfo() (build, train, app string) {
	if r == nil {
		return
	}
	prefs := r.cloudOSPrefs()
	build = prefs["cloudOSBuildVersion"]
	train = prefs["cloudOSBuildTrain"]
	app = prefs["cloudOSApplicationName"]
	if build == "" {
		build = r.GetBuildVersion()
	}
	if app == "" {
		app = r.GetApplication().GetName()
	}
	return
}

// VRESignals captures metadata-only indicators that a PCC release is a
// Virtual Research Environment (VRE) build — a research-bootable cloudOS
// image that apple/security-pcc's pccvre tool (and community wrappers
// like vphone-cli) can launch under Virtualization.framework.
type VRESignals struct {
	Device             string // cloudOSDevice preference (e.g. "vresearch101ap")
	HasDebugShell      bool   // ASSET_TYPE_DEBUG_SHELL present
	HasResearchVariant bool   // any asset variant contains "Research VM"
}

// IsVRE reports whether s indicates a VRE/vphone-style research-VM release.
func (s VRESignals) IsVRE() bool {
	return strings.HasPrefix(s.Device, vreDevicePrefix) ||
		(s.HasDebugShell && s.HasResearchVariant)
}

// VRE returns metadata indicators of a VRE/vphone-style research-VM release.
func (r *PCCRelease) VRE() VRESignals {
	var s VRESignals
	if r == nil {
		return s
	}
	s.Device = r.cloudOSPrefs()["cloudOSDevice"]
	for _, a := range r.GetAssets() {
		if a.GetType() == pcc.ReleaseMetadata_ASSET_TYPE_DEBUG_SHELL {
			s.HasDebugShell = true
		}
		if strings.Contains(a.GetVariant(), vreResearchVariant) {
			s.HasResearchVariant = true
		}
	}
	return s
}

// OSAssetURL returns the URL of the ASSET_TYPE_OS asset (the IPSW).
func (r *PCCRelease) OSAssetURL() string {
	for _, a := range r.GetAssets() {
		if a.GetType() == pcc.ReleaseMetadata_ASSET_TYPE_OS {
			return a.GetUrl()
		}
	}
	return ""
}

// OSAssetDigest returns the SHA256 hex digest of the OS asset, which is the
// final path segment of the asset URL and the immutable cache key.
func (r *PCCRelease) OSAssetDigest() string {
	url := r.OSAssetURL()
	if url == "" {
		return ""
	}
	return path.Base(url)
}

// PCCVersion is the ProductVersion/Build pair from an OS asset's BuildManifest.
type PCCVersion struct {
	Version string `json:"v"`
	Build   string `json:"b"`
}

// VPhoneFirmware records whether an OS asset IPSW carries vphone600 firmware.
// Apple shipped vphone600 (DeviceTree, sep-firmware, kernelcache.*.vphone600)
// alongside vresearch101 through cloudOS train 5E (iOS 26.3); starting with
// train 5F (iOS 26.4) only vresearch101 is present, so iPhone-shaped
// virtualization (vphone-cli) no longer works.
type VPhoneFirmware struct {
	Present bool `json:"present"`
	Count   int  `json:"count,omitempty"`
}

const pccLogCacheFile = "pcc_log.json"

// pccLogCache is the on-disk PCC AT-log cache. Storing the parsed release
// leaves + per-release vphone/version resolutions in one file lets warm
// runs skip the ~15s log replay and the ~30s of partial-zip fetches.
//
// TreeID changes invalidate the entire cache (Apple periodically rotates
// the AT log tree); a mismatch triggers a full refetch from index 0.
type pccLogCache struct {
	TreeID    uint64              `json:"tree_id"`
	HeadIndex uint64              `json:"head_index"` // log size at last fetch
	Releases  []*pccCachedRelease `json:"releases"`   // parsed release leaves, ordered by Index
}

// pccCachedRelease is one release leaf's wire bytes plus resolved data.
// Bytes are the source of truth — we re-parse on load instead of trying to
// JSON-marshal the proto/asn1 structures directly.
type pccCachedRelease struct {
	Index         uint64          `json:"index"`
	ATLeaf        ATLeaf          `json:"leaf"`
	MetadataBytes []byte          `json:"metadata_pb"`     // proto.Marshal(ReleaseMetadata)
	TicketBytes   []byte          `json:"ticket_asn1"`     // asn1 raw (Ticket.Raw)
	Version       *PCCVersion     `json:"version,omitempty"` // resolved BuildManifest.plist version
	VPhone        *VPhoneFirmware `json:"vphone,omitempty"`  // resolved vphone600 presence
}

func (cr *pccCachedRelease) toRelease() (*PCCRelease, error) {
	leaf := cr.ATLeaf
	r := &PCCRelease{
		Index:   cr.Index,
		ATLeaf:  &leaf,
		Version: cr.Version,
		VPhone:  cr.VPhone,
	}
	if err := proto.Unmarshal(cr.MetadataBytes, &r.ReleaseMetadata); err != nil {
		return nil, fmt.Errorf("unmarshal cached metadata: %w", err)
	}
	if _, err := asn1.Unmarshal(cr.TicketBytes, &r.Ticket); err != nil {
		return nil, fmt.Errorf("asn1 unmarshal cached ticket: %w", err)
	}
	return r, nil
}

func releaseToCached(r *PCCRelease) (*pccCachedRelease, error) {
	if r.ATLeaf == nil {
		return nil, fmt.Errorf("release %d missing ATLeaf", r.Index)
	}
	metaBytes, err := proto.Marshal(&r.ReleaseMetadata)
	if err != nil {
		return nil, fmt.Errorf("marshal metadata: %w", err)
	}
	ticketBytes := []byte(r.Ticket.Raw)
	if len(ticketBytes) == 0 {
		return nil, fmt.Errorf("release %d missing raw ticket bytes", r.Index)
	}
	return &pccCachedRelease{
		Index:         r.Index,
		ATLeaf:        *r.ATLeaf,
		MetadataBytes: metaBytes,
		TicketBytes:   ticketBytes,
		Version:       r.Version,
		VPhone:        r.VPhone,
	}, nil
}

func loadPCCLogCache() *pccLogCache {
	dir, err := getCacheDir()
	if err != nil {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, pccLogCacheFile))
	if err != nil {
		return nil
	}
	var c pccLogCache
	if err := json.Unmarshal(data, &c); err != nil {
		return nil
	}
	return &c
}

func savePCCLogCache(c *pccLogCache) {
	dir, err := getCacheDir()
	if err != nil {
		return
	}
	data, err := json.Marshal(c)
	if err != nil {
		return
	}
	os.WriteFile(filepath.Join(dir, pccLogCacheFile), data, 0o644)
}

// persistReleaseResolutions updates the on-disk cache to reflect Version
// and VPhone values that were resolved into the in-memory releases since
// the last save. No-op when there's no cache yet (the resolutions are also
// written by ResolvePCC* paths that operate on freshly-fetched releases).
func persistReleaseResolutions(releases []*PCCRelease) {
	c := loadPCCLogCache()
	if c == nil {
		return
	}
	byIdx := make(map[uint64]*pccCachedRelease, len(c.Releases))
	for _, cr := range c.Releases {
		byIdx[cr.Index] = cr
	}
	changed := false
	for _, r := range releases {
		cr, ok := byIdx[r.Index]
		if !ok {
			continue
		}
		if r.Version != nil && cr.Version == nil {
			cr.Version = r.Version
			changed = true
		}
		if r.VPhone != nil && cr.VPhone == nil {
			cr.VPhone = r.VPhone
			changed = true
		}
	}
	if changed {
		savePCCLogCache(c)
	}
}

// resolveOSAssetField runs fetch concurrently over each unique OS asset
// digest that doesn't yet have a value, attaches results back to every
// release sharing that digest, and persists the new values into the
// unified pcc_log.json cache.
func resolveOSAssetField[T any](
	releases []*PCCRelease,
	label string,
	get func(*PCCRelease) *T, // returns current value (nil = unresolved)
	set func(*PCCRelease, *T), // writes value back to release
	fetch func(url string) (T, error),
	keep func(T) bool,
) {
	// Skip the per-digest map allocation on warm runs where every release
	// already has a value loaded from cache.
	allResolved := true
	for _, r := range releases {
		if r.OSAssetDigest() != "" && get(r) == nil {
			allResolved = false
			break
		}
	}
	if allResolved {
		return
	}

	byDigest := make(map[string][]*PCCRelease)
	for _, r := range releases {
		if d := r.OSAssetDigest(); d != "" {
			byDigest[d] = append(byDigest[d], r)
		}
	}

	type job struct{ digest, url string }
	var jobs []job
	backfilled := false
	for digest, rs := range byDigest {
		// If any release for this digest already has a value (e.g., loaded
		// from cache), copy it across to siblings without fetching.
		var have *T
		for _, r := range rs {
			if v := get(r); v != nil {
				have = v
				break
			}
		}
		if have != nil {
			for _, r := range rs {
				if get(r) == nil {
					set(r, have)
					backfilled = true
				}
			}
			continue
		}
		jobs = append(jobs, job{digest, rs[0].OSAssetURL()})
	}
	if len(jobs) == 0 {
		// Nothing to fetch but copies may still need to land on disk so a
		// subsequent run filtered to one of the previously-uncached siblings
		// doesn't re-fetch the same central directory.
		if backfilled {
			persistReleaseResolutions(releases)
		}
		return
	}

	log.Infof("Resolving %d uncached PCC OS %s...", len(jobs), label)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	resolved := make(map[string]*T, len(jobs))
	for _, j := range jobs {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			v, err := fetch(j.url)
			if err != nil {
				log.Warnf("resolve %s %s: %v", label, j.digest, err)
				return
			}
			if keep != nil && !keep(v) {
				return
			}
			mu.Lock()
			resolved[j.digest] = &v
			mu.Unlock()
		})
	}
	wg.Wait()

	if len(resolved) == 0 {
		return
	}
	for digest, val := range resolved {
		for _, r := range byDigest[digest] {
			set(r, val)
		}
	}
	persistReleaseResolutions(releases)
}

// ResolvePCCVersions partial-zips each release's OS asset to read
// BuildManifest.plist's ProductVersion. Results are attached to each
// release's Version field and persisted in pcc_log.json so subsequent runs
// skip the fetch.
func ResolvePCCVersions(releases []*PCCRelease, fetch func(url string) (PCCVersion, error)) {
	resolveOSAssetField(releases, "versions",
		func(r *PCCRelease) *PCCVersion { return r.Version },
		func(r *PCCRelease, v *PCCVersion) { r.Version = v },
		fetch,
		func(v PCCVersion) bool { return v.Version != "" })
}

// ResolveVPhoneFirmware partial-zips each release's OS asset and checks
// for vphone600 firmware files. Absence is cached intentionally — it's the
// sticky signal that drives the future alert.
func ResolveVPhoneFirmware(releases []*PCCRelease, fetch func(url string) (VPhoneFirmware, error)) {
	resolveOSAssetField(releases, "vphone firmware checks",
		func(r *PCCRelease) *VPhoneFirmware { return r.VPhone },
		func(r *PCCRelease, v *VPhoneFirmware) { r.VPhone = v },
		fetch,
		nil)
}

func (r *PCCRelease) String() string {
	var out strings.Builder
	out.WriteString(fmt.Sprintf("%d) %s\n", r.Index, colorHash(r.ReleaseID())))
	if build, train, app := r.CloudOSInfo(); build != "" {
		out.WriteString(fmt.Sprintf(colorField("Build")+":  %s", colorName(build)))
		if train != "" {
			out.WriteString(fmt.Sprintf(" (%s)", train))
		}
		if app != "" {
			out.WriteString(fmt.Sprintf("  %s", colorTypeField(app)))
		}
		out.WriteString("\n")
	}
	out.WriteString(fmt.Sprintf(colorField("Type")+":   %s\n", pcc.ATLogDataType(r.Type).String()))
	out.WriteString(fmt.Sprintf(colorField("Schema")+": %s\n", string(r.SchemaVersion.String())))
	out.WriteString(colorField("Assets\n"))
	for _, asset := range r.GetAssets() {
		out.WriteString(fmt.Sprintf("    [%s]\n", colorTypeField(strings.TrimPrefix(asset.GetType().String(), "ASSET_TYPE_"))))
		out.WriteString(fmt.Sprintf(colorField("        Variant")+": %s\n", colorName(asset.GetVariant())))
		out.WriteString(fmt.Sprintf(colorField("        Digest")+":  %s (%s)\n", colorHash(hex.EncodeToString(asset.Digest.GetValue())), strings.TrimPrefix(asset.Digest.GetDigestAlg().String(), "DIGEST_ALG_")))
		out.WriteString(fmt.Sprintf(colorField("        URL")+":     %s\n", asset.GetUrl()))
	}
	out.WriteString(colorField("Tickets\n"))
	hash := sha256.New()
	hash.Write(r.Ticket.ApTicket.Bytes)
	out.WriteString(fmt.Sprintf(colorField("    OS")+": %s\n", colorHash(hex.EncodeToString(hash.Sum(nil)))))
	out.WriteString(fmt.Sprintf("        [%s: %s]\n", colorCreateTime("created"), r.ReleaseCreationTime().Format("2006-01-02 15:04:05")))
	out.WriteString(fmt.Sprintf("        [%s: %s]\n", colorExpireTime("expires"), time.UnixMilli(int64(r.ExpiryMS)).Format("2006-01-02 15:04:05")))
	out.WriteString(colorField("    Cryptexes\n"))
	for i, ct := range r.Ticket.CryptexTickets {
		hash.Reset()
		hash.Write(ct.Bytes)
		out.WriteString(fmt.Sprintf("        %d) %s\n", i, colorHash(hex.EncodeToString(hash.Sum(nil)))))
	}
	out.WriteString(colorField("DarwinInit:\n"))
	if r.GetDarwinInit() == nil {
		out.WriteString("    (none — release uses ReleaseMetadata fallback fields)\n")
		return out.String()
	}
	dat, _ := json.MarshalIndent(r.DarwinInit.AsMap(), "", "  ")
	if color.NoColor {
		out.WriteString(string(dat))
	} else {
		var buf strings.Builder
		if err := quick.Highlight(&buf, string(dat)+"\n", "json", "terminal256", "nord"); err != nil {
			out.WriteString(string(dat))
		} else {
			out.WriteString(buf.String())
		}
	}
	return out.String()
}

func (r *PCCRelease) Download(output, proxy string, insecure bool) error {
	// Preflight: HEAD every asset before downloading anything. The newest
	// releases sometimes 403 on the OS IPSW before CDN sync — fail now
	// rather than after pulling several GB of other assets.
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}
	for _, asset := range r.GetAssets() {
		req, err := http.NewRequest(http.MethodHead, asset.GetUrl(), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("preflight %s: %w", asset.GetType(), err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("asset %s unavailable (HTTP %d) — newest releases may not be on the CDN yet; try an older release or retry later",
				strings.TrimPrefix(asset.GetType().String(), "ASSET_TYPE_"), resp.StatusCode)
		}
	}

	if err := os.MkdirAll(output, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %v", err)
	}
	releaseID := r.ReleaseID()
	releaseName := releaseID
	if len(releaseName) > 7 {
		releaseName = releaseName[:7]
	}
	if releaseName == "" {
		releaseName = fmt.Sprintf("%d", r.Index)
	}
	pinst := pccInstance{
		HttpService: struct {
			Enabled bool `plist:"enabled,omitempty"`
		}{Enabled: true},
		Name:      releaseName,
		ReleaseID: releaseID,
	}
	for _, asset := range r.GetAssets() {
		assetURL := asset.GetUrl()
		filePath := filepath.Join(output, strings.TrimPrefix(asset.GetType().String(), "ASSET_TYPE_")+assetExt(asset))
		pinst.ReleaseAssets = append(pinst.ReleaseAssets, struct {
			File    string `plist:"file,omitempty"`
			Type    string `plist:"type,omitempty"`
			Variant string `plist:"variant,omitempty"`
		}{
			File:    filepath.Base(filePath),
			Type:    asset.GetType().String(),
			Variant: asset.GetVariant(),
		})
		log.WithFields(log.Fields{
			"digest":  hex.EncodeToString(asset.Digest.GetValue()),
			"variant": asset.GetVariant(),
		}).Info("Downloading Asset")
		downloader := NewDownload(proxy, insecure, false, false, false, false, false)
		downloader.URL = assetURL
		downloader.DestName = filePath
		if err := downloader.Do(); err != nil {
			return err
		}
	}
	if di := r.GetDarwinInit(); di != nil {
		dat, err := json.MarshalIndent(di.AsMap(), "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal darwin-init.json: %v", err)
		}
		if err := os.WriteFile(filepath.Join(output, "darwin-init.json"), dat, 0644); err != nil {
			return fmt.Errorf("failed to write darwin-init.json: %v", err)
		}
	} else {
		log.Warnf("PCC release %d has no darwinInit metadata; skipping darwin-init.json", r.Index)
	}
	pdat, err := plist.MarshalIndent(pinst, plist.XMLFormat, "\t")
	if err != nil {
		return fmt.Errorf("failed to marshal instance.plist: %v", err)
	}
	if err := os.WriteFile(filepath.Join(output, "instance.plist"), pdat, 0644); err != nil {
		return fmt.Errorf("failed to write instance.plist: %v", err)
	}
	return nil
}

func assetTypeExt(typ pcc.ReleaseMetadata_AssetType) string {
	switch typ {
	case pcc.ReleaseMetadata_ASSET_TYPE_OS:
		return ".ipsw"
	case pcc.ReleaseMetadata_ASSET_TYPE_PCS, pcc.ReleaseMetadata_ASSET_TYPE_MODEL, pcc.ReleaseMetadata_ASSET_TYPE_DEBUG_SHELL:
		return ".aar"
	case pcc.ReleaseMetadata_ASSET_TYPE_HOST_TOOLS:
		return ".dmg"
	default: // ReleaseMetadata_ASSET_TYPE_UNSPECIFIED
		return ""
	}
}

func assetExt(asset *pcc.ReleaseMetadata_Asset) string {
	if asset == nil {
		return ""
	}
	switch asset.GetFileType() {
	case pcc.ReleaseMetadata_FILE_TYPE_IPSW:
		return ".ipsw"
	case pcc.ReleaseMetadata_FILE_TYPE_DISKIMAGE:
		return ".dmg"
	case pcc.ReleaseMetadata_FILE_TYPE_APPLEARCHIVE:
		return ".aar"
	}
	return assetTypeExt(asset.GetType())
}

func parseAtLeaf(r *bytes.Reader) (*ATLeaf, error) {
	var leaf ATLeaf

	if err := binary.Read(r, binary.BigEndian, &leaf.Version); err != nil {
		return nil, fmt.Errorf("cannot read version: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.Type); err != nil {
		return nil, fmt.Errorf("cannot read type: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.DescriptionSize); err != nil {
		return nil, fmt.Errorf("cannot read description size: %v", err)
	}
	leaf.Description = make([]byte, leaf.DescriptionSize)
	if err := binary.Read(r, binary.BigEndian, &leaf.Description); err != nil {
		return nil, fmt.Errorf("cannot read description: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.HashSize); err != nil {
		return nil, fmt.Errorf("cannot read hash size: %v", err)
	}
	leaf.Hash = make([]byte, leaf.HashSize)
	if err := binary.Read(r, binary.BigEndian, &leaf.Hash); err != nil {
		return nil, fmt.Errorf("cannot read hash: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.ExpiryMS); err != nil {
		return nil, fmt.Errorf("cannot read expiry: %v", err)
	}
	if err := binary.Read(r, binary.BigEndian, &leaf.ExtensionsSize); err != nil {
		return nil, fmt.Errorf("cannot read extensions size: %v", err)
	}
	extensionData := make([]byte, leaf.ExtensionsSize)
	if err := binary.Read(r, binary.BigEndian, &extensionData); err != nil {
		return nil, fmt.Errorf("cannot read extensions: %v", err)
	}
	er := bytes.NewReader(extensionData)
	for er.Len() > 0 {
		var ext TransparencyExtension
		if err := binary.Read(er, binary.BigEndian, &ext.Type); err != nil {
			return nil, fmt.Errorf("cannot read extension type: %v", err)
		}
		if err := binary.Read(er, binary.BigEndian, &ext.Size); err != nil {
			return nil, fmt.Errorf("cannot read extension size: %v", err)
		}
		ext.Data = make([]byte, ext.Size)
		if err := binary.Read(er, binary.BigEndian, &ext.Data); err != nil {
			return nil, fmt.Errorf("cannot read extension data: %v", err)
		}
		leaf.Extensions = append(leaf.Extensions, ext)
	}
	return &leaf, nil
}

func hintedATLeafType(mutation []byte) (pcc.ATLogDataType, bool) {
	if len(mutation) < 2 {
		return 0, false
	}
	return pcc.ATLogDataType(mutation[1]), true
}

func parsePCCReleaseLeaf(leaf *pcc.LogLeavesResponse_Leaf) (*PCCRelease, error) {
	if leaf.GetNodeType() != pcc.NodeType_ATL_NODE {
		return nil, nil
	}

	var clnode pcc.ChangeLogNodeV2
	if err := proto.Unmarshal(leaf.GetNodeBytes(), &clnode); err != nil {
		if typ, ok := hintedATLeafType(clnode.GetMutation()); ok && typ != pcc.ATLogDataType_RELEASE {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot unmarshal ChangeLogNodeV2: %v", err)
	}

	atLeaf, err := parseAtLeaf(bytes.NewReader(clnode.GetMutation()))
	if err != nil {
		if typ, ok := hintedATLeafType(clnode.GetMutation()); ok && typ != pcc.ATLogDataType_RELEASE {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot parse ATLeaf: %v", err)
	}
	if pcc.ATLogDataType(atLeaf.Type) != pcc.ATLogDataType_RELEASE {
		return nil, nil
	}

	if len(leaf.GetMetadata()) == 0 {
		return nil, fmt.Errorf("release leaf missing metadata")
	}
	if len(leaf.GetRawData()) == 0 {
		return nil, fmt.Errorf("release leaf missing raw ticket data")
	}

	release := &PCCRelease{
		Index:  leaf.GetIndex(),
		ATLeaf: atLeaf,
	}

	if err := proto.Unmarshal(leaf.GetMetadata(), &release.ReleaseMetadata); err != nil {
		return nil, fmt.Errorf("cannot unmarshal ReleaseMetadata: %v", err)
	}
	if _, err := asn1.Unmarshal(leaf.GetRawData(), &release.Ticket); err != nil {
		return nil, fmt.Errorf("failed to ASN.1 parse Img4: %v", err)
	}

	return release, nil
}

func collectPCCReleases(startIdx, endIdx, batchSize uint64, progress func(done, total uint64), fetchLeaves func(startIndex, endIndex uint64) ([]*pcc.LogLeavesResponse_Leaf, error)) ([]*PCCRelease, error) {
	if startIdx >= endIdx {
		return nil, nil
	}
	if batchSize == 0 {
		batchSize = pccLogLeavesBatchSize
	}

	var releases []*PCCRelease
	total := endIdx - startIdx
	var done uint64

	for s := startIdx; s < endIdx; s += batchSize {
		e := min(s+batchSize, endIdx)
		leaves, err := fetchLeaves(s, e)
		if err != nil {
			return nil, err
		}
		for _, leaf := range leaves {
			release, err := parsePCCReleaseLeaf(leaf)
			if err != nil {
				return nil, fmt.Errorf("failed to parse pcc log leaf %d: %w", leaf.GetIndex(), err)
			}
			if release != nil {
				releases = append(releases, release)
			}
		}
		done += e - s
		if progress != nil {
			progress(done, total)
		}
	}

	return releases, nil
}

func UniquePCCReleases(releases []*PCCRelease) []*PCCRelease {
	if len(releases) < 2 {
		return releases
	}

	unique := make([]*PCCRelease, 0, len(releases))
	seen := make(map[string]int, len(releases))

	for _, release := range releases {
		hash := release.ReleaseID()
		if hash == "" {
			unique = append(unique, release)
			continue
		}
		if idx, ok := seen[hash]; ok {
			if release.Index > unique[idx].Index {
				unique[idx] = release
			}
			continue
		}
		seen[hash] = len(unique)
		unique = append(unique, release)
	}

	return unique
}

// GetPCCReleases returns parsed releases from Apple's PCC AT transparency
// log, using the on-disk pcc_log.json cache for incremental fetch. Steady
// state is two POSTs (ListTrees + LogHead) instead of the full ~15-batch
// replay of the entire log every invocation.
func GetPCCReleases(proxy string, insecure bool, progress func(done, total uint64)) ([]*PCCRelease, error) {
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
	}

	bag, err := fetchPCCBag(client)
	if err != nil {
		return nil, err
	}
	requestUUID := uuid.NewString()
	tree, err := fetchPCCTree(client, bag.AtResearcherListTrees, requestUUID)
	if err != nil {
		return nil, err
	}
	logSize, err := fetchPCCLogSize(client, bag.AtResearcherLogHead, tree, requestUUID)
	if err != nil {
		return nil, err
	}

	cache := loadPCCLogCache()
	if cache == nil || cache.TreeID != tree.GetTreeId() {
		cache = &pccLogCache{TreeID: tree.GetTreeId()}
	}

	prior := make([]*PCCRelease, 0, len(cache.Releases))
	for _, cr := range cache.Releases {
		r, err := cr.toRelease()
		if err != nil {
			// Treat a corrupt cache as a cold start rather than failing.
			log.Warnf("pcc log cache: %v — refetching from scratch", err)
			cache = &pccLogCache{TreeID: tree.GetTreeId()}
			prior = nil
			break
		}
		prior = append(prior, r)
	}

	if cache.HeadIndex >= logSize && len(prior) > 0 {
		return prior, nil
	}

	fetchLeaves := func(startIndex, endIndex uint64) ([]*pcc.LogLeavesResponse_Leaf, error) {
		return fetchPCCLogLeaves(client, bag.AtResearcherLogLeaves, tree, requestUUID, startIndex, endIndex)
	}
	newReleases, err := collectPCCReleases(cache.HeadIndex, logSize, pccLogLeavesBatchSize, progress, fetchLeaves)
	if err != nil {
		return nil, err
	}

	for _, r := range newReleases {
		cr, err := releaseToCached(r)
		if err != nil {
			return nil, fmt.Errorf("cache release %d: %w", r.Index, err)
		}
		cache.Releases = append(cache.Releases, cr)
	}
	cache.HeadIndex = logSize
	savePCCLogCache(cache)

	return append(prior, newReleases...), nil
}

func fetchPCCBag(client *http.Client) (*BagResponse, error) {
	req, err := http.NewRequest("GET", bagURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create http GET request: %v", err)
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to GET pcc atresearch bag: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pcc atresearch bag GET returned status: %s", res.Status)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var bag BagResponse
	if _, err := plist.Unmarshal(body, &bag); err != nil {
		return nil, fmt.Errorf("cannot unmarshal plist: %v", err)
	}
	return &bag, nil
}

func fetchPCCTree(client *http.Client, url, requestUUID string) (*pcc.ListTreesResponse_Tree, error) {
	data, err := proto.Marshal(&pcc.ListTreesRequest{
		Version:     pcc.ProtocolVersion_V3,
		RequestUuid: requestUUID,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot marshal ListTreesRequest: %v", err)
	}
	body, err := pccProtoPOST(client, url, requestUUID, data)
	if err != nil {
		return nil, err
	}
	var lt pcc.ListTreesResponse
	if err := proto.Unmarshal(body, &lt); err != nil {
		return nil, fmt.Errorf("cannot unmarshal ListTreesResponse: %v", err)
	}
	if lt.GetStatus() != pcc.Status_OK {
		return nil, fmt.Errorf("pcc list trees returned status: %s", lt.GetStatus())
	}
	for _, t := range lt.GetTrees() {
		if t.GetLogType() == pcc.LogType_AT_LOG &&
			t.GetApplication() == pcc.Application_PRIVATE_CLOUD_COMPUTE {
			return t, nil
		}
	}
	return nil, fmt.Errorf("failed to find private cloud compute tree in list trees response")
}

func fetchPCCLogSize(client *http.Client, url string, tree *pcc.ListTreesResponse_Tree, requestUUID string) (uint64, error) {
	data, err := proto.Marshal(&pcc.LogHeadRequest{
		Version:     pcc.ProtocolVersion_V3,
		TreeId:      tree.GetTreeId(),
		Revision:    -1,
		RequestUuid: requestUUID,
	})
	if err != nil {
		return 0, fmt.Errorf("cannot marshal LogHeadRequest: %v", err)
	}
	body, err := pccProtoPOST(client, url, requestUUID, data)
	if err != nil {
		return 0, err
	}
	var lh pcc.LogHeadResponse
	if err := proto.Unmarshal(body, &lh); err != nil {
		return 0, fmt.Errorf("cannot unmarshal LogHeadResponse: %v", err)
	}
	if lh.GetStatus() != pcc.Status_OK {
		return 0, fmt.Errorf("pcc log head returned status: %s", lh.GetStatus())
	}
	if lh.GetLogHead() == nil {
		return 0, fmt.Errorf("pcc log head response missing log head object")
	}
	var logHead pcc.LogHead
	if err := proto.Unmarshal(lh.GetLogHead().GetObject(), &logHead); err != nil {
		return 0, fmt.Errorf("cannot unmarshal LogHead: %v", err)
	}
	return logHead.GetLogSize(), nil
}

func fetchPCCLogLeaves(client *http.Client, url string, tree *pcc.ListTreesResponse_Tree, requestUUID string, startIndex, endIndex uint64) ([]*pcc.LogLeavesResponse_Leaf, error) {
	data, err := proto.Marshal(&pcc.LogLeavesRequest{
		Version:         pcc.ProtocolVersion_V3,
		TreeId:          tree.GetTreeId(),
		StartIndex:      startIndex,
		EndIndex:        endIndex,
		RequestUuid:     requestUUID,
		StartMergeGroup: 0,
		EndMergeGroup:   uint32(tree.GetMergeGroups()),
	})
	if err != nil {
		return nil, fmt.Errorf("cannot marshal LogLeavesRequest: %v", err)
	}
	body, err := pccProtoPOST(client, url, requestUUID, data)
	if err != nil {
		return nil, fmt.Errorf("pcc log leaves [%d,%d): %w", startIndex, endIndex, err)
	}
	var lls pcc.LogLeavesResponse
	if err := proto.Unmarshal(body, &lls); err != nil {
		return nil, fmt.Errorf("cannot unmarshal LogLeavesResponse: %v", err)
	}
	if lls.GetStatus() != pcc.Status_OK {
		return nil, fmt.Errorf("pcc log leaves [%d,%d) returned status: %s", startIndex, endIndex, lls.GetStatus())
	}
	return lls.GetLeaves(), nil
}

func pccProtoPOST(client *http.Client, url, requestUUID string, body []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("cannot create http POST request: %v", err)
	}
	req.Header.Set("X-Apple-Request-UUID", requestUUID)
	req.Header.Set("Content-Type", "application/protobuf")
	req.Header.Add("User-Agent", utils.RandomAgent())
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status: %s", res.Status)
	}
	return io.ReadAll(res.Body)
}
