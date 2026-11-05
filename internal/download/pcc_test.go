package download

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/memory"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/download/pcc"
	"github.com/fatih/color"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCollectPCCReleasesSummarizesSkippedMetadata(t *testing.T) {
	previousHandler := log.Log.(*log.Logger).Handler
	previousLevel := log.Log.(*log.Logger).Level
	t.Cleanup(func() {
		log.SetHandler(previousHandler)
		log.SetLevel(previousLevel)
	})
	log.SetLevel(log.InfoLevel)
	for _, malformed := range []bool{false, true} {
		captured := memory.New()
		log.SetHandler(captured)
		var leaves []*pcc.LogLeavesResponse_Leaf
		for i := range uint64(100) {
			leaves = append(leaves, newTestLogLeaf(t, i, pcc.ATLogDataType_RELEASE, false, true))
		}
		if malformed {
			leaf := newTestLogLeaf(t, 100, pcc.ATLogDataType_RELEASE, true, true)
			leaf.Metadata = []byte{0xff}
			leaves = append(leaves, leaf)
		}
		leaves = append(leaves, newTestLogLeaf(t, 101, pcc.ATLogDataType_RELEASE, true, true))
		releases, err := collectPCCReleases(0, 1, 1, nil, func(_, _ uint64) ([]*pcc.LogLeavesResponse_Leaf, error) {
			return leaves, nil
		})
		if err != nil || len(releases) != 1 {
			t.Fatalf("releases=%d err=%v", len(releases), err)
		}
		if len(captured.Entries) != 1 {
			t.Fatalf("got %d normal log entries, want one summary", len(captured.Entries))
		}
		summary := captured.Entries[0]
		wantMalformed := uint64(0)
		wantLevel := log.InfoLevel
		if malformed {
			wantMalformed, wantLevel = 1, log.WarnLevel
		}
		if summary.Level != wantLevel || summary.Fields["missing_metadata"] != uint64(100) || summary.Fields["malformed_metadata"] != wantMalformed {
			t.Fatalf("unexpected summary: %+v", summary)
		}
	}
}

func TestCollectPCCReleasesPagesThroughLogLeaves(t *testing.T) {
	t.Parallel()

	releaseLeaf := newTestLogLeaf(t, 4, pcc.ATLogDataType_RELEASE, true, true)

	var gotRanges [][2]uint64
	releases, err := collectPCCReleases(0, 5, 2, nil, func(startIndex, endIndex uint64) ([]*pcc.LogLeavesResponse_Leaf, error) {
		gotRanges = append(gotRanges, [2]uint64{startIndex, endIndex})
		if startIndex == 4 {
			return []*pcc.LogLeavesResponse_Leaf{releaseLeaf}, nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatalf("collectPCCReleases returned error: %v", err)
	}

	wantRanges := [][2]uint64{{0, 2}, {2, 4}, {4, 5}}
	if !slices.Equal(gotRanges, wantRanges) {
		t.Fatalf("unexpected ranges: got %v want %v", gotRanges, wantRanges)
	}
	if len(releases) != 1 {
		t.Fatalf("expected 1 release, got %d", len(releases))
	}
	if releases[0].Index != 4 {
		t.Fatalf("unexpected release index: got %d want 4", releases[0].Index)
	}
}

func TestParsePCCReleaseLeafSkipsMetadataLessLeaf(t *testing.T) {
	t.Parallel()

	// A RELEASE leaf with no ReleaseMetadata has nothing to download (issue
	// #1249 hit one); skip it without failing the whole fetch. Presence of
	// ticket raw data doesn't matter — metadata is what makes a leaf usable.
	tests := []struct {
		name           string
		includeRawData bool
	}{
		{name: "no metadata, with ticket", includeRawData: true},
		{name: "no metadata, no ticket", includeRawData: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			release, _, err := parsePCCReleaseLeaf(newTestLogLeaf(t, 7, pcc.ATLogDataType_RELEASE, false, tt.includeRawData))
			if err != nil {
				t.Fatalf("parsePCCReleaseLeaf returned error: %v", err)
			}
			if release != nil {
				t.Fatalf("expected metadata-less release leaf to be skipped, got %+v", release)
			}
		})
	}
}

func TestParsePCCReleaseLeafKeepsReleaseWithUnparseableTicket(t *testing.T) {
	t.Parallel()

	// A metadata-bearing RELEASE leaf whose ticket is a format we don't model
	// (e.g. Apple's newer version-2 ticket) must be KEPT — its assets come from
	// ReleaseMetadata and are downloadable; only the ticket hashes are lost.
	v2Ticket := mustMarshalASN1(t, struct {
		Version int
		Variant asn1.RawValue
	}{
		Version: 2,
		Variant: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: []byte{0x02, 0x01, 0x00}},
	})
	leaf := newTestLogLeaf(t, 11, pcc.ATLogDataType_RELEASE, true, false)
	leaf.RawData = v2Ticket

	release, _, err := parsePCCReleaseLeaf(leaf)
	if err != nil {
		t.Fatalf("parsePCCReleaseLeaf returned error: %v", err)
	}
	if release == nil {
		t.Fatal("expected metadata-bearing release to be kept despite unparseable ticket")
	}
	if release.OSAssetURL() == "" {
		t.Fatal("expected kept release to expose its downloadable OS asset URL")
	}
	if !bytes.Equal([]byte(release.Ticket.Raw), v2Ticket) {
		t.Fatalf("expected raw ticket bytes to be preserved, got %x", release.Ticket.Raw)
	}
	if release.Ticket.Version != 2 {
		t.Fatalf("ticket version = %d, want 2", release.Ticket.Version)
	}
	release.References = []*pcc.ReleaseMetadata_Reference{{Name: "Synthetic reference", Url: "https://example.invalid/reference"}}
	text := release.String()
	emptyHash := sha256.Sum256(nil)
	if !strings.Contains(text, "release schema 2; ticket details unavailable") || strings.Contains(text, hex.EncodeToString(emptyHash[:])) {
		t.Fatalf("unparsed ticket rendered misleading details: %s", text)
	}
	if !strings.Contains(text, "Synthetic reference: https://example.invalid/reference") {
		t.Fatalf("missing release reference: %s", text)
	}

	// The kept release must survive a cache round-trip without poisoning the
	// cache (toRelease must not fail on the unparseable ticket).
	cached, err := releaseToCached(release)
	if err != nil {
		t.Fatalf("releaseToCached failed for release with unparseable ticket: %v", err)
	}
	reloaded, err := cached.toRelease()
	if err != nil {
		t.Fatalf("toRelease failed for cached release with unparseable ticket: %v", err)
	}
	if !bytes.Equal([]byte(reloaded.Ticket.Raw), v2Ticket) {
		t.Fatalf("expected raw ticket bytes preserved across cache round-trip, got %x", reloaded.Ticket.Raw)
	}
	if reloaded.Ticket.Version != 2 || len(reloaded.GetReferences()) != 1 {
		t.Fatal("cache round-trip lost ticket version or references")
	}
}

func TestPCCDownloadPreservesCollidingAssets(t *testing.T) {
	t.Setenv("CLOUDSDK_AUTH_ACCESS_TOKEN", "synthetic-token")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("GCS token reached a non-GCS asset")
		}
		w.Header().Set("ETag", `"synthetic"`)
		http.ServeContent(w, r, "asset", time.Time{}, strings.NewReader("payload:"+r.URL.Path))
	}))
	t.Cleanup(server.Close)
	release := &PCCRelease{Index: 1, Assets: []*pcc.ReleaseMetadata_Asset{
		{Type: pcc.ReleaseMetadata_ASSET_TYPE_UNSPECIFIED, FileType: pcc.ReleaseMetadata_FILE_TYPE_APPLEARCHIVE, Variant: "first", Url: server.URL + "/first"},
		{Type: pcc.ReleaseMetadata_ASSET_TYPE_UNSPECIFIED, FileType: pcc.ReleaseMetadata_FILE_TYPE_APPLEARCHIVE, Variant: "second", Url: server.URL + "/second"},
		{Type: pcc.ReleaseMetadata_ASSET_TYPE_OS, FileType: pcc.ReleaseMetadata_FILE_TYPE_TARGZ, Variant: "os", Url: server.URL + "/os"},
		{Type: 7, FileType: pcc.ReleaseMetadata_FILE_TYPE_TARGZ, Variant: "firmware-a", Url: server.URL + "/firmware-a"},
		{Type: 7, FileType: pcc.ReleaseMetadata_FILE_TYPE_TARGZ, Variant: "firmware-b", Url: server.URL + "/firmware-b"},
	}}
	for _, asset := range release.Assets[:2] {
		sum := sha256.Sum256([]byte("payload:/" + asset.Variant))
		asset.Digest = &pcc.ReleaseMetadata_Digest{DigestAlg: pcc.ReleaseMetadata_DIGEST_ALG_SHA256, Value: sum[:]}
	}
	output := t.TempDir()
	if err := release.DownloadContext(t.Context(), output, "", false, false, false); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "instance.plist"))
	if err != nil {
		t.Fatal(err)
	}
	var instance pccInstance
	if _, err := plist.Unmarshal(data, &instance); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"first": "UNSPECIFIED_1.aar", "second": "UNSPECIFIED_2.aar", "os": "OS.tar.gz",
		"firmware-a": "UNKNOWN_7_4.tar.gz", "firmware-b": "UNKNOWN_7_5.tar.gz",
	}
	if len(instance.ReleaseAssets) != len(want) {
		t.Fatalf("saved %d assets, want %d", len(instance.ReleaseAssets), len(want))
	}
	for _, asset := range instance.ReleaseAssets {
		if asset.File != want[asset.Variant] {
			t.Errorf("%s filename = %q, want %q", asset.Variant, asset.File, want[asset.Variant])
		}
		data, err := os.ReadFile(filepath.Join(output, asset.File))
		if err != nil || string(data) != "payload:/"+asset.Variant {
			t.Errorf("%s payload = %q, err = %v", asset.Variant, data, err)
		}
	}
}

type pccRoundTripFunc func(*http.Request) (*http.Response, error)

func (f pccRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestPCCDownloadAuthenticatesRedirectedGCSAsset(t *testing.T) {
	const origin = "https://origin.invalid/image"
	const redirect = "https://storage.googleapis.com/synthetic-bucket/redirect"
	const payload = "synthetic archived OS"
	for _, tc := range []struct {
		name, target string
		authorized   bool
	}{
		{"storage", "https://storage.googleapis.com/bucket/asset", true},
		{"bucket", "https://bucket.storage.googleapis.com/asset", true},
		{"downgrade", "http://storage.googleapis.com/bucket/asset", false},
		{"other port", "https://storage.googleapis.com:8443/asset", false},
		{"lookalike", "https://storage.googleapis.com.example.invalid/asset", false},
		{"other google API", "https://example.googleapis.com/asset", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var heads, ranges atomic.Int32
			transport := &pccGCSAuthTransport{token: "synthetic-token", base: pccRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				wantAuth := ""
				if req.URL.String() == redirect || (req.URL.String() == tc.target && tc.authorized) {
					wantAuth = "Bearer synthetic-token"
				}
				if got := req.Header.Get("Authorization"); got != wantAuth {
					t.Errorf("authorization at %s = %q, want %q", req.URL, got, wantAuth)
				}
				next := ""
				switch req.URL.String() {
				case origin:
					next = redirect
				case redirect:
					next = tc.target
				}
				if next != "" {
					return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {next}}, Body: http.NoBody, Request: req}, nil
				}
				if req.Method == http.MethodHead {
					heads.Add(1)
				} else if req.Method == http.MethodGet && req.Header.Get("Range") != "" {
					ranges.Add(1)
				}
				w := httptest.NewRecorder()
				w.Header().Set("ETag", `"synthetic-gcs"`)
				http.ServeContent(w, req, "image.tar.gz", time.Time{}, strings.NewReader(payload))
				resp := w.Result()
				resp.Request = req
				return resp, nil
			})}
			release := &PCCRelease{Index: 1, Assets: []*pcc.ReleaseMetadata_Asset{{Type: pcc.ReleaseMetadata_ASSET_TYPE_OS, FileType: pcc.ReleaseMetadata_FILE_TYPE_TARGZ, Url: origin}}}
			output := t.TempDir()
			downloader := NewDownloadWithProfile(AppleCDNProfile, "", false, false, false, false)
			t.Cleanup(downloader.Close)
			if err := release.downloadContext(t.Context(), output, transport, downloader); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(filepath.Join(output, "OS.tar.gz"))
			if err != nil || string(data) != payload || heads.Load() == 0 || ranges.Load() == 0 {
				t.Fatalf("download = %q, err = %v, HEADs = %d, ranges = %d", data, err, heads.Load(), ranges.Load())
			}
		})
	}
}

func TestPCCAssetTransportBoundsResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	base := newPCCAssetHTTPTransport("", false)
	if base.DialContext == nil || base.TLSHandshakeTimeout <= 0 || base.ResponseHeaderTimeout <= 0 {
		t.Fatal("authenticated download transport has unbounded connection or header I/O")
	}
	base.ResponseHeaderTimeout = 20 * time.Millisecond
	client := &http.Client{Transport: &pccGCSAuthTransport{base: base, token: "synthetic-token"}}
	t.Cleanup(client.CloseIdleConnections)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if resp != nil {
		resp.Body.Close()
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || ctx.Err() != nil {
		t.Fatalf("request error = %v, context error = %v; want response-header timeout", err, ctx.Err())
	}
}

func TestPCCLogLeavesRequestsReleaseFilter(t *testing.T) {
	leaf := newTestLogLeaf(t, 4, pcc.ATLogDataType_RELEASE, true, true)
	response := mustMarshalProto(t, &pcc.LogLeavesResponse{Status: pcc.Status_OK, Leaves: []*pcc.LogLeavesResponse_Leaf{leaf}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		var request pcc.LogLeavesRequest
		if err := proto.Unmarshal(data, &request); err != nil {
			t.Error(err)
		}
		field := request.ProtoReflect().Descriptor().Fields().ByNumber(50)
		if field == nil || request.ProtoReflect().Get(field).Enum() != 1 || request.GetStartIndex() != 4 || request.GetEndIndex() != 5 {
			t.Errorf("unexpected log-leaves request: %s", &request)
		}
		w.Write(response)
	}))
	t.Cleanup(server.Close)
	leaves, err := fetchPCCLogLeaves(t.Context(), server.Client(), server.URL, &pcc.ListTreesResponse_Tree{TreeId: 7, MergeGroups: 1}, "synthetic-request", 4, 5)
	if err != nil || len(leaves) != 1 || leaves[0].GetIndex() != 4 {
		t.Fatalf("leaves = %v, err = %v", leaves, err)
	}
}

func TestPCCArchiveAssetsSkipIPSWResolution(t *testing.T) {
	var asset pcc.ReleaseMetadata_Asset
	// The public wire schema assigns firmware=6 and tar.gz=4.
	if err := proto.Unmarshal([]byte{0x08, 0x06, 0x30, 0x04}, &asset); err != nil {
		t.Fatal(err)
	}
	if PCCAssetTypeLabel(asset.GetType()) != "FIRMWARE" || assetExt(&asset) != ".tar.gz" {
		t.Fatalf("unsupported firmware archive: %s", &asset)
	}
	for _, fileType := range []pcc.ReleaseMetadata_FileType{pcc.ReleaseMetadata_FILE_TYPE_UNSPECIFIED, pcc.ReleaseMetadata_FILE_TYPE_TARGZ} {
		release := &PCCRelease{Assets: []*pcc.ReleaseMetadata_Asset{{Type: pcc.ReleaseMetadata_ASSET_TYPE_OS, FileType: fileType, Url: "https://example.invalid/image.tar.gz"}}}
		if release.OSAssetIsIPSW() {
			t.Fatal("tar.gz OS asset was classified as IPSW")
		}
		ResolvePCCVersions([]*PCCRelease{release}, func(string) (PCCVersion, error) { t.Error("attempted ZIP version lookup"); return PCCVersion{}, nil })
		ResolveVPhoneFirmware([]*PCCRelease{release}, func(string) (VPhoneFirmware, error) {
			t.Error("attempted ZIP firmware lookup")
			return VPhoneFirmware{}, nil
		})
	}
}

func TestParseAtLeafParsesLengthPrefixedExtensions(t *testing.T) {
	t.Parallel()

	leaf, err := parseAtLeaf(bytes.NewReader(encodeTestATLeafWithExtensions(t, byte(pcc.ATLogDataType_RELEASE), bytes.Repeat([]byte{0xaa}, 32), []TransparencyExtension{
		{
			Type: 2,
			Data: []byte{0, 0, 0, 0, 0, 0, 0, 7},
		},
	})))
	if err != nil {
		t.Fatalf("parseAtLeaf returned error: %v", err)
	}

	if got := len(leaf.Extensions); got != 1 {
		t.Fatalf("expected 1 extension, got %d", got)
	}
	if leaf.Extensions[0].Type != 2 {
		t.Fatalf("unexpected extension type: got %d want 2", leaf.Extensions[0].Type)
	}
	if !bytes.Equal(leaf.Extensions[0].Data, []byte{0, 0, 0, 0, 0, 0, 0, 7}) {
		t.Fatalf("unexpected extension data: %x", leaf.Extensions[0].Data)
	}
}

func TestParsePCCReleaseLeafSkipsNonReleaseLeaf(t *testing.T) {
	t.Parallel()

	release, _, err := parsePCCReleaseLeaf(newTestLogLeaf(t, 3, pcc.ATLogDataType_TEST_MARKER, true, true))
	if err != nil {
		t.Fatalf("parsePCCReleaseLeaf returned error: %v", err)
	}
	if release != nil {
		t.Fatalf("expected non-release leaf to be skipped, got %+v", release)
	}
}

func TestParsePCCReleaseLeafSkipsMalformedNonReleaseLeaf(t *testing.T) {
	t.Parallel()

	leaf := newTestLogLeaf(t, 8, pcc.ATLogDataType_TEST_MARKER, false, false)
	leaf.NodeBytes = []byte{0x0a, 0x02, 0x01, byte(pcc.ATLogDataType_TEST_MARKER), 0xff}

	release, _, err := parsePCCReleaseLeaf(leaf)
	if err != nil {
		t.Fatalf("parsePCCReleaseLeaf returned error: %v", err)
	}
	if release != nil {
		t.Fatalf("expected malformed non-release leaf to be skipped, got %+v", release)
	}
}

func TestParsePCCReleaseLeafSkipsUndecodableLeaf(t *testing.T) {
	t.Parallel()

	leaf := newTestLogLeaf(t, 9, pcc.ATLogDataType_RELEASE, true, true)
	leaf.NodeBytes = mustMarshalProto(t, &pcc.ChangeLogNodeV2{Mutation: []byte{1}})

	release, _, err := parsePCCReleaseLeaf(leaf)
	if err == nil {
		t.Fatal("expected malformed leaf error")
	}
	if release != nil {
		t.Fatalf("expected malformed leaf to fail, got %+v", release)
	}
}

func TestUniquePCCReleasesKeepsLatestIndexPerHash(t *testing.T) {
	t.Parallel()

	releases := []*PCCRelease{
		{Index: 10, ReleaseDigest: []byte{0xaa}},
		{Index: 12, ReleaseDigest: []byte{0xbb}},
		{Index: 15, ReleaseDigest: []byte{0xaa}},
	}

	unique := UniquePCCReleases(releases)
	if got := len(unique); got != 2 {
		t.Fatalf("expected 2 unique releases, got %d", got)
	}

	found := map[string]uint64{}
	for _, release := range unique {
		found[release.ReleaseID()] = release.Index
	}
	if found["aa"] != 15 {
		t.Fatalf("expected latest index for hash aa to be 15, got %d", found["aa"])
	}
	if found["bb"] != 12 {
		t.Fatalf("expected latest index for hash bb to be 12, got %d", found["bb"])
	}
}

func TestPCCReleaseIDFallsBackToATLeafHash(t *testing.T) {
	t.Parallel()

	release := &PCCRelease{ATLeaf: &ATLeaf{Hash: []byte{0xde, 0xad}}}

	if got := release.ReleaseID(); got != "dead" {
		t.Fatalf("unexpected release ID: got %q want %q", got, "dead")
	}
}

func TestPCCReleaseCreationTimeHandlesMissingTimestamp(t *testing.T) {
	t.Parallel()

	release := &PCCRelease{}

	if got := release.ReleaseCreationTime(); !got.IsZero() {
		t.Fatalf("unexpected release creation time: got %s want zero", got)
	}
}

func TestCloudOSInfoUsesReleaseMetadataFallbackFields(t *testing.T) {
	t.Parallel()

	release := &PCCRelease{
		DarwinInit:   &structpb.Struct{},
		Application:  &pcc.ReleaseMetadata_Application{Name: "TIE Proxy"},
		BuildVersion: "5F123"}

	build, train, app := release.CloudOSInfo()
	if build != "5F123" {
		t.Fatalf("unexpected build: got %q want %q", build, "5F123")
	}
	if train != "" {
		t.Fatalf("unexpected train: got %q want empty", train)
	}
	if app != "TIE Proxy" {
		t.Fatalf("unexpected app: got %q want %q", app, "TIE Proxy")
	}
}

func TestCloudOSInfoPrefersDarwinInitOverReleaseMetadataFallbackFields(t *testing.T) {
	t.Parallel()

	darwinInit, err := structpb.NewStruct(map[string]any{
		"preferences": []any{
			map[string]any{
				"application_id": "com.apple.cloudos.cloudOSInfo",
				"key":            "cloudOSBuildVersion",
				"value":          "5E290",
			},
			map[string]any{
				"application_id": "com.apple.cloudos.cloudOSInfo",
				"key":            "cloudOSApplicationName",
				"value":          "TIE",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create DarwinInit struct: %v", err)
	}

	release := &PCCRelease{
		DarwinInit:   darwinInit,
		Application:  &pcc.ReleaseMetadata_Application{Name: "TIE Proxy"},
		BuildVersion: "5F123"}

	build, _, app := release.CloudOSInfo()
	if build != "5E290" {
		t.Fatalf("unexpected build: got %q want %q", build, "5E290")
	}
	if app != "TIE" {
		t.Fatalf("unexpected app: got %q want %q", app, "TIE")
	}
}

func TestPCCReleaseStringPrintsOSBuildNextToCloudOSBuild(t *testing.T) {
	oldNoColor := color.NoColor
	color.NoColor = true
	defer func() { color.NoColor = oldNoColor }()

	release, _, err := parsePCCReleaseLeaf(newTestLogLeaf(t, 4, pcc.ATLogDataType_RELEASE, true, true))
	if err != nil {
		t.Fatalf("parsePCCReleaseLeaf returned error: %v", err)
	}
	release.Version = &PCCVersion{Version: "26.4", Build: "23E5207q"}
	release.ReleaseMetadata.BuildVersion = "5F88.1"

	out := release.String()
	if !strings.Contains(out, "Build:  5F88.1 / 23E5207q [beta]") {
		t.Fatalf("expected OS build next to cloudOS build, got:\n%s", out)
	}
	if !strings.Contains(out, "Log Type: RELEASE") {
		t.Fatalf("expected PCC log type label, got:\n%s", out)
	}
}

func TestPCCVersionBuildLabelMarksBetaBuildSuffix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   PCCVersion
		want string
	}{
		{name: "beta", in: PCCVersion{Build: "23E5207q"}, want: "23E5207q [beta]"},
		{name: "release", in: PCCVersion{Build: "23E246"}, want: "23E246"},
		{name: "empty", in: PCCVersion{}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.in.BuildLabel(); got != tt.want {
				t.Fatalf("BuildLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolvePCCVersionsRefetchesCachedVersionWithoutBuild(t *testing.T) {
	t.Parallel()

	release := &PCCRelease{
		Version: &PCCVersion{Version: "26.4"},
		Assets: []*pcc.ReleaseMetadata_Asset{{
			Type: pcc.ReleaseMetadata_ASSET_TYPE_OS,
			Url:  "https://example.test/os-digest",
		}},
	}

	var calls int
	ResolvePCCVersions([]*PCCRelease{release}, func(url string) (PCCVersion, error) {
		calls++
		if url != "https://example.test/os-digest" {
			t.Fatalf("unexpected URL: got %q", url)
		}
		return PCCVersion{Version: "26.4", Build: "23E5207q"}, nil
	})

	if calls != 1 {
		t.Fatalf("expected one fetch for incomplete cached version, got %d", calls)
	}
	if release.Version == nil || release.Version.Build != "23E5207q" {
		t.Fatalf("expected OS build to be resolved, got %#v", release.Version)
	}
}

func TestAssetExtUsesReleaseMetadataFileType(t *testing.T) {
	t.Parallel()

	rawAsset := mustMarshalProto(t, &pcc.ReleaseMetadata_Asset{
		Type:     pcc.ReleaseMetadata_ASSET_TYPE_MODEL,
		FileType: pcc.ReleaseMetadata_FILE_TYPE_DISKIMAGE,
	})

	var asset pcc.ReleaseMetadata_Asset
	if err := proto.Unmarshal(rawAsset, &asset); err != nil {
		t.Fatalf("failed to unmarshal asset: %v", err)
	}

	if got := assetExt(&asset); got != ".dmg" {
		t.Fatalf("unexpected extension: got %q want %q", got, ".dmg")
	}
}

func TestAssetExtFallsBackToAssetType(t *testing.T) {
	t.Parallel()

	asset := &pcc.ReleaseMetadata_Asset{
		Type: pcc.ReleaseMetadata_ASSET_TYPE_MODEL,
	}

	if got := assetExt(asset); got != ".aar" {
		t.Fatalf("unexpected extension: got %q want %q", got, ".aar")
	}
}

func newTestLogLeaf(t *testing.T, index uint64, typ pcc.ATLogDataType, includeMetadata, includeRawData bool) *pcc.LogLeavesResponse_Leaf {
	t.Helper()

	changeLogNode := &pcc.ChangeLogNodeV2{
		Mutation: encodeTestATLeaf(t, byte(typ), bytes.Repeat([]byte{byte(index)}, 32)),
	}

	leaf := &pcc.LogLeavesResponse_Leaf{
		Index:     index,
		NodeType:  pcc.NodeType_ATL_NODE,
		NodeBytes: mustMarshalProto(t, changeLogNode),
	}

	if includeMetadata {
		leaf.Metadata = mustMarshalProto(t, &pcc.ReleaseMetadata{
			SchemaVersion:   pcc.ReleaseMetadata_SCHEMA_VERSION_V1,
			ReleaseCreation: timestamppb.New(time.Unix(1_700_000_000, 0)),
			ReleaseDigest:   bytes.Repeat([]byte{0xa5}, 32),
			Assets: []*pcc.ReleaseMetadata_Asset{{
				Type:    pcc.ReleaseMetadata_ASSET_TYPE_OS,
				Url:     "https://example.test/pcc.ipsw",
				Variant: "default",
				Digest: &pcc.ReleaseMetadata_Digest{
					DigestAlg: pcc.ReleaseMetadata_DIGEST_ALG_SHA256,
					Value:     bytes.Repeat([]byte{0x42}, 32),
				},
			}},
			DarwinInit: &structpb.Struct{},
		})
	}

	if includeRawData {
		leaf.RawData = mustMarshalASN1(t, struct {
			Version        int
			ApTicket       []byte
			CryptexTickets [][]byte `asn1:"set"`
		}{
			Version:        1,
			ApTicket:       []byte("apticket"),
			CryptexTickets: [][]byte{[]byte("cryptex")},
		})
	}

	return leaf
}

func encodeTestATLeaf(t *testing.T, typ byte, hash []byte) []byte {
	t.Helper()
	return encodeTestATLeafWithExtensions(t, typ, hash, nil)
}

func encodeTestATLeafWithExtensions(t *testing.T, typ byte, hash []byte, extensions []TransparencyExtension) []byte {
	t.Helper()

	if len(hash) > 255 {
		t.Fatalf("hash too long: %d", len(hash))
	}

	var buf bytes.Buffer
	buf.WriteByte(1)
	buf.WriteByte(typ)
	buf.WriteByte(0)
	buf.WriteByte(byte(len(hash)))
	buf.Write(hash)

	var expiry [8]byte
	binary.BigEndian.PutUint64(expiry[:], uint64(time.Now().Add(24*time.Hour).UnixMilli()))
	buf.Write(expiry[:])

	var extBuf bytes.Buffer
	for _, ext := range extensions {
		extSize := uint16(len(ext.Data))
		if err := binary.Write(&extBuf, binary.BigEndian, ext.Type); err != nil {
			t.Fatalf("failed to encode extension type: %v", err)
		}
		if err := binary.Write(&extBuf, binary.BigEndian, extSize); err != nil {
			t.Fatalf("failed to encode extension size: %v", err)
		}
		if _, err := extBuf.Write(ext.Data); err != nil {
			t.Fatalf("failed to encode extension data: %v", err)
		}
	}
	if extBuf.Len() > int(^uint16(0)) {
		t.Fatalf("extensions too long: %d", extBuf.Len())
	}
	if err := binary.Write(&buf, binary.BigEndian, uint16(extBuf.Len())); err != nil {
		t.Fatalf("failed to encode extensions length: %v", err)
	}
	if _, err := buf.Write(extBuf.Bytes()); err != nil {
		t.Fatalf("failed to append extensions: %v", err)
	}

	return buf.Bytes()
}

func mustMarshalProto(t *testing.T, msg proto.Message) []byte {
	t.Helper()

	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("failed to marshal proto: %v", err)
	}

	return data
}

func mustMarshalASN1(t *testing.T, value any) []byte {
	t.Helper()

	data, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("failed to marshal ASN.1: %v", err)
	}

	return data
}
