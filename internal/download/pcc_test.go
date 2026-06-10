package download

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/ipsw/internal/download/pcc"
	"github.com/fatih/color"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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
			release, err := parsePCCReleaseLeaf(newTestLogLeaf(t, 7, pcc.ATLogDataType_RELEASE, false, tt.includeRawData))
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

	release, err := parsePCCReleaseLeaf(leaf)
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

	release, err := parsePCCReleaseLeaf(newTestLogLeaf(t, 3, pcc.ATLogDataType_TEST_MARKER, true, true))
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

	release, err := parsePCCReleaseLeaf(leaf)
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

	release, err := parsePCCReleaseLeaf(leaf)
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
		{Index: 10, ReleaseMetadata: pcc.ReleaseMetadata{ReleaseDigest: []byte{0xaa}}},
		{Index: 12, ReleaseMetadata: pcc.ReleaseMetadata{ReleaseDigest: []byte{0xbb}}},
		{Index: 15, ReleaseMetadata: pcc.ReleaseMetadata{ReleaseDigest: []byte{0xaa}}},
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

	release := &PCCRelease{ReleaseMetadata: pcc.ReleaseMetadata{
		DarwinInit:   &structpb.Struct{},
		Application:  &pcc.ReleaseMetadata_Application{Name: "TIE Proxy"},
		BuildVersion: "5F123",
	}}

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

	release := &PCCRelease{ReleaseMetadata: pcc.ReleaseMetadata{
		DarwinInit:   darwinInit,
		Application:  &pcc.ReleaseMetadata_Application{Name: "TIE Proxy"},
		BuildVersion: "5F123",
	}}

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

	release, err := parsePCCReleaseLeaf(newTestLogLeaf(t, 4, pcc.ATLogDataType_RELEASE, true, true))
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
		ReleaseMetadata: pcc.ReleaseMetadata{
			Assets: []*pcc.ReleaseMetadata_Asset{{
				Type: pcc.ReleaseMetadata_ASSET_TYPE_OS,
				Url:  "https://example.test/os-digest",
			}},
		},
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
