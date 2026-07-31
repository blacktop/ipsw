package download

import (
	"bytes"
	"slices"
	"testing"
	"time"

	pcccmd "github.com/blacktop/ipsw/internal/commands/pcc"
	internaldownload "github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/download/pcc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestFilterVPhoneReleasesRequiresConfirmedFirmwarePresence(t *testing.T) {
	t.Parallel()

	releases := []*internaldownload.PCCRelease{
		{Index: 10, VPhone: &internaldownload.VPhoneFirmware{Present: true, Count: 5}},
		{Index: 11, VPhone: &internaldownload.VPhoneFirmware{Present: false}},
		{Index: 12},
		{Index: 13, VPhone: &internaldownload.VPhoneFirmware{Present: true, Count: 5}},
	}

	filtered := filterVPhoneReleases(releases)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 confirmed vphone releases, got %d", len(filtered))
	}
	if filtered[0].Index != 10 || filtered[1].Index != 13 {
		t.Fatalf("unexpected filtered release indexes: %d, %d", filtered[0].Index, filtered[1].Index)
	}
}

func TestSortAndLimitPCCReleasesSelectsNewestRelease(t *testing.T) {
	t.Parallel()

	releases := []*internaldownload.PCCRelease{
		{
			Index: 1,
			ReleaseMetadata: pcc.ReleaseMetadata{
				ReleaseCreation: timestamppb.New(time.Date(2025, time.November, 4, 0, 0, 0, 0, time.UTC)),
			},
		},
		{Index: 2},
		{
			Index: 3,
			ReleaseMetadata: pcc.ReleaseMetadata{
				ReleaseCreation: timestamppb.New(time.Date(2026, time.January, 7, 0, 0, 0, 0, time.UTC)),
			},
		},
	}

	latest := sortAndLimitPCCReleases(slices.Clone(releases), true)
	if len(latest) != 1 || latest[0].Index != 3 {
		t.Fatalf("expected newest release 3, got %+v", latest)
	}

	all := sortAndLimitPCCReleases(slices.Clone(releases), false)
	if len(all) != 3 || all[0].Index != 3 || all[1].Index != 1 || all[2].Index != 2 {
		t.Fatalf("unexpected release ordering: %+v", all)
	}

	if latest := sortAndLimitPCCReleases(nil, true); len(latest) != 0 {
		t.Fatalf("expected no latest release for empty input, got %+v", latest)
	}
}

func TestPCCURLSummaryIncludesReleaseIdentityAndLabeledAssets(t *testing.T) {
	t.Parallel()

	darwinInit, err := structpb.NewStruct(map[string]any{
		"preferences": []any{
			map[string]any{
				"application_id": "com.apple.cloudos.cloudOSInfo",
				"key":            "cloudOSBuildVersion",
				"value":          "5C235",
			},
			map[string]any{
				"application_id": "com.apple.cloudos.cloudOSInfo",
				"key":            "cloudOSBuildTrain",
				"value":          "LuckCLining",
			},
			map[string]any{
				"application_id": "com.apple.cloudos.cloudOSInfo",
				"key":            "cloudOSApplicationName",
				"value":          "TIE",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create synthetic DarwinInit: %v", err)
	}

	release := &internaldownload.PCCRelease{
		Index:   29605,
		Version: &internaldownload.PCCVersion{Version: "26.1", Build: "23B83"},
		ReleaseMetadata: pcc.ReleaseMetadata{
			ReleaseCreation: timestamppb.New(time.Date(2025, time.November, 4, 0, 26, 50, 0, time.UTC)),
			DarwinInit:      darwinInit,
			Assets: []*pcc.ReleaseMetadata_Asset{
				{Type: pcc.ReleaseMetadata_ASSET_TYPE_OS, Url: "https://example.test/os"},
				{Type: pcc.ReleaseMetadata_ASSET_TYPE_PCS, Url: "https://example.test/pcs"},
				{Type: pcc.ReleaseMetadata_ASSET_TYPE_MODEL},
			},
		},
	}

	const want = `29605) 26.1  5C235 / 23B83 (LuckCLining)  TIE  2025-11-04
  OS           https://example.test/os
  PCS          https://example.test/pcs`
	if got := pcccmd.ReleaseURLSummary(release); got != want {
		t.Fatalf("unexpected PCC URL summary:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	var out bytes.Buffer
	if err := writePCCURLSummaries(&out, []*internaldownload.PCCRelease{release, release}); err != nil {
		t.Fatalf("writePCCURLSummaries returned error: %v", err)
	}
	if got := bytes.Count(out.Bytes(), []byte("\n\n")); got != 1 {
		t.Fatalf("expected one blank line between summaries, got %d", got)
	}
}

func TestPCCURLSummaryMarksUnresolvedOSVersion(t *testing.T) {
	t.Parallel()

	release := &internaldownload.PCCRelease{
		Index: 27,
		ReleaseMetadata: pcc.ReleaseMetadata{
			BuildVersion: "3B5602c.2",
			Application:  &pcc.ReleaseMetadata_Application{Name: "TIE Proxy"},
		},
	}

	if got, want := pcccmd.ReleaseURLSummary(release), "00027) ?  3B5602c.2  TIE Proxy  ????-??-??"; got != want {
		t.Fatalf("unexpected unresolved-version summary: got %q want %q", got, want)
	}
}

func TestPCCURLSummaryMarksMissingReleaseIdentity(t *testing.T) {
	t.Parallel()

	release := &internaldownload.PCCRelease{Index: 3}

	if got, want := pcccmd.ReleaseURLSummary(release), "00003) ?  ?  ????-??-??"; got != want {
		t.Fatalf("unexpected missing-identity summary: got %q want %q", got, want)
	}
}
