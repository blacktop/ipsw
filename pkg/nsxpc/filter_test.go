package nsxpc

import "testing"

func TestNormalizeGlobPatternsSplitsCommaSeparatedValues(t *testing.T) {
	got := normalizeGlobPatterns([]string{"MediaPlayback*, MediaParser*", "AudioMX*", "MediaPlayback*"})
	want := []string{"AudioMX*", "MediaParser*", "MediaPlayback*"}
	if len(got) != len(want) {
		t.Fatalf("patterns=%#v, want %#v", got, want)
	}
	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("patterns=%#v, want %#v", got, want)
		}
	}
}

func TestImageNameMatchesDylibGlob(t *testing.T) {
	if !imageNameMatchesAny("/System/Library/PrivateFrameworks/MediaPlaybackCore.framework/MediaPlaybackCore", []string{"MediaPlayback*"}) {
		t.Fatal("framework image did not match basename glob")
	}
	if !imageNameMatchesAny("/usr/lib/libAudioMX.dylib", []string{"libAudioMX*"}) {
		t.Fatal("dylib image did not match basename glob")
	}
	if imageNameMatchesAny("/System/Library/PrivateFrameworks/WebKit.framework/WebKit", []string{"MediaPlayback*"}) {
		t.Fatal("unrelated image matched dylib glob")
	}
}

func TestMatchAnyGlobSupportsServiceGlob(t *testing.T) {
	if !matchAnyGlob("com.apple.coremedia.mediaparserd", []string{"COM.APPLE.COREMEDIA.*"}) {
		t.Fatal("service glob did not match service name")
	}
	if !matchAnyGlob("com.apple.coremedia.mediaparserd", []string{"COREMEDIA"}) {
		t.Fatal("service substring did not match case-insensitively")
	}
	if matchAnyGlob("com.apple.webkit.GPU", []string{"com.apple.coremedia.*"}) {
		t.Fatal("unrelated service matched service glob")
	}
}

func TestImageNameScopeAllowsServiceOnlySelection(t *testing.T) {
	scanner := &scanner{servicePatterns: []string{"com.apple.coremedia.*"}}
	if !scanner.imageNameMatchesScope("/System/Library/Frameworks/CoreMedia.framework/CoreMedia") {
		t.Fatal("service-only scans should not reject images by name before cstring matching")
	}
}

func TestScannerImageInScopeUsesPreselectedImages(t *testing.T) {
	scanner := &scanner{
		dylibPatterns: []string{"MediaPlayback*"},
		scopedImages: map[string]struct{}{
			"/System/Library/PrivateFrameworks/MediaPlaybackCore.framework/MediaPlaybackCore": {},
		},
	}
	if !scanner.imageInScope("/System/Library/PrivateFrameworks/MediaPlaybackCore.framework/MediaPlaybackCore") {
		t.Fatal("expected preselected image to be in scope")
	}
	if scanner.imageInScope("/System/Library/PrivateFrameworks/WebKit.framework/WebKit") {
		t.Fatal("unexpected unselected image in scope")
	}
}
