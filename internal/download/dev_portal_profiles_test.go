//go:build !ios

package download

import (
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
)

func TestParseDevLoggingProfilesCurrentMarkup(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(`
<main id="main">
  <ul class="profile-list">
    <li class="profile" data-platform-name="iOS/iPadOS">
      <div class="profile-content">
        <div class="profile-name"><span data-profile-detail="name">Accessory Setup Kit</span></div>
        <div class="profile-actions">
          <a href="https://developer.apple.com/services-account/download?path=/iOS/Accessory.mobileconfig">Profile</a>
          <a href="https://developer.apple.com/instructions.pdf">Instructions</a>
        </div>
      </div>
    </li>
    <li class="profile">
      <div class="profile-content">
        <div class="profile-name"><span data-profile-detail="name">Timing Snoop</span><span class="lighter"> for macOS</span></div>
        <div class="profile-actions">
          <a href="/services-account/download?path=/OS_X/TimingSnoop.zip">Profile</a>
        </div>
      </div>
    </li>
  </ul>
</main>`))
	if err != nil {
		t.Fatalf("failed to parse test HTML: %v", err)
	}

	profiles := parseDevLoggingProfiles(doc)
	want := map[string]string{
		"Accessory Setup Kit (iOS/iPadOS)": "https://developer.apple.com/services-account/download?path=/iOS/Accessory.mobileconfig",
		"Timing Snoop (macOS)":             "https://developer.apple.com/services-account/download?path=/OS_X/TimingSnoop.zip",
	}
	if len(profiles) != len(want) {
		t.Fatalf("parsed %d profiles, want %d: %#v", len(profiles), len(want), profiles)
	}
	for name, url := range want {
		if profiles[name] != url {
			t.Errorf("profile %q URL = %q, want %q", name, profiles[name], url)
		}
	}
}

func TestParseDevLoggingProfilesLegacyMarkup(t *testing.T) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(`
<main id="main">
  <section>
    <li class="profile"><section><section class="column">
      <span data-profile-detail>Bluetooth</span><span class="platform">tvOS</span>
      <ul><li><a href="https://example.com/bluetooth.mobileconfig">Download</a></li></ul>
    </section></section></li>
  </section>
</main>`))
	if err != nil {
		t.Fatalf("failed to parse test HTML: %v", err)
	}

	profiles := parseDevLoggingProfiles(doc)
	if got := profiles["Bluetooth (tvOS)"]; got != "https://example.com/bluetooth.mobileconfig" {
		t.Fatalf("legacy profile URL = %q", got)
	}
}

func TestDevProfileOutputName(t *testing.T) {
	const name = `Accessory Setup Kit (iOS/iPadOS)\Beta`
	if got, want := devProfileOutputName(name), "Accessory_Setup_Kit_(iOS_iPadOS)_Beta"; got != want {
		t.Fatalf("devProfileOutputName(%q) = %q, want %q", name, got, want)
	}
}
