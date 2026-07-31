package cmd

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/internal/download/pcc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestPCCVPhoneNotificationUsesCompactSummaryWithDateLast(t *testing.T) {
	t.Parallel()

	release := notificationTestPCCRelease(42, "os-digest")

	const want = `New PCC vphone600 firmware

00042) 26.1  5C235 / 23B83  TIE  2025-11-04
  OS           https://example.test/pcc/os-digest`
	if got := pccVPhoneNotification([]*download.PCCRelease{release}); got != want {
		t.Fatalf("unexpected PCC notification:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestPCCVPhoneDiscordNotificationsDoNotBatchReleases(t *testing.T) {
	t.Parallel()

	first := notificationTestPCCRelease(42, "first")
	second := notificationTestPCCRelease(43, "second")

	got := pccVPhoneDiscordNotifications([]*download.PCCRelease{first, second})
	if len(got) != 2 {
		t.Fatalf("expected one Discord message per release, got %d", len(got))
	}
	if !strings.Contains(got[0], "/first") || strings.Contains(got[0], "/second") {
		t.Fatalf("first Discord message contains unexpected releases:\n%s", got[0])
	}
	if !strings.Contains(got[1], "/second") || strings.Contains(got[1], "/first") {
		t.Fatalf("second Discord message contains unexpected releases:\n%s", got[1])
	}
}

func TestPCCWatchHTTPClientPropagatesPollCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	client := pccWatchHTTPClient(ctx, &http.Client{
		Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return nil, request.Context().Err()
		}),
	})
	request, err := http.NewRequest(http.MethodGet, "https://example.test", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	if _, err := client.Do(request); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled poll context, got %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func notificationTestPCCRelease(index uint64, digest string) *download.PCCRelease {
	return &download.PCCRelease{
		Index:   index,
		Version: &download.PCCVersion{Version: "26.1", Build: "23B83"},
		ReleaseMetadata: pcc.ReleaseMetadata{
			ReleaseCreation: timestamppb.New(time.Date(2025, time.November, 4, 3, 2, 1, 0, time.UTC)),
			BuildVersion:    "5C235",
			Application:     &pcc.ReleaseMetadata_Application{Name: "TIE"},
			Assets: []*pcc.ReleaseMetadata_Asset{{
				Type: pcc.ReleaseMetadata_ASSET_TYPE_OS,
				Url:  "https://example.test/pcc/" + digest,
			}},
		},
	}
}
