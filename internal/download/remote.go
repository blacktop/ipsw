package download

import (
	"archive/zip"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ranger"
)

// ErrDevPortalAuthRequired is returned when a request is redirected to the
// Apple ID sign-in page: the URL is served by the Apple Developer Portal and
// cannot be fetched without a signed-in developer account.
var ErrDevPortalAuthRequired = errors.New(
	"requires a signed-in Apple Developer account (redirected to the Apple ID sign-in page)")

const appleIDSignInHost = "idmsa.apple.com"

// RemoteConfig is the remote reader config
type RemoteConfig struct {
	Proxy    string
	Insecure bool
	// Client overrides Proxy/Insecure when set and is safe to share across
	// readers for connection reuse.
	Client *http.Client
	// BlockSize controls the ranger HTTP range request block size. Values are
	// clamped to [DefaultRemoteZipBlockSize, LargeRemoteZipBlockSize]; if unset,
	// ranger's default is used.
	BlockSize int
}

const (
	// DefaultRemoteZipBlockSize preserves ranger's default for metadata and tiny
	// member reads.
	DefaultRemoteZipBlockSize = ranger.DefaultBlockSize
	// LargeRemoteZipBlockSize is tuned for multi-GB firmware members.
	LargeRemoteZipBlockSize = 8 * 1024 * 1024

	mediumRemoteZipBlockSize = 4 * 1024 * 1024
	smallRemoteZipBlockSize  = 1 * 1024 * 1024
)

// NormalizeRemoteZipBlockSize returns a bounded block size safe for ranger.
func NormalizeRemoteZipBlockSize(blockSize int) int {
	switch {
	case blockSize <= 0:
		return DefaultRemoteZipBlockSize
	case blockSize < DefaultRemoteZipBlockSize:
		return DefaultRemoteZipBlockSize
	case blockSize > LargeRemoteZipBlockSize:
		return LargeRemoteZipBlockSize
	default:
		return blockSize
	}
}

// NewRemoteHTTPClient returns an HTTP client configured for remote ZIP range
// requests.
func NewRemoteHTTPClient(proxy string, insecure bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
		},
		CheckRedirect: rejectAppleIDSignInRedirect,
	}
}

// rejectAppleIDSignInRedirect keeps net/http's default redirect limit but fails
// fast when an anonymous request is bounced to the Apple ID sign-in page, which
// would otherwise be followed and served as an HTML login form.
func rejectAppleIDSignInRedirect(req *http.Request, via []*http.Request) error {
	if req.URL.Host == appleIDSignInHost {
		return ErrDevPortalAuthRequired
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// RemoteZipBlockSizeForMemberSize picks a range-request block size for the
// compressed bytes expected to be read from a remote ZIP member.
func RemoteZipBlockSizeForMemberSize(size uint64) int {
	switch {
	case size <= 1*1024*1024:
		return DefaultRemoteZipBlockSize
	case size <= 8*1024*1024:
		return smallRemoteZipBlockSize
	case size <= 16*1024*1024:
		return mediumRemoteZipBlockSize
	default:
		return LargeRemoteZipBlockSize
	}
}

// RemoteZipBlockSizeForFiles picks a block size based on the largest compressed
// ZIP member in files.
func RemoteZipBlockSizeForFiles(files []*zip.File) int {
	var maxSize uint64
	for _, file := range files {
		if file != nil && file.CompressedSize64 > maxSize {
			maxSize = file.CompressedSize64
		}
	}
	return RemoteZipBlockSizeForMemberSize(maxSize)
}

// NewRemoteZipReader returns a new remote zip file reader
func NewRemoteZipReader(zipURL string, config *RemoteConfig) (*zip.Reader, error) {
	if config == nil {
		config = &RemoteConfig{}
	}

	url, err := url.Parse(zipURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	client := config.Client
	if client == nil {
		client = NewRemoteHTTPClient(config.Proxy, config.Insecure)
	}

	reader := &ranger.Reader{
		Fetcher: &ranger.HTTPRanger{
			URL:       url,
			UserAgent: utils.RandomAgent(),
			Client:    client,
		},
		BlockSize: NormalizeRemoteZipBlockSize(config.BlockSize),
	}

	length, err := reader.Length()
	if err != nil {
		if errors.Is(err, ErrDevPortalAuthRequired) {
			return nil, ErrDevPortalAuthRequired
		}
		return nil, fmt.Errorf("failed to get reader length: %w", err)
	}

	zr, err := zip.NewReader(reader, length)
	if err != nil {
		return nil, fmt.Errorf("failed to create zip reader: %w", err)
	}

	return zr, nil
}
