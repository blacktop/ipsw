package download

import (
	"archive/zip"
	"crypto/tls"
	"net/http"
	"net/url"

	"github.com/blacktop/ranger"
	"github.com/pkg/errors"

	"github.com/blacktop/ipsw/internal/utils"
)

// RemoteConfig is the remote reader config
type RemoteConfig struct {
	Proxy    string
	Insecure bool
}

// NewRemoteZipReader returns a new remote zip file reader
func NewRemoteZipReader(zipURL string, config *RemoteConfig) (*zip.Reader, error) {

	url, err := url.Parse(zipURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse url")
	}

	reader, err := ranger.NewReader(&ranger.HTTPRanger{
		URL:       url,
		UserAgent: utils.RandomAgent(),
		Client: &http.Client{
			Transport: &http.Transport{
				Proxy:           GetProxy(config.Proxy),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
			},
		},
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ranger reader")
	}

	length, err := reader.Length()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get reader length")
	}

	zr, err := zip.NewReader(reader, length)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create zip reader")
	}

	return zr, nil
}
