// Package info provides a route for getting info about an IPSW or OTA file
package info

import (
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/download"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/gin-gonic/gin"
)

// validatePublicURL rejects URLs that resolve to loopback, private, link-local,
// or unspecified addresses. Pre-flight check only — does not prevent DNS
// rebinding (would need a custom net.Dialer.Control hook for that).
func validatePublicURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme %q not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("missing host")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("host %q resolved to no addresses", host)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("host %q resolves to non-public address %s", host, ip)
		}
	}
	return nil
}

// swagger:response
type infoResponse struct {
	Path string     `json:"path"`
	Info *info.Info `json:"info"`
}

func getInfo(c *gin.Context) {
	path := c.Query("path")

	i, err := info.Parse(path)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, infoResponse{Path: path, Info: i})
}

// swagger:response
type infoRemoteResponse struct {
	URL  string     `json:"path"`
	Info *info.Info `json:"info"`
}

func getRemoteInfo(c *gin.Context) {
	remoteURL := c.Query("url")

	if err := validatePublicURL(remoteURL); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	// proxy and insecure query params removed: attacker-controlled HTTP
	// transport knobs are an SSRF amplifier and have no legitimate per-request use
	zr, err := download.NewRemoteZipReader(remoteURL, &download.RemoteConfig{})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	i, err := info.ParseZipFiles(zr.File)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, infoRemoteResponse{URL: remoteURL, Info: i})
}
