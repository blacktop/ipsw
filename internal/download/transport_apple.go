//go:build !ios

package download

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/ipsw/internal/download/rootcert"
)

var proxyEnvVars = [...]string{
	"HTTPS_PROXY",
	"https_proxy",
	"HTTP_PROXY",
	"http_proxy",
	"ALL_PROXY",
	"all_proxy",
}

func newAppleHTTPTransport(proxy string, insecure bool) *http.Transport {
	transport := &http.Transport{
		Proxy: GetProxy(proxy),
	}

	if insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		return transport
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		// If a proxy is in play, forcing Apple-root-only can break enterprise proxy trust chains.
		// In that case, prefer platform/default trust behavior and let callers opt into --insecure.
		if hasConfiguredProxy(proxy) {
			log.WithError(err).Warn("failed to load system cert pool with proxy configured; using platform/default TLS trust")
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
			return transport
		}

		log.WithError(err).Warn("failed to load system cert pool; using bundled Apple root CA only")
		certPool = x509.NewCertPool()
	} else if certPool == nil {
		certPool = x509.NewCertPool()
	}

	certPool.AddCert(rootcert.AppleRootCA)

	transport.TLSClientConfig = &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}

	return transport
}

func hasConfiguredProxy(proxy string) bool {
	if strings.TrimSpace(proxy) != "" {
		return true
	}

	for _, key := range proxyEnvVars {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return true
		}
	}

	return false
}
