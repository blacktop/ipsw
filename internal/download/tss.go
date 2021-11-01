package download

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"

	"github.com/blacktop/go-plist"
)

// NOTES:
// - https://github.com/Neal/savethemblobs
// - https://github.com/tihmstar/tsschecker
// - https://www.theiphonewiki.com/wiki/SHSH
// - https://www.theiphonewiki.com/wiki/SHSH_Protocol
// - https://tsssaver.1conan.com/v2/
// - https://api.ineal.me/tss/docs

const tssURL = "https://gs.apple.com/TSS/controller?action=2"

type manifest struct {
	Digest  []byte `plist:"Digest,omitempty"`
	EPRO    bool   `plist:"EPRO,omitempty"` // = true
	ESEC    bool   `plist:"ESEC,omitempty"` // = true
	Trusted bool   `plist:"Trusted,omitempty"`
}

type manifests map[string]manifest

// TSSRequest is the tss apticket request plist object
type TSSRequest struct {
	ApImg4Ticket              bool     `plist:"@ApImg4Ticket,omitempty"`
	BBTicket                  bool     `plist:"@BBTicket,omitempty"`
	HostPlatformInfo          string   `plist:"@HostPlatformInfo,omitempty"`
	Locality                  string   `plist:"@Locality,omitempty"`
	VersionInfo               string   `plist:"@VersionInfo,omitempty"` // = libauthinstall-850.0.1.0.1 ( /usr/lib/libauthinstall.dylib)
	ApBoardID                 int      `plist:"ApBoardID,omitempty"`
	ApChipID                  int      `plist:"ApChipID,omitempty"`
	ApECID                    int      `plist:"ApECID,omitempty"`
	ApNonce                   [32]byte `plist:"ApNonce,omitempty"`
	ApProductionMode          bool     `plist:"ApProductionMode,omitempty"`
	ApSecurityDomain          int      `plist:"ApSecurityDomain,omitempty"` // = 1
	ApSecurityMode            bool     `plist:"ApSecurityMode,omitempty"`
	PearlCertificationRootPub [97]byte `plist:"PearlCertificationRootPub,omitempty"`
	UniqueBuildID             [20]byte `plist:"UniqueBuildID,omitempty"`
	SepNonce                  [20]byte `plist:"SepNonce,omitempty"`
	// all the various manifest parts
	manifests
}

// GetTSS returns shsh blob
func GetTSS(proxy string) error {

	var sepNonce [20]byte
	var apNonce [32]byte
	var uniqueBID [20]byte
	var pearlCertRootPub [97]byte

	tssReq := TSSRequest{
		ApImg4Ticket:              true,
		BBTicket:                  true,
		HostPlatformInfo:          "mac",
		Locality:                  "en_US",
		VersionInfo:               "libauthinstall-850.0.1.0.1",
		ApBoardID:                 0x0C,             // device.ApBoardID
		ApChipID:                  0x8110,           // device.ApChipID
		ApECID:                    7143879912186918, // device.ApECID
		ApNonce:                   apNonce,          // device.CryptexNonce
		ApProductionMode:          true,             // device.EPRO
		ApSecurityDomain:          1,                // device.ApSecurityDomain
		ApSecurityMode:            true,             // device.ESEC
		SepNonce:                  sepNonce,
		UniqueBuildID:             uniqueBID,
		PearlCertificationRootPub: pearlCertRootPub,
	}

	tdata, err := plist.Marshal(tssReq, plist.AutomaticFormat)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", tssURL, bytes.NewBuffer(tdata))
	if err != nil {
		return fmt.Errorf("failed to create https request: %v", err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-type", "text/xml; charset=\"utf-8\"")
	req.Header.Add("User-Agent", "InetURL/1.0")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy:           GetProxy(proxy),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to connect to URL: got status %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	re := regexp.MustCompile(`^STATUS=(?P<status>\d+)&MESSAGE=(?P<message>[A-Za-z0-9_\-%].*)(?:&REQUEST_STRING=(?P<request>.*))?$`)
	if re.MatchString(string(body)) {
		matches := re.FindStringSubmatch(string(body))
		status := matches[re.SubexpIndex("status")]
		message := matches[re.SubexpIndex("message")]
		request := matches[re.SubexpIndex("request")]
		fmt.Printf("status: %s, message: %s, request: %s\n", status, message, request)
	}

	// TODO: parse response body as plist and get `ApImg4Ticket`

	return nil
}
