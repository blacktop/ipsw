//go:build !ios

package download

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
)

type MacAppStore struct {
	*AppStore
}

// NewMacAppStore returns a MacAppStore instance
func NewMacAppStore(config *AppStoreConfig) *MacAppStore {
	return &MacAppStore{
		AppStore: NewAppStore(config),
	}
}

func (as *MacAppStore) Search(searchTerm string, limit int) (Apps, error) {
	req, err := http.NewRequest("GET", appStoreSearchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}

	q := url.Values{}
	q.Add("term", searchTerm)
	q.Add("country", as.config.StoreFront)
	q.Add("limit", strconv.Itoa(limit))
	q.Add("entity", "macSoftware")
	q.Add("media", "software")

	req.URL.RawQuery = q.Encode()
	req.Header.Set("Content-Type", "application/json")

	response, err := as.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	log.Debugf("GET appstore Search (%d):\n%s\n", response.StatusCode, string(body))

	if 200 > response.StatusCode || 300 <= response.StatusCode {
		return nil, fmt.Errorf("failed to search appstore: response received %s", response.Status)
	}

	// os.WriteFile("search.json", body, 0644)

	var result QueryResults
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to deserialize response body JSON: %v", err)
	}

	if len(result.Results) == 0 {
		return nil, fmt.Errorf("no results found for search term %s", searchTerm)
	}

	return result.Results, nil
}

func (as *MacAppStore) Lookup(bundleID string) (*App, error) {
	req, err := http.NewRequest("GET", appStoreLookupURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}

	q := url.Values{}
	q.Add("bundleId", bundleID)
	q.Add("country", as.config.StoreFront)
	q.Add("limit", "1")
	q.Add("entity", "macSoftware")
	q.Add("media", "software")

	req.URL.RawQuery = q.Encode()
	req.Header.Set("Content-Type", "application/json")

	response, err := as.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	log.Debugf("GET appstore Lookup (%d):\n%s\n", response.StatusCode, string(body))

	if 200 > response.StatusCode || 300 <= response.StatusCode {
		return nil, fmt.Errorf("failed to lookup bundleID in appstore: response received %s", response.Status)
	}

	// os.WriteFile("lookup.json", body, 0644)

	var result QueryResults
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to deserialize response body JSON: %v", err)
	}

	if len(result.Results) == 0 {
		return nil, fmt.Errorf("no results found for bundleID %s", bundleID)
	}

	return &result.Results[0], nil
}

func (as *MacAppStore) Purchase(bundleID string) error {

	app, err := as.Lookup(bundleID)
	if err != nil {
		return fmt.Errorf("failed to lookup app for bundle ID %s: %v", bundleID, err)
	}

	if app.Price > 0 {
		return fmt.Errorf("paid apps cannot be purchased")
	}

	buf := new(bytes.Buffer)

	mac, err := getMacAddress()
	if err != nil {
		return fmt.Errorf("failed to get mac address: %v", err)
	}

	guid := strings.ReplaceAll(strings.ToUpper(mac), ":", "")

	plist.NewEncoderForFormat(buf, plist.XMLFormat).Encode(&purchaseRequest{
		AppExtVrsID:       "0",
		Price:             "0",
		PricingParameters: "SWUPD",
		ProductType:       "C",
		SalableAdamID:     app.ID,
	})

	req, err := http.NewRequest("POST", appStorePurchaseURL, buf)
	if err != nil {
		return fmt.Errorf("failed to create http POST request: %v", err)
	}

	q := url.Values{}
	q.Add("guid", guid)
	req.URL.RawQuery = q.Encode()

	req.Header.Add("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-apple-plist")
	req.Header.Set("iCloud-DSID", as.dsid)
	req.Header.Set("X-Dsid", as.dsid)
	req.Header.Set("X-Apple-Store-Front", as.config.StoreFront)
	req.Header.Set("X-Token", as.token)

	response, err := as.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("POST Purchase: (%d):\n%s\n", response.StatusCode, string(body))

	// os.WriteFile("purchase.xml", body, 0644)

	var purc purchaseResponse
	if err := plist.NewDecoder(bytes.NewReader(body)).Decode(&purc); err != nil {
		return fmt.Errorf("failed to decode purchase response: %v", err)
	}

	if purc.FailureType == FailureTypePasswordTokenExpired {
		key, err := as.Vault.Get(VaultName)
		if err != nil {
			return fmt.Errorf("failed to get dev auth from vault: %v", err)
		}

		var auth AppleAccountAuth
		if err := json.Unmarshal(key.Data, &auth); err != nil {
			return fmt.Errorf("failed to unmarshal dev auth: %v", err)
		}
		if err := as.signIn(auth.Credentials.Username, auth.Credentials.Password, "", 0); err != nil {
			return fmt.Errorf("failed to re-signin: %v", err)
		}
		auth = AppleAccountAuth{}

		return as.Purchase(bundleID)
	}

	if response.StatusCode == 500 {
		return fmt.Errorf("account already has a license for this app")
	}

	if purc.JingleDocType != "purchaseSuccess" || purc.Status != 0 {
		return fmt.Errorf("failed to purchase app %s", app.Name)
	}

	return nil
}

func (as *MacAppStore) Download(bundleID, output string) error {

	app, err := as.Lookup(bundleID)
	if err != nil {
		return fmt.Errorf("failed to lookup app for bundle ID %s: %v", bundleID, err)
	}

	buf := new(bytes.Buffer)

	mac, err := getMacAddress()
	if err != nil {
		return fmt.Errorf("failed to get mac address: %v", err)
	}

	guid := strings.ReplaceAll(strings.ToUpper(mac), ":", "")

	plist.NewEncoderForFormat(buf, plist.XMLFormat).Encode(&downloadRequest{
		CreditDisplay: "",
		GuID:          guid,
		SalableAdamID: app.ID,
	})

	req, err := http.NewRequest("POST", appStoreDownloadURL, buf)
	if err != nil {
		return fmt.Errorf("failed to create http POST request: %v", err)
	}

	q := url.Values{}
	q.Add("guid", guid)
	req.URL.RawQuery = q.Encode()

	req.Header.Add("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-apple-plist")
	req.Header.Set("iCloud-DSID", as.dsid)
	req.Header.Set("X-Dsid", as.dsid)

	response, err := as.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("POST Download: (%d):\n%s\n", response.StatusCode, string(body))

	// os.WriteFile("download.xml", body, 0644)

	var dl downloadResponse
	if err := plist.NewDecoder(bytes.NewReader(body)).Decode(&dl); err != nil {
		return fmt.Errorf("failed to decode download response: %v", err)
	}

	if dl.FailureType == FailureTypeLicenseNotFound {
		if err := as.Purchase(bundleID); err != nil {
			return fmt.Errorf("failed to purchase app: %v", err)
		}
		return as.Download(bundleID, output)
	}

	if len(dl.Apps) == 0 {
		return fmt.Errorf("no items found in download response")
	}

	src, err := as.download(dl.Apps[0].URL)
	if err != nil {
		return fmt.Errorf("failed to download app: %v", err)
	}
	defer os.Remove(src)

	dst := filepath.Join(output, fmt.Sprintf("%s_%d.v%s.pkg", app.BundleID, app.ID, app.Version))

	if err := os.Rename(src, dst); err != nil {
		return err
	}

	log.Infof("Created %s", dst)

	dpInfo := dl.Apps[0].Sinfs[0].DPInfo

	dpInfoPath := filepath.Join(output, fmt.Sprintf("%s_%d.v%s.dpInfo", app.BundleID, app.ID, app.Version))
	if err := os.WriteFile(dpInfoPath, dpInfo, 0o644); err != nil {
		return err
	}

	log.Infof("Created %s", dpInfoPath)

	hwInfo, err := hex.DecodeString(guid)
	if err != nil {
		return err
	}

	hwInfoPath := filepath.Join(output, fmt.Sprintf("%s_%d.v%s.hwInfo", app.BundleID, app.ID, app.Version))
	if err := os.WriteFile(hwInfoPath, hwInfo, 0o644); err != nil {
		return err
	}

	log.Infof("Created %s", hwInfoPath)

	return nil
}

func (as *MacAppStore) download(url string) (string, error) {

	// proxy, insecure are null because we override the client below
	downloader := NewDownload(
		as.config.Proxy,
		as.config.Insecure,
		as.config.SkipAll,
		as.config.ResumeAll,
		as.config.RestartAll,
		false,
		as.config.Verbose,
	)
	// use authenticated client
	downloader.client = as.Client

	dest, err := os.CreateTemp("", "appstore.pkg")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}

	log.WithFields(log.Fields{
		"file": dest.Name(),
	}).Info("Downloading")

	// download file
	downloader.URL = url
	downloader.DestName = dest.Name()

	err = downloader.Do()
	if err != nil {
		return "", fmt.Errorf("failed to download file: %v", err)
	}

	return dest.Name(), nil
}
