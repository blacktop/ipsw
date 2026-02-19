//go:build !ios

package download

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/utils"

	"github.com/99designs/keyring"
	"github.com/AlecAivazis/survey/v2"
	"github.com/AlecAivazis/survey/v2/terminal"
	"github.com/apex/log"
	"github.com/pkg/errors"
)

// CREDIT - https://github.com/majd/ipatool

const (
	appStoreBuyHost      = "buy.itunes.apple.com"
	appStoreAuthPath     = "/WebObjects/MZFinance.woa/wa/authenticate"
	appStoreDownloadPath = "/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct"
	appStorePurchasePath = "/WebObjects/MZFinance.woa/wa/buyProduct"
	appStoreBagURL       = "https://init.itunes.apple.com/bag.xml"
	appStoreSearchURL    = "https://itunes.apple.com/search"
	appStoreLookupURL    = "https://itunes.apple.com/lookup"

	// AppStoreSearchLimit is the maximum number of results returned by the App Store search API
	AppStoreSearchLimit = 200

	ErrLoginRequires2fa               = "MZFinance.BadLogin.Configurator_message"
	FailureTypeInvalidCredentials     = "-5000"
	FailureTypeUnknownError           = "5002"
	FailureTypePasswordTokenExpired   = "2034"
	FailureTypeLicenseNotFound        = "9610"
	FailureTypeTemporarilyUnavailable = "2059"
	FailureTypeSignInToTheItunesStore = "2042"
)

var (
	documentXMLPattern       = regexp.MustCompile(`(?is)<Document\b[^>]*>(.*)</Document>`)
	plistXMLPattern          = regexp.MustCompile(`(?is)<plist\b[^>]*>.*?</plist>`)
	dictXMLPattern           = regexp.MustCompile(`(?is)<dict\b[^>]*>.*</dict>`)
	fullRecoveryRetryBudget  = 1
	transientUnknownBackoffs = []time.Duration{
		1 * time.Second,
		3 * time.Second,
		10 * time.Second,
	}
)

type AppStoreConfig struct {
	// download config
	Proxy    string
	Insecure bool
	// behavior config
	SkipAll      bool
	ResumeAll    bool
	RestartAll   bool
	RemoveCommas bool
	PreferSMS    bool
	PageSize     int
	Verbose      bool
	// extra config
	StoreFront    string
	VaultPassword string
	ConfigDir     string
	KeybagPlist   string
}

type AppStore struct {
	Client *http.Client

	Vault keyring.Keyring

	authEndpoint string
	pod          string
	storeFront   string
	username     string
	dsid         string
	token        string

	config *AppStoreConfig
}

type QueryResults struct {
	ResultCount int  `json:"resultCount"`
	Results     Apps `json:"results"`
}

type App struct {
	ID             int     `json:"trackId,omitempty"`
	BundleID       string  `json:"bundleId,omitempty"`
	Name           string  `json:"trackName,omitempty"`
	SellerURL      string  `json:"sellerUrl,omitempty"`
	SellerName     string  `json:"sellerName,omitempty"`
	Version        string  `json:"version,omitempty"`
	ReleaseDate    string  `json:"currentVersionReleaseDate,omitempty"`
	Price          float64 `json:"price,omitempty"`
	FormattedPrice string  `json:"formattedPrice,omitempty"`
	Size           string  `json:"fileSizeBytes,omitempty"`
	Rating         float64 `json:"averageUserRating,omitempty"`
	RatingCount    int     `json:"userRatingCount,omitempty"`
	ArtworkUrl     string  `json:"artworkUrl512,omitempty"`
}

type Apps []App

type loginRequest struct {
	AppleID       string `json:"appleId,omitempty" plist:"appleId,omitempty"`
	Attempt       string `json:"attempt,omitempty" plist:"attempt,omitempty"`
	CreateSession string `json:"createSession,omitempty" plist:"createSession,omitempty"`
	GuID          string `json:"guid,omitempty" plist:"guid,omitempty"`
	Password      string `json:"password,omitempty" plist:"password,omitempty"`
	Rmp           string `json:"rmp,omitempty" plist:"rmp,omitempty"`
	Why           string `json:"why,omitempty" plist:"why,omitempty"`
}

type loginResponse struct {
	Pings           []any  `json:"pings,omitempty" plist:"pings,omitempty"`
	FailureType     string `json:"failureType,omitempty" plist:"failureType,omitempty"`
	CustomerMessage string `json:"customerMessage,omitempty" plist:"customerMessage,omitempty"`
	AccountInfo     struct {
		AppleID string `json:"appleId,omitempty" plist:"appleId,omitempty"`
		Address struct {
			FirstName string `json:"firstName,omitempty" plist:"firstName,omitempty"`
			LastName  string `json:"lastName,omitempty" plist:"lastName,omitempty"`
		} `json:"address" plist:"address,omitempty"`
	} `json:"accountInfo" plist:"accountInfo,omitempty"`
	AltDSID             string `json:"altDsid,omitempty" plist:"altDsid,omitempty"`
	PasswordToken       string `json:"passwordToken,omitempty" plist:"passwordToken,omitempty"`
	ClearToken          string `json:"clearToken,omitempty" plist:"clearToken,omitempty"`
	MAllowed            bool   `json:"m-allowed,omitempty" plist:"m-allowed,omitempty"`
	IsCloudEnabled      string `json:"is-cloud-enabled,omitempty" plist:"is-cloud-enabled,omitempty"`
	CancelPurchaseBatch bool   `json:"cancel-purchase-batch,omitempty" plist:"cancel-purchase-batch,omitempty"`
	DsPersonID          string `json:"dsPersonId,omitempty" plist:"dsPersonId,omitempty"`
	CreditDisplay       string `json:"creditDisplay,omitempty" plist:"creditDisplay,omitempty"`
	CreditBalance       string `json:"creditBalance,omitempty" plist:"creditBalance,omitempty"`
	FreeSongBalance     string `json:"freeSongBalance,omitempty" plist:"freeSongBalance,omitempty"`
	IsManagedStudent    bool   `json:"isManagedStudent,omitempty" plist:"isManagedStudent,omitempty"`
	SubscriptionStatus  struct {
		Terms []struct {
			Type          string `json:"type,omitempty" plist:"type,omitempty"`
			LatestTerms   int    `json:"latestTerms,omitempty" plist:"latestTerms,omitempty"`
			AgreedToTerms int    `json:"agreedToTerms,omitempty" plist:"agreedToTerms,omitempty"`
			Source        string `json:"source,omitempty" plist:"source,omitempty"`
		} `json:"terms,omitempty" plist:"terms,omitempty"`
		Account struct {
			IsMinor         bool `json:"isMinor,omitempty" plist:"isMinor,omitempty"`
			SuspectUnderage bool `json:"suspectUnderage,omitempty" plist:"suspectUnderage,omitempty"`
		} `json:"account" plist:"account,omitempty"`
		Family struct {
			HasFamily bool `json:"hasFamily,omitempty" plist:"hasFamily,omitempty"`
		} `json:"family" plist:"family,omitempty"`
	} `json:"subscriptionStatus" plist:"subscriptionStatus,omitempty"`
	AccountFlags      map[string]any `json:"accountFlags,omitempty" plist:"accountFlags,omitempty"`
	Status            int            `json:"status,omitempty" plist:"status,omitempty"`
	DownloadQueueInfo struct {
		DsID                  int  `json:"dsid,omitempty" plist:"dsid,omitempty"`
		IsAutoDownloadMachine bool `json:"is-auto-download-machine,omitempty" plist:"is-auto-download-machine,omitempty"`
	} `json:"download-queue-info" plist:"download-queue-info,omitempty"`
	PrivacyAcknowledgement map[string]int `json:"privacyAcknowledgement,omitempty" plist:"privacyAcknowledgement,omitempty"`
}

type bagResponse struct {
	URLBag struct {
		AuthenticateAccount string `plist:"authenticateAccount,omitempty"`
	} `plist:"urlBag,omitempty"`
}

type purchaseRequest struct {
	AppExtVrsID               string `plist:"appExtVrsId,omitempty"`
	HasAskedToFulfillPreorder string `plist:"hasAskedToFulfillPreorder,omitempty"`
	BuyWithoutAuthorization   string `plist:"buyWithoutAuthorization,omitempty"`
	HasDoneAgeCheck           string `plist:"hasDoneAgeCheck,omitempty"`
	GuID                      string `plist:"guid,omitempty"`
	NeedDiv                   string `plist:"needDiv,omitempty"`
	OrigPage                  string `plist:"origPage,omitempty"`
	OrigPageLocation          string `plist:"origPageLocation,omitempty"`
	Price                     string `plist:"price,omitempty"`
	PricingParameters         string `plist:"pricingParameters,omitempty"`
	ProductType               string `plist:"productType,omitempty"`
	SalableAdamID             int    `plist:"salableAdamId,omitempty"`
}

type purchaseResponse struct {
	FailureType     string `plist:"failureType,omitempty"`
	CustomerMessage string `plist:"customerMessage,omitempty"`
	JingleDocType   string `plist:"jingleDocType,omitempty"`
	Status          int    `plist:"status,omitempty"`
}

type downloadRequest struct {
	CreditDisplay string `plist:"creditDisplay,omitempty"`
	GUID          string `plist:"guid,omitempty"`
	KBSync        string `plist:"kbsync,omitempty"`
	SalableAdamId int    `plist:"salableAdamId,omitempty"`
	SerialNumber  string `plist:"serialNumber,omitempty"`
}

// type downloadRequest struct {
// 	GUID              string `plist:"guid,omitempty"`
// 	Price             string `plist:"price,omitempty"`
// 	PricingParameters string `plist:"pricingParameters,omitempty"`
// 	ProductType       string `plist:"productType,omitempty"`
// 	SalableAdamId     string `plist:"salableAdamId,omitempty"`
// }

type downloadResponse struct {
	FailureType     string              `plist:"failureType,omitempty"`
	CustomerMessage string              `plist:"customerMessage,omitempty"`
	JingleDocType   string              `plist:"jingleDocType,omitempty"`
	JingleAction    string              `plist:"jingleAction,omitempty"`
	Status          int                 `plist:"status,omitempty"`
	Authorized      bool                `plist:"authorized,omitempty"`
	Count           int                 `plist:"download-queue-item-count,omitempty"`
	Apps            []downloadAppResult `plist:"songList,omitempty"`
	Metrics         downloadMetrics     `plist:"metrics,omitempty"`
}

type downloadMetrics struct {
	ItemIDs           []int   `plist:"itemIds,omitempty"`
	Currency          string  `plist:"currency,omitempty"`
	ExchangeRateToUSD float64 `plist:"exchangeRateToUSD,omitempty"`
}

type downloadSinfResult struct {
	ID   int64  `plist:"id,omitempty"`
	Data []byte `plist:"sinf,omitempty"`
}

type downloadAppResult struct {
	ID               int                  `plist:"songId,omitempty"`
	URL              string               `plist:"URL,omitempty"`
	ArtworkURL       string               `plist:"artworkURL,omitempty"`
	HashMD5          string               `plist:"md5,omitempty"`
	UncompressedSize string               `plist:"uncompressedSize,omitempty"`
	Sinfs            []downloadSinfResult `plist:"sinfs,omitempty"`
	Metadata         map[string]any       `plist:"metadata,omitempty"`
}

type packageManifest struct {
	SinfPaths []string `plist:"SinfPaths,omitempty"`
}

type packageInfo struct {
	BundleExecutable string `plist:"CFBundleExecutable,omitempty"`
}

func getMacAddress() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %w", err)
	}
	for _, iface := range ifaces {
		addr := iface.HardwareAddr.String()
		if addr != "" {
			return addr, nil
		}
	}
	return "", fmt.Errorf("no network interfaces found")
}

func appStoreURL(host, path string) string {
	return "https://" + host + path
}

func appStoreHostForPod(pod string) string {
	pod = strings.TrimSpace(pod)
	if pod == "" {
		return appStoreBuyHost
	}
	return "p" + pod + "-" + appStoreBuyHost
}

func resolveRedirectEndpoint(base *url.URL, location string) (string, error) {
	parsedLocation, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return "", fmt.Errorf("failed to parse redirect location: %w", err)
	}

	if parsedLocation.IsAbs() {
		return parsedLocation.String(), nil
	}

	if base == nil {
		return "", fmt.Errorf("failed to resolve relative redirect location: missing base URL")
	}

	return base.ResolveReference(parsedLocation).String(), nil
}

func decodePlistResponse(body []byte, out any) error {
	return plist.NewDecoder(bytes.NewReader(normalizePlistBody(body))).Decode(out)
}

func normalizePlistBody(body []byte) []byte {
	normalized := bytes.TrimSpace(body)
	if len(normalized) == 0 {
		return normalized
	}

	if documentBody := extractDocumentBody(normalized); len(documentBody) > 0 {
		normalized = documentBody
	}

	if plistBody := extractPlistBody(normalized); len(plistBody) > 0 {
		normalized = plistBody
	}

	if dictBody := extractDictBody(normalized); len(dictBody) > 0 {
		return dictBody
	}

	if bytes.Contains(normalized, []byte("<key>")) {
		wrapped := make([]byte, 0, len(normalized)+len("<dict></dict>"))
		wrapped = append(wrapped, []byte("<dict>")...)
		wrapped = append(wrapped, normalized...)
		wrapped = append(wrapped, []byte("</dict>")...)
		return wrapped
	}

	return normalized
}

func extractDocumentBody(body []byte) []byte {
	match := documentXMLPattern.FindSubmatch(body)
	if len(match) < 2 {
		return nil
	}
	return bytes.TrimSpace(match[1])
}

func extractPlistBody(body []byte) []byte {
	match := plistXMLPattern.Find(body)
	if len(match) == 0 {
		return nil
	}
	return bytes.TrimSpace(match)
}

func extractDictBody(body []byte) []byte {
	match := dictXMLPattern.Find(body)
	if len(match) == 0 {
		return nil
	}
	return bytes.TrimSpace(match)
}

func (as *AppStore) getBagAuthEndpoint(guid string) (string, error) {
	req, err := http.NewRequest("GET", appStoreBagURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create bag request: %w", err)
	}

	query := req.URL.Query()
	query.Set("guid", guid)
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Accept", "application/xml")
	req.Header.Set("User-Agent", userAgent)

	res, err := as.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("bag request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bag request returned status: %s", res.Status)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read bag response: %w", err)
	}

	var bag bagResponse
	if err := decodePlistResponse(body, &bag); err != nil {
		return "", fmt.Errorf("failed to decode bag response: %w", err)
	}

	return strings.TrimSpace(bag.URLBag.AuthenticateAccount), nil
}

func (as *AppStore) resolveAuthEndpoint(guid string) string {
	fallback := appStoreURL(appStoreBuyHost, appStoreAuthPath)

	endpoint, err := as.getBagAuthEndpoint(guid)
	if err != nil {
		log.WithError(err).Debug("Failed to resolve App Store bag auth endpoint; using default endpoint")
		return fallback
	}

	if endpoint == "" {
		return fallback
	}

	return endpoint
}

func (as *AppStore) appStoreCookieHosts() []string {
	hosts := []string{appStoreBuyHost}
	if podHost := appStoreHostForPod(as.pod); podHost != appStoreBuyHost {
		hosts = append(hosts, podHost)
	}
	return hosts
}

func (as *AppStore) appStoreSessionCookies() []*http.Cookie {
	cookieMap := make(map[string]*http.Cookie)
	for _, host := range as.appStoreCookieHosts() {
		cookies := as.Client.Jar.Cookies(&url.URL{Scheme: "https", Host: host})
		for _, cookie := range cookies {
			key := strings.Join([]string{cookie.Name, cookie.Domain, cookie.Path}, "|")
			cookieMap[key] = cookie
		}
	}

	cookies := make([]*http.Cookie, 0, len(cookieMap))
	for _, cookie := range cookieMap {
		cookies = append(cookies, cookie)
	}
	return cookies
}

func newAppStoreTransport(config *AppStoreConfig) *http.Transport {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.Insecure,
	}

	if !config.Insecure {
		pool, err := x509.SystemCertPool()
		if err != nil {
			log.WithError(err).Debug("Failed to load system cert pool; falling back to default TLS trust")
		} else if pool != nil {
			tlsConfig.RootCAs = pool
		}
	}

	return &http.Transport{
		Proxy:           GetProxy(config.Proxy),
		TLSClientConfig: tlsConfig,
	}
}

// NewAppStore returns a AppStore instance
func NewAppStore(config *AppStoreConfig) *AppStore {
	jar, _ := cookiejar.New(nil)

	as := AppStore{
		Client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 0 && via[len(via)-1].URL.Path == appStoreAuthPath {
					return http.ErrUseLastResponse
				}
				return nil
			},
			Jar:       jar,
			Transport: newAppStoreTransport(config),
		},
		config: config,
	}

	return &as
}

// Init AppStore
func (as *AppStore) Init() (err error) {
	// create credential vault (if it doesn't exist)
	as.Vault, err = keyring.Open(keyring.Config{
		ServiceName:                    KeychainServiceName,
		KeychainSynchronizable:         false,
		KeychainAccessibleWhenUnlocked: true,
		KeychainTrustApplication:       true,
		FileDir:                        as.config.ConfigDir,
		FilePasswordFunc: func(string) (string, error) {
			if len(as.config.VaultPassword) == 0 {
				msg := "Enter a password to decrypt your credentials vault: " + filepath.Join(as.config.ConfigDir, VaultName)
				if _, err := os.Stat(filepath.Join(as.config.ConfigDir, VaultName)); errors.Is(err, os.ErrNotExist) {
					msg = "Enter a password to encrypt your credentials to vault: " + filepath.Join(as.config.ConfigDir, VaultName)
				}
				prompt := &survey.Password{
					Message: msg,
				}
				if err := survey.AskOne(prompt, &as.config.VaultPassword); err != nil {
					if err == terminal.InterruptErr {
						log.Warn("Exiting...")
						os.Exit(0)
					}
					return "", err
				}
			}
			return as.config.VaultPassword, nil
		},
	})
	if err != nil {
		return fmt.Errorf("failed to open vault: %s", err)
	}

	return nil
}

func (as *AppStore) Login(username, password string) error {
	if len(username) == 0 || len(password) == 0 {
		creds, err := as.Vault.Get(VaultName)
		if err != nil { // failed to get credentials from vault (prompt user for credentials)
			log.Errorf("failed to get credentials from vault: %v", err)
			// get username
			if len(username) == 0 {
				prompt := &survey.Input{
					Message: "Please type your username:",
				}
				if err := survey.AskOne(prompt, &username); err != nil {
					if err == terminal.InterruptErr {
						log.Warn("Exiting...")
						os.Exit(0)
					}
					return err
				}
			}
			// get password
			if len(password) == 0 {
				prompt := &survey.Password{
					Message: "Please type your password:",
				}
				if err := survey.AskOne(prompt, &password); err != nil {
					if err == terminal.InterruptErr {
						log.Warn("Exiting...")
						os.Exit(0)
					}
					return err
				}
			}
			// save credentials to vault
			dat, err := json.Marshal(&AppleAccountAuth{
				Credentials: credentials{
					Username: username,
					Password: password,
				},
			})
			if err != nil {
				return fmt.Errorf("failed to marshal keychain credentials: %v", err)
			}
			if err := as.Vault.Set(keyring.Item{
				Key:         VaultName,
				Data:        dat,
				Label:       AppName,
				Description: "application password",
			}); err != nil {
				return fmt.Errorf("failed to store credentials in vault: %v", err)
			}
		} else { // credentials found in vault
			var auth AppleAccountAuth
			if err := json.Unmarshal(creds.Data, &auth); err != nil {
				return fmt.Errorf("failed to unmarshal keychain credentials: %v", err)
			}
			username = auth.Credentials.Username
			password = auth.Credentials.Password
			auth = AppleAccountAuth{}
		}
	}

	if err := as.loadSession(); err != nil { // load previous session (if error, login)
		return as.signIn(username, password, "", 1, "")
	}

	return nil
}

func (as *AppStore) signIn(username, password, code string, attempt int, pod string) error {
	mac, err := getMacAddress()
	if err != nil {
		return fmt.Errorf("failed to get mac address: %v", err)
	}
	guid := strings.ReplaceAll(strings.ToUpper(mac), ":", "")
	as.authEndpoint = as.resolveAuthEndpoint(guid)
	log.WithField("endpoint", as.authEndpoint).Debug("Using App Store auth endpoint")

	if pod == "" {
		as.pod = ""
	}

	return as.signInWithEndpoint(username, password, code, attempt, pod, as.authEndpoint, false)
}

func (as *AppStore) signInWithEndpoint(username, password, code string, attempt int, pod, endpoint string, triedFallback bool) error {
	if attempt > 4 {
		return errors.New("too many authentication attempts")
	}

	mac, err := getMacAddress()
	if err != nil {
		return fmt.Errorf("failed to get mac address: %v", err)
	}

	var buf bytes.Buffer
	encoder := plist.NewEncoderForFormat(&buf, plist.XMLFormat)

	lr := loginRequest{
		AppleID:  username,
		Attempt:  strconv.Itoa(attempt),
		GuID:     strings.ReplaceAll(strings.ToUpper(mac), ":", ""),
		Password: password + strings.ReplaceAll(code, " ", ""),
		Rmp:      "0",
		Why:      "signIn",
	}

	if err := encoder.Encode(lr); err != nil {
		return err
	}

	req, err := http.NewRequest("POST", endpoint, &buf)
	if err != nil {
		return fmt.Errorf("failed to create http POST request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("User-Agent", userAgent)

	res, err := as.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	responsePod := strings.TrimSpace(res.Header.Get("pod"))
	if responsePod != "" {
		as.pod = responsePod
	} else if pod != "" {
		as.pod = pod
	}
	responseStoreFront := strings.TrimSpace(res.Header.Get("X-Set-Apple-Store-Front"))
	if responseStoreFront != "" {
		as.storeFront = responseStoreFront
	}

	if res.StatusCode == http.StatusFound {
		nextEndpoint := endpoint
		if loc := strings.TrimSpace(res.Header.Get("Location")); loc != "" {
			resolvedEndpoint, err := resolveRedirectEndpoint(req.URL, loc)
			if err != nil {
				return err
			}
			nextEndpoint = resolvedEndpoint
		}
		nextPod := responsePod
		if nextPod == "" {
			nextPod = pod
		}

		return as.signInWithEndpoint(username, password, "", attempt+1, nextPod, nextEndpoint, triedFallback)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}

	log.Debugf("POST Login: (%d):\n%s\n", res.StatusCode, string(body))

	// os.WriteFile("login.xml", body, 0644)

	if res.StatusCode == http.StatusForbidden && !triedFallback {
		fallbackEndpoint := appStoreURL(appStoreBuyHost, appStoreAuthPath)
		if endpoint == fallbackEndpoint {
			fallbackEndpoint = as.resolveAuthEndpoint(lr.GuID)
		}
		if fallbackEndpoint != "" && fallbackEndpoint != endpoint {
			log.WithFields(log.Fields{
				"status":   res.StatusCode,
				"from":     endpoint,
				"fallback": fallbackEndpoint,
			}).Debug("Retrying App Store login with fallback auth endpoint")
			return as.signInWithEndpoint(username, password, code, attempt+1, as.pod, fallbackEndpoint, true)
		}
	}

	var login loginResponse
	if err := decodePlistResponse(body, &login); err != nil {
		return fmt.Errorf("failed to decode login response: %v", err)
	}

	if attempt == 1 && login.FailureType == FailureTypeInvalidCredentials {
		return as.signInWithEndpoint(username, password, "", attempt+1, as.pod, endpoint, triedFallback)
	}

	if res.StatusCode == http.StatusNotFound || login.CustomerMessage == ErrLoginRequires2fa {
		if len(code) == 0 {
			prompt := &survey.Password{
				Message: "Please type your verification code:",
			}
			if err := survey.AskOne(prompt, &code); err != nil {
				if err == terminal.InterruptErr {
					log.Warn("Exiting...")
					os.Exit(0)
				}
				return err
			}
		}
		return as.signInWithEndpoint(username, password, code, attempt+1, as.pod, endpoint, triedFallback)
	}

	if login.FailureType != "" {
		if login.CustomerMessage != "" {
			return errors.New(login.CustomerMessage)
		}
		return fmt.Errorf("App Store login failed: failureType=%s", login.FailureType)
	}

	if res.StatusCode != http.StatusOK || login.DsPersonID == "" || login.PasswordToken == "" {
		if login.CustomerMessage != "" {
			return errors.New(login.CustomerMessage)
		}
		return fmt.Errorf("App Store login failed: status=%d", res.StatusCode)
	}

	as.username = username
	as.dsid = login.DsPersonID
	as.token = login.PasswordToken
	as.authEndpoint = endpoint

	return as.storeSession(login)
}

func (as *AppStore) reSignInFromVault() error {
	key, err := as.Vault.Get(VaultName)
	if err != nil {
		return fmt.Errorf("failed to get dev auth from vault: %v", err)
	}

	var auth AppleAccountAuth
	if err := json.Unmarshal(key.Data, &auth); err != nil {
		return fmt.Errorf("failed to unmarshal dev auth: %v", err)
	}

	if err := as.signIn(auth.Credentials.Username, auth.Credentials.Password, "", 1, ""); err != nil {
		return fmt.Errorf("failed to re-signin: %v", err)
	}
	auth = AppleAccountAuth{}

	return nil
}

func (as *AppStore) storeSession(resp loginResponse) error {
	// get dev auth from vault
	sess, err := as.Vault.Get(VaultName)
	if err != nil {
		return fmt.Errorf("failed to get dev auth from vault: %v", err)
	}

	var auth AppleAccountAuth
	if err := json.Unmarshal(sess.Data, &auth); err != nil {
		return fmt.Errorf("failed to unmarshal dev auth: %v", err)
	}

	auth.Credentials.PasswordToken = resp.PasswordToken
	auth.Credentials.DsPersonID = resp.DsPersonID
	auth.Credentials.Pod = as.pod
	auth.Credentials.StoreFront = as.storeFront

	auth.AppStoreSession = session{
		Cookies: as.appStoreSessionCookies(),
	}

	// save dev auth to vault
	data, err := json.Marshal(&auth)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %v", err)
	}

	if err := as.Vault.Set(keyring.Item{
		Key:         VaultName,
		Data:        data,
		Label:       AppName,
		Description: "application password",
	}); err != nil {
		return fmt.Errorf("failed to store app store session in vault: %v", err)
	}

	// clear dev auth mem
	auth = AppleAccountAuth{}

	return nil
}

func (as *AppStore) loadSession() error {
	// get dev auth from vault
	sess, err := as.Vault.Get(VaultName)
	if err != nil {
		return fmt.Errorf("failed to get dev auth from vault: %v", err)
	}

	var auth AppleAccountAuth
	if err := json.Unmarshal(sess.Data, &auth); err != nil {
		return fmt.Errorf("failed to unmarshal dev auth: %v", err)
	}

	as.username = auth.Credentials.Username
	as.dsid = auth.Credentials.DsPersonID
	as.token = auth.Credentials.PasswordToken
	as.pod = strings.TrimSpace(auth.Credentials.Pod)
	as.storeFront = strings.TrimSpace(auth.Credentials.StoreFront)
	as.authEndpoint = ""

	if as.dsid == "" || as.token == "" {
		return fmt.Errorf("vault is missing required credential data")
	}

	for _, host := range as.appStoreCookieHosts() {
		as.Client.Jar.SetCookies(&url.URL{Scheme: "https", Host: host}, auth.AppStoreSession.Cookies)
	}

	// clear dev auth mem
	auth = AppleAccountAuth{}

	return nil
}

func (as *AppStore) Search(searchTerm string, limit int) (Apps, error) {
	req, err := http.NewRequest("GET", appStoreSearchURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}

	q := url.Values{}
	q.Add("term", searchTerm)
	q.Add("country", as.config.StoreFront)
	q.Add("limit", strconv.Itoa(limit))
	q.Add("entity", "software,iPadSoftware")
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

func (as *AppStore) Lookup(bundleID string) (*App, error) {
	req, err := http.NewRequest("GET", appStoreLookupURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}

	q := url.Values{}
	q.Add("bundleId", bundleID)
	q.Add("country", as.config.StoreFront)
	q.Add("limit", "1")
	q.Add("entity", "software,iPadSoftware")
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

func (as *AppStore) Purchase(bundleID string) error {

	app, err := as.Lookup(bundleID)
	if err != nil {
		return fmt.Errorf("failed to lookup app for bundle ID %s: %v", bundleID, err)
	}

	if app.Price > 0 {
		return fmt.Errorf("paid apps cannot be purchased")
	}

	mac, err := getMacAddress()
	if err != nil {
		return fmt.Errorf("failed to get mac address: %v", err)
	}

	guid := strings.ReplaceAll(strings.ToUpper(mac), ":", "")

	for _, pricing := range []string{"STDQ", "GAME"} {
		shouldRetryWithNext, err := as.purchaseWithPricing(app, guid, pricing, true)
		if err != nil {
			return err
		}
		if !shouldRetryWithNext {
			return nil
		}
	}

	return fmt.Errorf("failed to purchase app %s", app.Name)
}

func (as *AppStore) purchaseWithPricing(app *App, guid, pricing string, allowReauthRetry bool) (bool, error) {
	buf := new(bytes.Buffer)

	if err := plist.NewEncoderForFormat(buf, plist.XMLFormat).Encode(&purchaseRequest{
		AppExtVrsID:               "0",
		HasAskedToFulfillPreorder: "true",
		BuyWithoutAuthorization:   "true",
		HasDoneAgeCheck:           "true",
		GuID:                      guid,
		NeedDiv:                   "0",
		OrigPage:                  fmt.Sprintf("Software-%d", app.ID),
		OrigPageLocation:          "Buy",
		Price:                     "0",
		PricingParameters:         pricing,
		ProductType:               "C",
		SalableAdamID:             app.ID,
	}); err != nil {
		return false, fmt.Errorf("failed to encode purchase request: %v", err)
	}

	req, err := http.NewRequest("POST", appStoreURL(appStoreHostForPod(as.pod), appStorePurchasePath), buf)
	if err != nil {
		return false, fmt.Errorf("failed to create http POST request: %v", err)
	}

	q := url.Values{}
	q.Add("guid", guid)
	req.URL.RawQuery = q.Encode()

	req.Header.Add("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-apple-plist")
	req.Header.Set("iCloud-DSID", as.dsid)
	req.Header.Set("X-Dsid", as.dsid)
	if as.storeFront != "" {
		req.Header.Set("X-Apple-Store-Front", as.storeFront)
	} else if as.config.StoreFront != "" {
		req.Header.Set("X-Apple-Store-Front", as.config.StoreFront)
	}
	req.Header.Set("X-Token", as.token)

	response, err := as.Client.Do(req)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	log.Debugf("POST Purchase (%s): (%d):\n%s\n", pricing, response.StatusCode, string(body))

	// os.WriteFile("purchase.xml", body, 0644)

	var purc purchaseResponse
	if err := decodePlistResponse(body, &purc); err != nil {
		return false, fmt.Errorf("failed to decode purchase response: %v", err)
	}

	if purc.FailureType == FailureTypePasswordTokenExpired {
		if !allowReauthRetry {
			return false, fmt.Errorf("failed to purchase app %s: token expired after re-auth retry (pricing=%s)", app.Name, pricing)
		}

		key, err := as.Vault.Get(VaultName)
		if err != nil {
			return false, fmt.Errorf("failed to get dev auth from vault: %v", err)
		}

		var auth AppleAccountAuth
		if err := json.Unmarshal(key.Data, &auth); err != nil {
			return false, fmt.Errorf("failed to unmarshal dev auth: %v", err)
		}
		if err := as.signIn(auth.Credentials.Username, auth.Credentials.Password, "", 1, ""); err != nil {
			return false, fmt.Errorf("failed to re-signin: %v", err)
		}
		auth = AppleAccountAuth{}

		return as.purchaseWithPricing(app, guid, pricing, false)
	}

	if response.StatusCode == http.StatusInternalServerError {
		customerMessage := strings.ToLower(strings.TrimSpace(purc.CustomerMessage))
		if strings.Contains(customerMessage, "already has a license") || strings.Contains(customerMessage, "already purchased") {
			return false, nil
		}
		if purc.CustomerMessage != "" {
			return false, fmt.Errorf("failed to purchase app %s: status=%d customerMessage=%q (pricing=%s)", app.Name, response.StatusCode, purc.CustomerMessage, pricing)
		}
		return false, fmt.Errorf("failed to purchase app %s: status=%d (pricing=%s)", app.Name, response.StatusCode, pricing)
	}

	if purc.FailureType == FailureTypeTemporarilyUnavailable && pricing == "STDQ" {
		return true, nil
	}

	if purc.FailureType != "" {
		if purc.CustomerMessage != "" {
			return false, fmt.Errorf("failed to purchase app %s: %s (failureType=%s, pricing=%s)", app.Name, purc.CustomerMessage, purc.FailureType, pricing)
		}
		return false, fmt.Errorf("failed to purchase app %s: failureType=%s (pricing=%s)", app.Name, purc.FailureType, pricing)
	}

	if response.StatusCode != http.StatusOK {
		if purc.CustomerMessage != "" {
			return false, fmt.Errorf("failed to purchase app %s: status=%d customerMessage=%q (pricing=%s)", app.Name, response.StatusCode, purc.CustomerMessage, pricing)
		}
		return false, fmt.Errorf("failed to purchase app %s: status=%d (pricing=%s)", app.Name, response.StatusCode, pricing)
	}

	if purc.JingleDocType != "purchaseSuccess" || purc.Status != 0 {
		return false, fmt.Errorf("failed to purchase app %s: jingleDocType=%s status=%d (pricing=%s)", app.Name, purc.JingleDocType, purc.Status, pricing)
	}

	return false, nil
}

func (as *AppStore) Download(bundleID, output string) error {
	return as.downloadWithAuthRetry(bundleID, output, true, true, len(transientUnknownBackoffs), fullRecoveryRetryBudget)
}

func (as *AppStore) downloadWithAuthRetry(bundleID, output string, allowAuthRetry, allowPurchaseRecovery bool, unknownRetryBudget, recoveryRetryBudget int) error {

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

	if err := plist.NewEncoderForFormat(buf, plist.XMLFormat).Encode(&downloadRequest{
		CreditDisplay: "",
		GUID:          guid,
		SalableAdamId: app.ID,
	}); err != nil {
		return fmt.Errorf("failed to encode download request: %v", err)
	}

	req, err := http.NewRequest("POST", appStoreURL(appStoreHostForPod(as.pod), appStoreDownloadPath), buf)
	if err != nil {
		return fmt.Errorf("failed to create http POST request: %v", err)
	}

	query := req.URL.Query()
	query.Set("guid", guid)
	req.URL.RawQuery = query.Encode()

	req.Header.Set("Content-Type", "application/x-apple-plist")
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("iCloud-DSID", as.dsid)
	req.Header.Set("X-Dsid", as.dsid)
	req.Header.Set("X-Token", as.token)
	if as.storeFront != "" {
		req.Header.Set("X-Apple-Store-Front", as.storeFront)
	} else if as.config.StoreFront != "" {
		req.Header.Set("X-Apple-Store-Front", as.config.StoreFront)
	}

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
	if err := decodePlistResponse(body, &dl); err != nil {
		return fmt.Errorf("failed to decode download response: %v", err)
	}

	if dl.FailureType == FailureTypeSignInToTheItunesStore || dl.FailureType == FailureTypePasswordTokenExpired {
		if !allowAuthRetry {
			if dl.CustomerMessage != "" {
				return fmt.Errorf("App Store download failed after re-auth retry: %s (failureType=%s)", dl.CustomerMessage, dl.FailureType)
			}
			return fmt.Errorf("App Store download failed after re-auth retry: failureType=%s", dl.FailureType)
		}
		if err := as.reSignInFromVault(); err != nil {
			return err
		}
		return as.downloadWithAuthRetry(bundleID, output, false, allowPurchaseRecovery, unknownRetryBudget, recoveryRetryBudget)
	}

	if dl.FailureType == FailureTypeLicenseNotFound {
		if err := as.Purchase(bundleID); err != nil {
			return fmt.Errorf("failed to purchase app: %v", err)
		}
		return as.downloadWithAuthRetry(bundleID, output, allowAuthRetry, false, unknownRetryBudget, recoveryRetryBudget)
	}

	if dl.FailureType == FailureTypeUnknownError {
		if allowAuthRetry {
			log.WithField("customer_message", strings.TrimSpace(dl.CustomerMessage)).Debug("Retrying App Store download after unknown error by refreshing session")
			if err := as.reSignInFromVault(); err != nil {
				return err
			}
			return as.downloadWithAuthRetry(bundleID, output, false, allowPurchaseRecovery, unknownRetryBudget, recoveryRetryBudget)
		}
		if allowPurchaseRecovery {
			log.Debug("Retrying App Store download after unknown error by attempting license purchase")
			if err := as.Purchase(bundleID); err != nil {
				log.WithError(err).Debug("Purchase recovery failed; retrying download once without purchase recovery")
			}
			return as.downloadWithAuthRetry(bundleID, output, allowAuthRetry, false, unknownRetryBudget, recoveryRetryBudget)
		}
		if unknownRetryBudget > 0 {
			retryAttempt := len(transientUnknownBackoffs) - unknownRetryBudget + 1
			backoff := transientUnknownBackoffs[retryAttempt-1]
			log.WithFields(log.Fields{
				"retry_attempt": retryAttempt,
				"retry_backoff": backoff.String(),
				"failure_type":  dl.FailureType,
			}).Warn("Retrying transient App Store unknown error")
			time.Sleep(backoff)
			return as.downloadWithAuthRetry(bundleID, output, false, false, unknownRetryBudget-1, recoveryRetryBudget)
		}
		if recoveryRetryBudget > 0 {
			log.WithFields(log.Fields{
				"failure_type":          dl.FailureType,
				"recovery_retry_budget": recoveryRetryBudget,
			}).Warn("Retrying App Store download with full recovery cycle")
			return as.downloadWithAuthRetry(
				bundleID,
				output,
				true,
				true,
				len(transientUnknownBackoffs),
				recoveryRetryBudget-1,
			)
		}
		if dl.CustomerMessage != "" {
			return fmt.Errorf("App Store download failed: %s (failureType=%s)", dl.CustomerMessage, dl.FailureType)
		}
		return fmt.Errorf("App Store download failed: failureType=%s", dl.FailureType)
	}

	if dl.FailureType != "" {
		if dl.CustomerMessage != "" {
			return fmt.Errorf("App Store download failed: %s (failureType=%s)", dl.CustomerMessage, dl.FailureType)
		}
		return fmt.Errorf("App Store download failed: failureType=%s", dl.FailureType)
	}

	if len(dl.Apps) == 0 {
		return fmt.Errorf("no items found in download response")
	}

	src, err := as.download(dl.Apps[0].URL)
	if err != nil {
		return fmt.Errorf("failed to download app: %v", err)
	}
	defer os.Remove(src)

	dst := filepath.Join(output, fmt.Sprintf("%s_%d.v%s.ipa", app.BundleID, app.ID, app.Version))

	if err := as.applyPatches(src, dst, &dl.Apps[0]); err != nil {
		return fmt.Errorf("failed to apply app patches: %v", err)
	}

	log.Infof("Created %s", dst)

	return nil
}

func (as *AppStore) download(url string) (string, error) {

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

	dest, err := os.CreateTemp("", "appstore.ipa")
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

func (as *AppStore) applyPatches(src, dst string, info *downloadAppResult) (err error) {
	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open destination patch file: %v", err)
	}

	srcZip, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("failed to open source patch file: %v", err)
	}
	defer srcZip.Close()

	dstZip := zip.NewWriter(dstFile)
	defer dstZip.Close()

	manifestData := new(bytes.Buffer)
	infoData := new(bytes.Buffer)

	appBundle, err := as.replicateZip(srcZip, dstZip, infoData, manifestData)
	if err != nil {
		return fmt.Errorf("failed to replicate app bundle zip: %v", err)
	}

	if err := as.writeMetadata(info.Metadata, dstZip); err != nil {
		return fmt.Errorf("failed to write metadata: %v", err)
	}

	if manifestData.Len() > 0 {
		if err = as.applySinfPatches(dstZip, manifestData.Bytes(), appBundle, info); err != nil {
			return fmt.Errorf("failed to apply sinf patches: %v", err)
		}
	} else {
		if err := as.applyLegacySinfPatches(dstZip, infoData.Bytes(), appBundle, info); err != nil {
			return fmt.Errorf("failed to apply legacy sinf patches: %v", err)
		}
	}

	return nil
}

func (as *AppStore) writeMetadata(metadata map[string]any, zip *zip.Writer) error {
	metadata["apple-id"] = as.username
	metadata["userName"] = as.username

	metadataFile, err := zip.Create("iTunesMetadata.plist")
	if err != nil {
		return fmt.Errorf("failed to create iTunesMetadata.plist: %v", err)
	}

	data, err := plist.Marshal(metadata, plist.BinaryFormat)
	if err != nil {
		return fmt.Errorf("failed to marshal iTunesMetadata.plist: %v", err)
	}

	if _, err := metadataFile.Write(data); err != nil {
		return fmt.Errorf("failed to write iTunesMetadata.plist: %v", err)
	}

	return nil
}

func (as *AppStore) replicateZip(src *zip.ReadCloser, dst *zip.Writer, info *bytes.Buffer, manifest *bytes.Buffer) (appBundle string, err error) {
	for _, file := range src.File {
		srcFile, err := file.OpenRaw()
		if err != nil {
			return "", fmt.Errorf("failed to open source file: %v", err)
		}

		if strings.HasSuffix(file.Name, ".app/SC_Info/Manifest.plist") {
			srcFileD, err := file.Open()
			if err != nil {
				return "", fmt.Errorf("failed to open source file: %v", err)
			}

			if _, err := io.Copy(manifest, srcFileD); err != nil {
				return "", fmt.Errorf("failed to copy manifest file: %v", err)
			}
		}

		if strings.Contains(file.Name, ".app/Info.plist") {
			srcFileD, err := file.Open()
			if err != nil {
				return "", fmt.Errorf("failed to open source file: %v", err)
			}

			if !strings.Contains(file.Name, "/Watch/") {
				appBundle = filepath.Base(strings.TrimSuffix(file.Name, ".app/Info.plist"))
			}

			if _, err := io.Copy(info, srcFileD); err != nil {
				return "", fmt.Errorf("failed to copy info file: %v", err)
			}
		}

		header := file.FileHeader
		dstFile, err := dst.CreateRaw(&header)
		if err != nil {
			return "", fmt.Errorf("failed to create destination header file: %v", err)
		}

		if _, err := io.Copy(dstFile, srcFile); err != nil {
			return "", fmt.Errorf("failed to copy file: %v", err)
		}
	}

	if appBundle == "" {
		return "", fmt.Errorf("failed to determine name of app bundle")
	}

	return appBundle, nil
}

func (as *AppStore) applySinfPatches(zip *zip.Writer, manifestData []byte, appBundle string, info *downloadAppResult) error {
	var manifest packageManifest
	if _, err := plist.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("failed to unmarshal package manifest: %w", err)
	}

	zipped, err := utils.Zip(info.Sinfs, manifest.SinfPaths)
	if err != nil {
		return fmt.Errorf("failed to zip sinf files: %w", err)
	}

	for _, pair := range zipped {
		sp := fmt.Sprintf("Payload/%s.app/%s", appBundle, pair.Second)

		file, err := zip.Create(sp)
		if err != nil {
			return fmt.Errorf("failed to create sinf file: %w", err)
		}

		if _, err := file.Write(pair.First.Data); err != nil {
			return fmt.Errorf("failed to write sinf data: %w", err)
		}
	}

	return nil
}

func (as *AppStore) applyLegacySinfPatches(zip *zip.Writer, infoData []byte, appBundle string, info *downloadAppResult) error {

	var pinfo packageInfo
	if _, err := plist.Unmarshal(infoData, &pinfo); err != nil {
		return fmt.Errorf("failed to unmarshal package info data: %w", err)
	}

	if pinfo.BundleExecutable == "" {
		return fmt.Errorf("failed to determine app executable for legacy sinf patch")
	}

	if len(info.Sinfs) == 0 {
		return fmt.Errorf("no sinf data available for legacy patch")
	}

	sp := fmt.Sprintf("Payload/%s.app/SC_Info/%s.sinf", appBundle, pinfo.BundleExecutable)

	file, err := zip.Create(sp)
	if err != nil {
		return fmt.Errorf("failed to create sinf file: %w", err)
	}

	if _, err := file.Write(info.Sinfs[0].Data); err != nil {
		return fmt.Errorf("failed to write sinf data: %w", err)
	}

	return nil
}
