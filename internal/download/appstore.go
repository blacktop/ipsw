//go:build !ios

package download

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	urlPrefex           = "https://p25-"
	url2faPrefex        = "https://p71-"
	appStoreAuthURL     = urlPrefex + "buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"
	appStoreAuth2faURL  = url2faPrefex + "buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate"
	appStoreDownloadURL = urlPrefex + "buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct"
	appStorePurchaseURL = "https://buy.itunes.apple.com/WebObjects/MZBuy.woa/wa/buyProduct"
	appStoreSearchURL   = "https://itunes.apple.com/search"
	appStoreLookupURL   = "https://itunes.apple.com/lookup"

	// AppStoreSearchLimit is the maximum number of results returned by the App Store search API
	AppStoreSearchLimit = 200

	ErrLoginRequires2fa               = "MZFinance.BadLogin.Configurator_message"
	FailureTypeInvalidCredentials     = "-5000"
	FailureTypeUnknownError           = "5002"
	FailureTypePasswordTokenExpired   = "2034"
	FailureTypeLicenseNotFound        = "9610"
	FailureTypeTemporarilyUnavailable = "2059"
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
}

type AppStore struct {
	Client *http.Client

	Vault keyring.Keyring

	username string
	dsid     string
	token    string

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
		} `json:"address,omitempty" plist:"address,omitempty"`
	} `json:"accountInfo,omitempty" plist:"accountInfo,omitempty"`
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
		} `json:"account,omitempty" plist:"account,omitempty"`
		Family struct {
			HasFamily bool `json:"hasFamily,omitempty" plist:"hasFamily,omitempty"`
		} `json:"family,omitempty" plist:"family,omitempty"`
	} `json:"subscriptionStatus,omitempty" plist:"subscriptionStatus,omitempty"`
	AccountFlags      map[string]any `json:"accountFlags,omitempty" plist:"accountFlags,omitempty"`
	Status            int            `json:"status,omitempty" plist:"status,omitempty"`
	DownloadQueueInfo struct {
		DsID                  int  `json:"dsid,omitempty" plist:"dsid,omitempty"`
		IsAutoDownloadMachine bool `json:"is-auto-download-machine,omitempty" plist:"is-auto-download-machine,omitempty"`
	} `json:"download-queue-info,omitempty" plist:"download-queue-info,omitempty"`
	PrivacyAcknowledgement map[string]int `json:"privacyAcknowledgement,omitempty" plist:"privacyAcknowledgement,omitempty"`
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
	GuID          string `plist:"guid,omitempty"`
	SalableAdamID int    `plist:"salableAdamId,omitempty"`
}

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

// NewAppStore returns a AppStore instance
func NewAppStore(config *AppStoreConfig) *AppStore {
	jar, _ := cookiejar.New(nil)

	as := AppStore{
		Client: &http.Client{
			Jar: jar,
			Transport: &http.Transport{
				Proxy:           GetProxy(config.Proxy),
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.Insecure},
			},
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
			as.Vault.Set(keyring.Item{
				Key:         VaultName,
				Data:        dat,
				Label:       AppName,
				Description: "application password",
			})
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
		return as.signIn(username, password, "", 0)
	}

	return nil
}

func (as *AppStore) signIn(username, password, code string, attempt int) error {
	buf := new(bytes.Buffer)

	mac, err := getMacAddress()
	if err != nil {
		return fmt.Errorf("failed to get mac address: %v", err)
	}

	guid := strings.ReplaceAll(strings.ToUpper(mac), ":", "")

	plist.NewEncoderForFormat(buf, plist.XMLFormat).Encode(&loginRequest{
		AppleID:       username,
		Password:      fmt.Sprintf("%s%s", password, code),
		Attempt:       "4",
		CreateSession: "true",
		GuID:          guid,
		Rmp:           "0",
		Why:           "signIn",
	})

	req, err := http.NewRequest("POST", appStoreAuthURL, buf)
	if err != nil {
		return fmt.Errorf("failed to create http POST request: %v", err)
	}

	q := url.Values{}
	q.Add("guid", guid)
	req.URL.RawQuery = q.Encode()

	req.Header.Add("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := as.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("POST Login: (%d):\n%s\n", response.StatusCode, string(body))

	// os.WriteFile("login.xml", body, 0644)

	var login loginResponse
	if err := plist.NewDecoder(bytes.NewReader(body)).Decode(&login); err != nil {
		return fmt.Errorf("failed to decode login response: %v", err)
	}

	if attempt == 0 && login.FailureType == FailureTypeInvalidCredentials {
		return as.signIn(username, password, "", attempt+1)
	}

	if login.CustomerMessage == ErrLoginRequires2fa {
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
		return as.signIn(username, password, code, 0)
	}

	as.username = username
	as.dsid = login.DsPersonID
	as.token = login.PasswordToken

	return as.storeSession(login)
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

	auth.AppStoreSession = session{
		Cookies: as.Client.Jar.Cookies(&url.URL{Scheme: "https", Host: "p25-buy.itunes.apple.com"}),
	}

	// save dev auth to vault
	data, err := json.Marshal(&auth)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %v", err)
	}

	as.Vault.Set(keyring.Item{
		Key:         VaultName,
		Data:        data,
		Label:       AppName,
		Description: "application password",
	})

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

	if as.dsid == "" || as.token == "" {
		return fmt.Errorf("vault is missing required credential data")
	}

	as.Client.Jar.SetCookies(&url.URL{Scheme: "https", Host: "p25-buy.itunes.apple.com"}, auth.AppStoreSession.Cookies)

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

	buf := new(bytes.Buffer)

	mac, err := getMacAddress()
	if err != nil {
		return fmt.Errorf("failed to get mac address: %v", err)
	}

	guid := strings.ReplaceAll(strings.ToUpper(mac), ":", "")

	plist.NewEncoderForFormat(buf, plist.XMLFormat).Encode(&purchaseRequest{
		AppExtVrsID:               "0",
		HasAskedToFulfillPreorder: "true",
		BuyWithoutAuthorization:   "true",
		HasDoneAgeCheck:           "true",
		GuID:                      guid,
		NeedDiv:                   "0",
		OrigPage:                  fmt.Sprintf("Software-%d", app.ID),
		OrigPageLocation:          "Buy",
		Price:                     "0",
		PricingParameters:         "STDQ",
		ProductType:               "C",
		SalableAdamID:             app.ID,
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

func (as *AppStore) Download(bundleID, output string) error {

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
	if _, err := plist.Unmarshal(infoData, &info); err != nil {
		return fmt.Errorf("failed to unmarshal package info data: %w", err)
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
