package download

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"strings"

	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/PuerkitoBio/goquery"
	"github.com/apex/log"
)

const (
	betaDownloadsURL    = "https://developer.apple.com/download/"
	releaseDownloadsURL = "https://developer.apple.com/download/release/"

	loginURL      = "https://idmsa.apple.com/appleauth/auth/signin"
	trustURL      = "https://idmsa.apple.com/appleauth/auth/2sv/trust"
	itcServiceKey = "https://appstoreconnect.apple.com/olympus/v1/app/config?hostname=itunesconnect.apple.com"
)

var (
	scnt                   string
	xAppleIDSessionID      string
	xAppleIDAccountCountry string
	redirect               string
)

const (
	ERROR_CODE_BAD_CREDS        = -20101 // Your Apple ID or password was incorrect.
	ERROR_CODE_BAD_VERIFICATION = -21669 // Incorrect verification code.
	// TODO: flesh out the rest of the error codes
)

// App is the app object
type App struct {
	Client *http.Client

	authService authService
	authOptions authOptions
	codeRequest authOptions
}

// DevDownloads are all the downloads from https://developer.apple.com/download/
type DevDownloads struct {
	Version string `json:"version,omitempty"`
	Title   string `json:"title,omitempty"`
	Build   string `json:"build,omitempty"`
	URL     string `json:"url,omitempty"`
	Type    string `json:"type,omitempty"`
}

// Downloads listDownloads.action response
type Downloads struct {
	CreationTimestamp   time.Time `json:"creationTimestamp,omitempty"`
	ResultCode          int       `json:"resultCode,omitempty"`
	UserLocale          string    `json:"userLocale,omitempty"`
	ProtocolVersion     string    `json:"protocolVersion,omitempty"`
	RequestURL          string    `json:"requestUrl,omitempty"`
	ResponseID          string    `json:"responseId,omitempty"`
	HTTPResponseHeaders struct {
		SetCookie string `json:"Set-Cookie,omitempty"`
	} `json:"httpResponseHeaders,omitempty"`
	Downloads []download
}

type authService struct {
	URL string `json:"authServiceUrl,omitempty"`
	Key string `json:"authServiceKey,omitempty"`
}

type auth struct {
	AccountName string   `json:"accountName,omitempty"`
	Password    string   `json:"password,omitempty"`
	RememberMe  bool     `json:"rememberMe,omitempty"`
	TrustTokens []string `json:"trust_tokens,omitempty"`
}

type trustedPhoneNumbers []trustedPhoneNumber

type trustedPhoneNumber struct {
	ID                 int    `json:"id,omitempty"`
	ObfuscatedNumber   string `json:"obfuscatedNumber,omitempty"`
	PushMode           string `json:"pushMode,omitempty"`
	NumberWithDialCode string `json:"numberWithDialCode,omitempty"`
}

type securityCode struct {
	Code                  string `json:"code,omitempty"`
	Length                int    `json:"length,omitempty"`
	TooManyCodesSent      bool   `json:"tooManyCodesSent,omitempty"`
	TooManyCodesValidated bool   `json:"tooManyCodesValidated,omitempty"`
	SecurityCodeLocked    bool   `json:"securityCodeLocked,omitempty"`
	SecurityCodeCooldown  bool   `json:"securityCodeCooldown,omitempty"`
}

type authOptions struct {
	TrustedDeviceCount              int                 `json:"trustedDeviceCount,omitempty"`
	OtherTrustedDeviceClass         string              `json:"otherTrustedDeviceClass,omitempty"`
	TrustedPhoneNumbers             trustedPhoneNumbers `json:"trustedPhoneNumbers,omitempty"`
	PhoneNumber                     trustedPhoneNumber  `json:"phoneNumber,omitempty"`
	TrustedPhoneNumber              trustedPhoneNumber  `json:"trustedPhoneNumber,omitempty"`
	SecurityCode                    securityCode        `json:"securityCode,omitempty"`
	Mode                            string              `json:"mode,omitempty"`
	Type                            string              `json:"type,omitempty"`
	AuthenticationType              string              `json:"authenticationType,omitempty"`
	RecoveryURL                     string              `json:"recoveryUrl,omitempty"`
	CantUsePhoneNumberURL           string              `json:"cantUsePhoneNumberUrl,omitempty"`
	RecoveryWebURL                  string              `json:"recoveryWebUrl,omitempty"`
	RepairPhoneNumberURL            string              `json:"repairPhoneNumberUrl,omitempty"`
	RepairPhoneNumberWebURL         string              `json:"repairPhoneNumberWebUrl,omitempty"`
	AboutTwoFactorAuthenticationURL string              `json:"aboutTwoFactorAuthenticationUrl,omitempty"`
	AutoVerified                    bool                `json:"autoVerified,omitempty"`
	ShowAutoVerificationUI          bool                `json:"showAutoVerificationUI,omitempty"`
	ManagedAccount                  bool                `json:"managedAccount,omitempty"`
	Hsa2Account                     bool                `json:"hsa2Account,omitempty"`
	RestrictedAccount               bool                `json:"restrictedAccount,omitempty"`
	SupportsRecovery                bool                `json:"supportsRecovery,omitempty"`
	SupportsCustodianRecovery       bool                `json:"supportsCustodianRecovery,omitempty"`
	ServiceErrors                   []serviceError      `json:"serviceErrors,omitempty"`
	NoTrustedDevices                bool                `json:"noTrustedDevices,omitempty"`
}

type secCode struct {
	Code string `json:"code,omitempty"`
}
type phoneNumber struct {
	ID int `json:"id"`
}
type phone struct {
	SecurityCode secCode     `json:"securityCode,omitempty"`
	Number       phoneNumber `json:"phoneNumber"`
	Mode         string      `json:"mode"`
}

type signInResponse struct {
	AuthType string `json:"authType,omitempty"`
}

type serviceError struct {
	Code              string `json:"code,omitempty"`
	Title             string `json:"title,omitempty"`
	Message           string `json:"message,omitempty"`
	SuppressDismissal bool   `json:"suppressDismissal,omitempty"`
}

type serviceErrorsResponse struct {
	Errors   []serviceError `json:"serviceErrors,omitempty"`
	HasError bool           `json:"hasError,omitempty"`
}

type category struct {
	ID        int    `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	SortOrder int    `json:"sortOrder,omitempty"`
}

type fformat struct {
	Extension   string `json:"extension,omitempty"`
	Description string `json:"description,omitempty"`
}

type dfile struct {
	Filename     string  `json:"filename,omitempty"`
	DisplayName  string  `json:"displayName,omitempty"`
	RemotePath   string  `json:"remotePath,omitempty"`
	FileSize     int     `json:"fileSize,omitempty"`
	SortOrder    int     `json:"sortOrder,omitempty"`
	DateCreated  string  `json:"dateCreated,omitempty"`
	DateModified string  `json:"dateModified,omitempty"`
	FileFormat   fformat `json:"fileFormat,omitempty"`
}

type download struct {
	Name          string     `json:"name,omitempty"`
	Description   string     `json:"description,omitempty"`
	IsReleased    int        `json:"isReleased,omitempty"`
	DatePublished string     `json:"datePublished,omitempty"`
	DateCreated   string     `json:"dateCreated,omitempty"`
	DateModified  string     `json:"dateModified,omitempty"`
	Categories    []category `json:"categories,omitempty"`
	Files         []dfile    `json:"files,omitempty"`
}

func noRedirect(req *http.Request, via []*http.Request) error {
	redirect = req.Response.Header.Get("Location")
	log.Infof("redirecting to %s", redirect)
	return nil
}

func (app *App) updateRequestHeaders(req *http.Request) {
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	req.Header.Set("X-Apple-Id-Session-Id", xAppleIDSessionID)
	req.Header.Set("X-Apple-Widget-Key", app.authService.Key)
	req.Header.Set("Scnt", scnt)

	req.Header.Add("User-Agent", "Configurator/2.0 (Macintosh; OS X 10.12.6; 16G29) AppleWebKit/2603.3.8")
}

// NewApp returns a new instance of teh dev portal app
func NewApp() *App {
	jar, _ := cookiejar.New(nil)

	app := App{
		Client: &http.Client{
			Jar: jar,
			// CheckRedirect: noRedirect,
		},
	}

	return &app
}

func (app *App) getITCServiceKey() error {

	response, err := app.Client.Get(itcServiceKey)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(body, &app.authService); err != nil {
		return fmt.Errorf("failed to deserialize response body JSON: %v", err)
	}

	log.Debugf("GET iTC Service Key: %s\n", string(body))

	if response.StatusCode != 200 {
		return fmt.Errorf("failed to get iTC Service Key: response received %s", response.Status)
	}

	return nil
}

func (app *App) getAuthOptions() error {
	req, err := http.NewRequest("GET", "https://idmsa.apple.com/appleauth/auth", nil)
	if err != nil {
		return fmt.Errorf("failed to create http GET request: %v", err)
	}
	app.updateRequestHeaders(req)

	response, err := app.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("GET getAuthOptions: %s\n", string(body))

	if err := json.Unmarshal(body, &app.authOptions); err != nil {
		return fmt.Errorf("failed to deserialize response body JSON: %v", err)
	}

	// TODO: parse out trusted device/phone info

	if response.StatusCode != 200 {
		return fmt.Errorf("failed to get auth options: response received %s", response.Status)
	}

	return nil
}

func (app *App) requestCode() error {
	buf := new(bytes.Buffer)

	json.NewEncoder(buf).Encode(&phone{
		Number: phoneNumber{
			ID: 1,
		},
		// Mode: "sms",
		Mode: "push",
	})

	// req, err := http.NewRequest("PUT", "https://idmsa.apple.com/appleauth/auth/verify/phone", buf)
	req, err := http.NewRequest("PUT", "https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode", buf)
	if err != nil {
		return fmt.Errorf("failed to create http PUT request: %v", err)
	}
	app.updateRequestHeaders(req)

	response, err := app.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("PUT requestCode (%d): %s\n", response.StatusCode, string(body))

	if err := json.Unmarshal(body, &app.codeRequest); err != nil {
		return fmt.Errorf("failed to deserialize response body JSON: %v", err)
	}

	if 200 > response.StatusCode && response.StatusCode >= 300 {
		var errStr string
		if app.codeRequest.ServiceErrors != nil {
			for _, svcErr := range app.codeRequest.ServiceErrors {
				errStr += fmt.Sprintf(": %s", svcErr.Message)
			}
			return fmt.Errorf("failed to verify code: response received %s%s", response.Status, errStr)
		}

		if response.StatusCode == 423 { // code rate limiting
			log.Error(errStr)
			return nil
		}

		return fmt.Errorf("failed to verify code: response received %s%s", response.Status, errStr)
	}

	return nil
}

func (app *App) verifyCode(codeType, code string) error {
	buf := new(bytes.Buffer)

	json.NewEncoder(buf).Encode(&phone{
		Number: phoneNumber{
			ID: 1,
		},
		Mode: "sms",
		SecurityCode: secCode{
			Code: code,
		},
	})

	req, err := http.NewRequest("POST", fmt.Sprintf("https://idmsa.apple.com/appleauth/auth/verify/%s/securitycode", codeType), buf)
	if err != nil {
		return fmt.Errorf("failed to create http POST request: %v", err)
	}
	app.updateRequestHeaders(req)

	response, err := app.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("POST verifyCode: %s\n", string(body))

	if response.StatusCode != 200 {
		var requestCodeResp authOptions
		if err := json.Unmarshal(body, &requestCodeResp); err != nil {
			return fmt.Errorf("failed to deserialize response body JSON: %v", err)
		}
		if requestCodeResp.ServiceErrors != nil {
			var errStr string
			for _, svcErr := range requestCodeResp.ServiceErrors {
				errStr += fmt.Sprintf(": %s", svcErr.Message)
			}
			return fmt.Errorf("failed to verify code: response received %s%s", response.Status, errStr)
		}

		return fmt.Errorf("failed to verify code: response received %s", response.Status)
	}

	return nil
}

func (app *App) updateSession() error {

	req, err := http.NewRequest("GET", trustURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create http GET request: %v", err)
	}
	app.updateRequestHeaders(req)

	response, err := app.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("GET updateSession: %s\n", string(body))

	if 200 > response.StatusCode && response.StatusCode >= 300 {
		return fmt.Errorf("failed to update to trusted session: response received %s", response.Status)
	}

	return nil
}

func (app *App) signIn(username, password string) error {

	buf := new(bytes.Buffer)

	json.NewEncoder(buf).Encode(&auth{
		AccountName: username,
		Password:    password,
		RememberMe:  false,
	})

	req, err := http.NewRequest("POST", loginURL, buf)
	if err != nil {
		return fmt.Errorf("failed to create http POST request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	req.Header.Set("X-Apple-Widget-Key", app.authService.Key)
	req.Header.Add("User-Agent", "Configurator/2.0 (Macintosh; OS X 10.12.6; 16G29) AppleWebKit/2603.3.8")
	req.Header.Set("Accept", "application/json, text/javascript")

	response, err := app.Client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	log.Debugf("POST Login: %s\n", string(body))

	if response.StatusCode == 409 {
		xAppleIDAccountCountry = response.Header.Get("X-Apple-Id-Session-Id")
		xAppleIDSessionID = response.Header.Get("X-Apple-Id-Session-Id")
		scnt = response.Header.Get("Scnt")

		if err := app.getAuthOptions(); err != nil {
			return err
		}

		if err := app.requestCode(); err != nil {
			return err
		}

		code := ""
		prompt := &survey.Password{
			Message: "Please type your verification code",
		}
		survey.AskOne(prompt, &code)

		// TODO: how do I tell what type of code it is?

		if err := app.verifyCode("phone", code); err != nil {
			// if err := app.verifyCode("trusteddevice", code); err != nil {
			return err
		}

		if err := app.updateSession(); err != nil {
			return err
		}

		// TODO: add the ability to cache the session/cookies so you don't have to signin again (cronjob)
		// NOTE: you can't serialize cookie jars (non-exported fields)

		// buff := new(bytes.Buffer)
		// enc := gob.NewEncoder(buff)

		// if err := enc.Encode(app.Client); err != nil {
		// 	return err
		// }

		// if err := ioutil.WriteFile(".devcache", buf.Bytes(), 0755); err != nil {
		// 	return err
		// }

	} else if response.StatusCode == 200 {
		log.Warn("not tested with (non-two-factor enabled accounts) if fails; please let author know")
	} else {
		return fmt.Errorf("failed to sign in; expected status code 409 (for two factor auth): response received %s", response.Status)
	}

	return nil
}

// Login to Apple
func (app *App) Login(username, password string) error {

	// TODO: add the ability to cache the session/cookies so you don't have to signin again (cronjob)
	// if _, err := os.Stat(".devcache"); err == nil {
	// 	cache, err := os.Open(".devcache")
	// 	if err != nil {
	// 		return err
	// 	}
	// 	// Decoding the serialized data
	// 	return gob.NewDecoder(cache).Decode(&app.Client)
	// }

	if err := app.getITCServiceKey(); err != nil {
		return err
	}

	return app.signIn(username, password)
}

// GetDownloads returns all the downloads in "More Downloads" - https://developer.apple.com/download/all/
func (app *App) GetDownloads() (*Downloads, error) {
	var downloads Downloads

	req, err := http.NewRequest("POST", "https://developer.apple.com/services-account/QH65B2/downloadws/listDownloads.action", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http POST request: %v", err)
	}
	req.Header.Set("Accept", "application/json")

	response, err := app.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &downloads); err != nil {
		return nil, fmt.Errorf("failed to deserialize response body JSON: %v", err)
	}

	log.Debugf("Get Downloads: %s\n", string(body))

	return &downloads, nil
}

// GetDevDownloads scrapes the https://developer.apple.com/download/ page for links
func (app *App) GetDevDownloads(beta bool) ([]DevDownloads, error) {

	var ipsws []DevDownloads

	var downloadURL string
	if beta {
		downloadURL = betaDownloadsURL
	} else {
		downloadURL = releaseDownloadsURL
	}

	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create http GET request: %v", err)
	}

	response, err := app.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to do GET request: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		return nil, fmt.Errorf("failed to GET %s: response received %s", downloadURL, response.Status)
	}

	doc, err := goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		return nil, err
	}

	doc.Find("#main li.os-links").Each(func(i int, s *goquery.Selection) {
		s.Find(".row").Each(func(index int, row *goquery.Selection) {

			// Get ALL the iOS ipsw links
			row.Find("ul.ios-list").Each(func(_ int, ul *goquery.Selection) {
				ul.Find("ul > li").Each(func(_ int, li *goquery.Selection) {
					a := li.Find("a[href]")
					href, _ := a.Attr("href")
					p := li.Find("p")
					version := ul.Parent().Parent().Parent().Find("h2")
					ipsw := DevDownloads{
						Title:   a.Text(),
						Version: version.Text(),
						Build:   p.Text(),
						URL:     href,
						Type:    "ios",
					}

					ipsws = append(ipsws, ipsw)
				})
			})

			// Get ALL the tvOS ipsw links
			row.Find("ul.tvos-list").Each(func(_ int, ul *goquery.Selection) {
				ul.Find("li").Each(func(_ int, li *goquery.Selection) {
					a := li.Find("a[href]")
					href, _ := a.Attr("href")
					p := li.Find("p")
					version := ul.Parent().Parent().Parent().Find("h2")
					ipsw := DevDownloads{
						Title:   a.Text(),
						Version: version.Text(),
						Build:   p.Text(),
						URL:     href,
						Type:    "tvos",
					}

					ipsws = append(ipsws, ipsw)
				})
			})

		})
	})

	// Get ALL the App download links
	doc.Find("#main li.app-links").Each(func(i int, s *goquery.Selection) {
		s.Find(".row").Each(func(index int, row *goquery.Selection) {
			row.Find("a[href]").Each(func(index int, a *goquery.Selection) {
				href, _ := a.Attr("href")
				if strings.Contains(href, "/services-account/download") {
					version := a.Parent().Parent().Find("h2")
					ipsw := DevDownloads{
						Version: version.Text(),
						URL:     href,
						Type:    "app",
					}

					ipsws = append(ipsws, ipsw)
				}
			})
		})
	})

	if len(ipsws) == 0 {
		// Get ALL the App download links (non-developer account)
		doc.Find("#main").Each(func(i int, s *goquery.Selection) {
			s.Find(".row").Each(func(index int, row *goquery.Selection) {
				row.Find("a[href]").Each(func(index int, a *goquery.Selection) {
					href, _ := a.Attr("href")
					if strings.Contains(href, "/services-account/download") {
						version := a.Parent().Parent().Find("h2")
						ipsw := DevDownloads{
							Version: version.Text(),
							URL:     href,
							Type:    "app",
						}

						ipsws = append(ipsws, ipsw)
					}
				})
			})
		})
	}

	return ipsws, nil
}
