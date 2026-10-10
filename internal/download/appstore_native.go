//go:build !ios

package download

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/storeauth"
)

const (
	appStoreNativeUserAgent = "Configurator/2.20 Configurator/2.20 (Macintosh; OS X 26.5; 25F80) AppleWebKit/619.1.15.111.2 AMS/1 (dt:1)"
	maxNativeAuthBody       = 1 << 20
	maxNativeAuthRedirects  = 2
)

var appStoreAnisetteHeaders = [...]string{
	"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-LU",
	"X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale",
	"X-Mme-Device-Id", "X-Apple-I-SRL-NO", "X-MMe-Client-Info",
}

// This go-plist version requires a comma to honor a field name. Do not use
// omitempty: the native request must include the false boolean too.
type nativeAppStoreRequest struct {
	AppleID                string `plist:"appleId,"`
	CreateSession          bool   `plist:"createSession,"`
	CredentialSource       int    `plist:"credentialSource,"`
	GUID                   string `plist:"guid,"`
	IsSilentAuthentication bool   `plist:"isSilentAuthentication,"`
	Password               string `plist:"password,"`
	PasswordSettings       struct {
		Free string `plist:"free,"`
		Paid string `plist:"paid,"`
	} `plist:"passwordSettings,"`
	RMP string `plist:"rmp,"`
}

type appStoreRequestSigner func(context.Context, []byte) ([]byte, error)

type appStoreGrandSlam interface {
	Login(context.Context, string, string) (*storeauth.GrandSlamSession, error)
	TriggerTwoFactor(context.Context, *storeauth.GrandSlamChallenge) error
	SubmitTwoFactor(context.Context, *storeauth.GrandSlamChallenge, string) error
}

func (as *AppStore) authenticate(username, password string) error {
	signer, err := storeauth.NewSAPSession(as.config.Context, as.Client)
	if err == nil {
		defer signer.Close()
		log.Debug("Using native Osprey SAP authentication")
		return as.signIn(username, password, "", 1, "", signer.Sign)
	}
	if !errors.Is(err, storeauth.ErrNativeUnavailable) {
		return fmt.Errorf("initialize native App Store signing: %w", err)
	}
	if !storeauth.NativeSupported() {
		return as.authenticateWithFallback(username, password, storeauth.ErrGrandSlamUnavailable)
	}
	return as.authenticateWithFallback(username, password, as.authenticateNative(username, password))
}

func (as *AppStore) authenticateWithFallback(username, password string, err error) error {
	if errors.Is(err, storeauth.ErrGrandSlamUnavailable) {
		if contextErr := as.config.Context.Err(); contextErr != nil {
			return contextErr
		}
		log.WithError(err).Debug("Native App Store authentication unavailable; trying existing login")
		log.Warn("Signed App Store login is unavailable on this system; trying legacy login. A supported macOS build is currently required for signed login")
		if err := as.signIn(username, password, "", 1, "", nil); err != nil {
			return fmt.Errorf("legacy App Store login failed (signed login currently requires a supported macOS build): %w", err)
		}
		return nil
	}
	return err
}

func (as *AppStore) authenticateNative(username, password string) error {
	log.Debug("Using native App Store authentication")
	headers, err := storeauth.NativeHeaders(as.config.Context)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("%w: get native App Store authentication headers: %v", storeauth.ErrGrandSlamUnavailable, err)
	}
	gsa, err := storeauth.NewGrandSlamClient(as.Client, headers)
	if err != nil {
		return err
	}
	session, err := as.grandSlamSession(gsa, username, password, func() (string, error) {
		var code string
		err := survey.AskOne(&survey.Password{Message: "Please type your verification code:"}, &code)
		return code, err
	})
	if err != nil {
		return err
	}
	mac, err := getMacAddress()
	if err != nil {
		return err
	}
	guid := strings.ReplaceAll(strings.ToUpper(mac), ":", "")
	return as.bridgeNativeSession(username, guid, session, headers, storeauth.Sign)
}

func (as *AppStore) grandSlamSession(gsa appStoreGrandSlam, username, password string, readCode func() (string, error)) (*storeauth.GrandSlamSession, error) {
	session, err := gsa.Login(as.config.Context, username, password)
	var challenge *storeauth.GrandSlamChallenge
	if !errors.As(err, &challenge) {
		return session, err
	}
	if err := gsa.TriggerTwoFactor(as.config.Context, challenge); err != nil {
		return nil, err
	}
	code, err := readCode()
	if err != nil {
		return nil, err
	}
	if err := gsa.SubmitTwoFactor(as.config.Context, challenge, code); err != nil {
		return nil, err
	}
	// Validation marks the device trusted. Only a fresh GSA exchange returns
	// the trusted password-equivalent token required by the Store bridge.
	return gsa.Login(as.config.Context, username, password)
}

func (as *AppStore) nativeAuthEndpoint(guid string) *url.URL {
	if bag, err := as.appStoreBag(guid); err == nil {
		for _, source := range []string{bag.URLBag.AuthenticateAccount, bag.AuthenticateAccount} {
			if endpoint, err := parseNativeAuthEndpoint(source); err == nil {
				return endpoint
			}
		}
	}
	// Current bags can still advertise only the legacy family.
	return &url.URL{Scheme: "https", Host: appStoreAuthHost, Path: appStoreAuthNativePath}
}

func validNativeAuthReference(source string) bool {
	if source == "" || len(source) > 8192 || strings.ContainsAny(source, "#\\") {
		return false
	}
	for _, c := range source {
		if c <= ' ' || c == 0x7f {
			return false
		}
	}
	path, _, _ := strings.Cut(source, "?")
	if strings.Contains(path, "%") {
		return false
	}
	for part := range strings.SplitSeq(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}

func validAppStorePod(pod string) bool {
	if len(pod) > 58 {
		return false
	}
	for _, c := range pod {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func parseNativeAuthEndpoint(source string) (*url.URL, error) {
	invalid := errors.New("invalid native App Store authentication endpoint")
	if !validNativeAuthReference(source) {
		return nil, invalid
	}
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawPath != "" || strings.HasSuffix(u.Host, ":") || (u.Port() != "" && u.Port() != "443") {
		return nil, invalid
	}
	if !isAppStorePodHost(u.Hostname(), appStoreAuthHost) {
		return nil, invalid
	}
	switch u.Path {
	case "/auth/v1/native", "/auth/v1/native/", "/auth/v1/native/fast", appStoreAuthNativePath:
		u.Path = appStoreAuthNativePath
	default:
		return nil, invalid
	}
	return u, nil
}

func resolveNativeAuthRedirect(base *url.URL, location string) (*url.URL, error) {
	if base == nil || !validNativeAuthReference(location) {
		return nil, errors.New("invalid native App Store authentication redirect")
	}
	reference, err := url.Parse(location)
	if err != nil {
		return nil, errors.New("invalid native App Store authentication redirect")
	}
	return parseNativeAuthEndpoint(base.ResolveReference(reference).String())
}

func nativeStorefront(country string) string {
	prefix := "143441-1"
	switch strings.ToUpper(country) {
	case "GB", "UK":
		prefix = "143444"
	case "DE":
		prefix = "143443-4"
	case "FR":
		prefix = "143442-3"
	case "JP":
		prefix = "143462-9"
	case "CA":
		prefix = "143455-6"
	case "AU":
		prefix = "143460"
	case "CN":
		prefix = "143465-19"
	case "IT":
		prefix = "143450-7"
	case "ES":
		prefix = "143454-8"
	}
	return prefix + ",34"
}

func (as *AppStore) bridgeNativeSession(username, guid string, session *storeauth.GrandSlamSession, headers http.Header, sign appStoreRequestSigner) error {
	if session == nil || session.PET == "" || session.ADSID == "" {
		return errors.New("GrandSlam returned no usable App Store credentials")
	}
	payload := nativeAppStoreRequest{AppleID: username, CreateSession: true, CredentialSource: 2, GUID: guid, Password: session.PET, RMP: "0"}
	payload.PasswordSettings.Free, payload.PasswordSettings.Paid = "always", "always"
	body, err := plist.Marshal(payload, plist.XMLFormat)
	if err != nil {
		return fmt.Errorf("encode native App Store login: %w", err)
	}
	endpoint := as.nativeAuthEndpoint(guid)
	storefront := nativeStorefront(session.StorefrontCountry)
	client := *as.Client
	if client.Timeout <= 0 || client.Timeout > 30*time.Second {
		client.Timeout = 30 * time.Second
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for redirects := 0; ; redirects++ {
		signature, err := sign(as.config.Context, body)
		if err != nil {
			return fmt.Errorf("sign native App Store request: %w", err)
		}
		if len(signature) == 0 {
			return errors.New("native App Store signature is empty")
		}
		req, err := http.NewRequestWithContext(as.config.Context, http.MethodPost, endpoint.String(), bytes.NewReader(body))
		if err != nil {
			return errors.New("failed to create native App Store request")
		}
		req.Header.Set("Content-Type", "application/x-apple-plist")
		req.Header.Set("User-Agent", appStoreNativeUserAgent)
		req.Header.Set("X-Apple-Client-Application", "com.apple.configurator.ui")
		req.Header.Set("X-Apple-ActionSignature", base64.StdEncoding.EncodeToString(signature))
		req.Header.Set("X-Apple-ADSID", session.ADSID)
		req.Header.Set("x-apple-age-area-compliance-id", "US")
		req.Header.Set("X-Apple-Connection-Type", "WiFi")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		if session.DSID != 0 {
			dsid := strconv.FormatInt(session.DSID, 10)
			req.Header.Set("X-DSID", dsid)
			req.Header.Set("iCloud-DSID", dsid)
			req.Header.Set("X-Apple-Store-Front", storefront)
		}
		for _, name := range appStoreAnisetteHeaders {
			if value := headers.Get(name); value != "" {
				req.Header.Set(name, value)
			}
		}
		req.Header.Set("X-Apple-I-Locale", headers.Get("X-Apple-Locale"))
		req.Header.Set("X-Apple-Tz", headers.Get("X-Apple-I-TimeZone"))
		res, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("native App Store request failed: %w", redactAppStoreTransportError(err))
		}
		data, readErr := io.ReadAll(io.LimitReader(res.Body, maxNativeAuthBody+1))
		res.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read native App Store response: %w", readErr)
		}
		if len(data) > maxNativeAuthBody {
			return errors.New("native App Store response exceeds size limit")
		}
		logHTTPResponseMetadata("POST native App Store login", res.StatusCode, len(data))
		switch res.StatusCode {
		case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
			if redirects == maxNativeAuthRedirects {
				return errors.New("too many native App Store authentication redirects")
			}
			next, err := resolveNativeAuthRedirect(endpoint, res.Header.Get("Location"))
			if err != nil {
				return err
			}
			endpoint = next
			continue
		}
		var login loginResponse
		if err := decodePlistResponse(data, &login); err != nil {
			return fmt.Errorf("native App Store login HTTP %d (Content-Type: %q): response is not a valid plist", res.StatusCode, res.Header.Get("Content-Type"))
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 || login.FailureType != "" || login.PasswordToken == "" || login.DsPersonID == "" {
			return fmt.Errorf("native App Store login rejected (HTTP %d, failureType=%q)", res.StatusCode, nativeFailureType(login.FailureType))
		}
		if session.DSID != 0 && login.DsPersonID != strconv.FormatInt(session.DSID, 10) {
			return errors.New("native App Store returned a conflicting account identity")
		}
		pod, err := nativeResponsePod(res.Header, login.DsPersonID)
		if err != nil {
			return err
		}
		if sf := res.Header.Get("X-Set-Apple-Store-Front"); sf != "" {
			storefront = sf
		}
		as.username, as.dsid, as.token, as.authEndpoint = username, login.DsPersonID, login.PasswordToken, endpoint.String()
		as.pod, as.storeFront = pod, storefront
		return as.storeSession(login)
	}
}

func redactAppStoreTransportError(err error) error {
	if wrapped, ok := errors.AsType[*url.Error](err); ok {
		return wrapped.Err
	}
	return err
}

func nativeFailureType(value string) string {
	if value == "" {
		return ""
	}
	if len(value) > 12 {
		return "unknown"
	}
	for i, c := range value {
		if (c < '0' || c > '9') && (i != 0 || c != '-') {
			return "unknown"
		}
	}
	return value
}

func nativeResponsePod(headers http.Header, dsid string) (string, error) {
	conflict := errors.New("native App Store returned a conflicting account identity")
	if value := headers.Get("X-Dsid"); value != "" && value != dsid {
		return "", conflict
	}
	pod := headers.Get("pod")
	if !validAppStorePod(pod) {
		return "", errors.New("native App Store returned an invalid pod")
	}
	for _, cookie := range headers.Values("Set-Cookie") {
		pair, _, _ := strings.Cut(cookie, ";")
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "itspod" {
			if !validAppStorePod(value) {
				return "", errors.New("native App Store returned an invalid pod")
			}
			if value != "" {
				if pod != "" && pod != value {
					return "", errors.New("native App Store returned conflicting pods")
				}
				pod = value
			}
			continue
		}
		if value == "" {
			continue
		}
		switch {
		case name == "X-Dsid":
			if value != dsid {
				return "", conflict
			}
		case strings.HasPrefix(name, "mt-tkn-"):
			if strings.TrimPrefix(name, "mt-tkn-") != dsid {
				return "", conflict
			}
		case strings.HasPrefix(name, "mz_mt0-"):
			if strings.TrimPrefix(name, "mz_mt0-") != dsid {
				return "", conflict
			}
		}
	}
	return pod, nil
}
