//go:build !ios

package download

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/blacktop/ipsw/internal/storeauth"
)

func nativeTestSession() *storeauth.GrandSlamSession {
	return &storeauth.GrandSlamSession{ADSID: "synthetic-adsid", PET: "synthetic-pet", DSID: 12345, StorefrontCountry: "US"}
}

func nativeTestHeaders() http.Header {
	return http.Header{"X-Apple-I-Md": {"synthetic-md"}, "X-Apple-I-Md-M": {"synthetic-mdm"}, "X-Apple-Locale": {"en_US"}, "X-Apple-I-Timezone": {"UTC"}, "X-Apple-Identity-Token": {"must-not-be-forwarded"}, "X-Apple-Amd": {"must-not-be-forwarded"}}
}

func nativeTestBag(req *http.Request, endpoint string) *http.Response {
	return appStoreTestResponse(req, 200, "text/xml", `<plist><dict><key>authenticateAccount</key><string>https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate</string><key>urlBag</key><dict><key>authenticateAccount</key><string>`+endpoint+`</string></dict></dict></plist>`)
}

func syntheticNativeSigner(_ context.Context, body []byte) ([]byte, error) {
	sum := sha256.Sum256(body)
	return sum[:], nil
}

func checkNativeTestRequest(t *testing.T, req *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := syntheticNativeSigner(t.Context(), body)
	if req.Header.Get("X-Apple-ActionSignature") != base64.StdEncoding.EncodeToString(signature) {
		t.Error("signature does not cover exact request body")
	}
	if req.Method != http.MethodPost || req.Header.Get("Content-Type") != "application/x-apple-plist" || req.Header.Get("User-Agent") != appStoreNativeUserAgent {
		t.Error("incorrect native request profile")
	}
	return body
}

func TestNativeAppStoreBridge(t *testing.T) {
	posts, signs := 0, 0
	const selected = "https://p42-auth.itunes.apple.com/auth/v1/native?route=synthetic"
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet {
			return nativeTestBag(req, selected), nil
		}
		posts++
		body := checkNativeTestRequest(t, req)
		if req.URL.String() != "https://p42-auth.itunes.apple.com/auth/v1/native/fast/?route=synthetic" {
			t.Errorf("endpoint=%s", req.URL)
		}
		var values map[string]any
		if err := decodePlistResponse(body, &values); err != nil {
			t.Fatal(err)
		}
		if len(values) != 8 || values["appleId"] != "synthetic@example.invalid" || values["password"] != "synthetic-pet" || values["createSession"] != true || values["isSilentAuthentication"] != false || !bytes.Contains(body, []byte("<integer>2</integer>")) {
			t.Errorf("native body fields or types changed: %#v", values)
		}
		if req.Header.Get("X-DSID") != "12345" || req.Header.Get("iCloud-DSID") != "12345" || req.Header.Get("X-Apple-ADSID") != "synthetic-adsid" || req.Header.Get("X-Apple-Store-Front") != "143441-1,34" || req.Header.Get("X-Apple-I-MD") != "synthetic-md" || req.Header.Get("X-Apple-Client-Application") != "com.apple.configurator.ui" {
			t.Error("missing native authentication headers")
		}
		if req.Header.Get("X-Apple-Identity-Token") != "" || req.Header.Get("X-Apple-AMD") != "" {
			t.Error("forwarded headers outside the native profile")
		}
		res := appStoreTestResponse(req, 200, "text/xml", syntheticAppStoreLogin)
		res.Header.Add("Set-Cookie", "X-Dsid=12345; Domain=itunes.apple.com; Path=/; Secure")
		res.Header.Add("Set-Cookie", "itspod=42; Domain=itunes.apple.com; Path=/; Secure")
		res.Header.Add("Set-Cookie", "mz_at0=synthetic-cookie; Domain=itunes.apple.com; Path=/; Secure")
		return res, nil
	})
	signer := func(ctx context.Context, b []byte) ([]byte, error) { signs++; return syntheticNativeSigner(ctx, b) }
	if err := as.bridgeNativeSession("synthetic@example.invalid", "020000000001", nativeTestSession(), nativeTestHeaders(), signer); err != nil {
		t.Fatal(err)
	}
	if posts != 1 || signs != 1 || as.pod != "42" || as.token != "synthetic-token" {
		t.Fatalf("posts=%d signs=%d pod=%q", posts, signs, as.pod)
	}
	as.token, as.dsid, as.pod, as.storeFront = "", "", "", ""
	if err := as.loadSession(); err != nil {
		t.Fatal(err)
	}
	if as.token != "synthetic-token" || as.dsid != "12345" || as.pod != "42" || as.storeFront != "143441-1,34" || len(as.appStoreSessionCookies()) == 0 {
		t.Fatal("native session did not reload")
	}
}

func TestNativeAppStoreRedirect(t *testing.T) {
	for _, status := range []int{301, 302, 307, 308} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			posts, signs := 0, 0
			var first []byte
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodGet {
					return nativeTestBag(req, "https://auth.itunes.apple.com/auth/v1/native"), nil
				}
				posts++
				body := checkNativeTestRequest(t, req)
				if posts == 1 {
					first = body
					res := appStoreTestResponse(req, status, "text/html", "")
					res.Header.Set("Location", "https://p7-auth.itunes.apple.com/auth/v1/native/fast/")
					return res, nil
				}
				if !bytes.Equal(first, body) {
					t.Error("redirect changed signed body")
				}
				return appStoreTestResponse(req, 200, "text/xml", syntheticAppStoreLogin), nil
			})
			signer := func(ctx context.Context, b []byte) ([]byte, error) { signs++; return syntheticNativeSigner(ctx, b) }
			if err := as.bridgeNativeSession("synthetic@example.invalid", "020000000001", nativeTestSession(), nativeTestHeaders(), signer); err != nil {
				t.Fatal(err)
			}
			if posts != 2 || signs != 2 {
				t.Fatalf("posts=%d signs=%d", posts, signs)
			}
		})
	}
}

func TestNativeAppStoreUnsafeRedirect(t *testing.T) {
	for _, destination := range []string{"", "http://auth.itunes.apple.com/auth/v1/native", "https://auth.itunes.apple.com.example.invalid/auth/v1/native", "https://user@auth.itunes.apple.com/auth/v1/native", "https://pbad-auth.itunes.apple.com/auth/v1/native", "https://auth.itunes.apple.com:8443/auth/v1/native", "https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate", "/auth/v1/native/../native", "/%61uth/v1/native", "https://auth.itunes.apple.com:/auth/v1/native", "/auth/v1/native/fast/#secret"} {
		t.Run(destination, func(t *testing.T) {
			posts, signs := 0, 0
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodGet {
					return nativeTestBag(req, "https://auth.itunes.apple.com/auth/v1/native"), nil
				}
				posts++
				res := appStoreTestResponse(req, 302, "text/html", "")
				res.Header.Set("Location", destination)
				return res, nil
			})
			signer := func(ctx context.Context, b []byte) ([]byte, error) { signs++; return syntheticNativeSigner(ctx, b) }
			err := as.bridgeNativeSession("synthetic@example.invalid", "020000000001", nativeTestSession(), nativeTestHeaders(), signer)
			if err == nil || posts != 1 || signs != 1 {
				t.Fatalf("posts=%d signs=%d err=%v", posts, signs, err)
			}
		})
	}
}

func TestNativeAppStoreRejectsInvalidResult(t *testing.T) {
	for _, tc := range []struct {
		name, body, cookie string
		status             int
	}{
		{"HTML", "synthetic-private-response", "", 404},
		{"missing credentials", `<plist><dict/></plist>`, "", 200},
		{"failure", `<plist><dict><key>failureType</key><string>synthetic-private-response</string></dict></plist>`, "", 200},
		{"conflicting dsid", syntheticAppStoreLogin, "X-Dsid=99999; Path=/", 200},
		{"conflicting token identity", syntheticAppStoreLogin, "mz_mt0-99999=value; Path=/", 200},
		{"invalid pod", syntheticAppStoreLogin, "itspod=p@example.invalid; Path=/", 200},
		{"whitespace pod", syntheticAppStoreLogin, "itspod= 42; Path=/", 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodGet {
					return nativeTestBag(req, ""), nil
				}
				res := appStoreTestResponse(req, tc.status, "text/html", tc.body)
				if tc.cookie != "" {
					res.Header.Add("Set-Cookie", tc.cookie)
				}
				return res, nil
			})
			err := as.bridgeNativeSession("synthetic@example.invalid", "020000000001", nativeTestSession(), nativeTestHeaders(), syntheticNativeSigner)
			if err == nil || strings.Contains(err.Error(), "synthetic-private-response") || as.token != "" {
				t.Fatalf("err=%v published=%v", err, as.token != "")
			}
		})
	}
}

func TestNativeAppStoreActivation(t *testing.T) {
	requests := 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) { requests++; return nativeTestBag(req, ""), nil })
	if err := as.bridgeNativeSession("synthetic@example.invalid", "020000000001", nil, nativeTestHeaders(), syntheticNativeSigner); err == nil || requests != 0 {
		t.Fatalf("missing session dispatched: %v", err)
	}
	signErr := errors.New("synthetic signing error")
	err := as.bridgeNativeSession("synthetic@example.invalid", "020000000001", nativeTestSession(), nativeTestHeaders(), func(context.Context, []byte) ([]byte, error) { return nil, signErr })
	if !errors.Is(err, signErr) || requests != 1 {
		t.Fatalf("unsigned dispatch: requests=%d err=%v", requests, err)
	}
	if _, err := parseNativeAuthEndpoint("https://auth.itunes.apple.com/%61uth/v1/native"); err == nil {
		t.Error("accepted encoded native path")
	}
	base, _ := url.Parse("https://auth.itunes.apple.com/auth/v1/native/fast/")
	if next, err := resolveNativeAuthRedirect(base, "?route=a%2Fb+c"); err != nil || next.RawQuery != "route=a%2Fb+c" {
		t.Fatalf("query redirect=%v %v", next, err)
	}
}

func TestNativeAppStoreUnavailableFallsBack(t *testing.T) {
	requests := 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		requests++
		if req.Method == http.MethodGet {
			return nativeTestBag(req, ""), nil
		}
		return appStoreTestResponse(req, 200, "text/xml", syntheticAppStoreLogin), nil
	})
	err := as.authenticateWithFallback("synthetic@example.invalid", "synthetic-password", fmt.Errorf("native headers: %w", storeauth.ErrGrandSlamUnavailable))
	if err != nil || requests != 2 || as.token != "synthetic-token" {
		t.Fatalf("fallback requests=%d err=%v", requests, err)
	}
	for _, failure := range []error{context.Canceled, context.DeadlineExceeded, storeauth.ErrGrandSlamInvalidCredentials, storeauth.ErrInvalidTwoFactorCode, errors.New("signed Store login rejected")} {
		requests = 0
		err := as.authenticateWithFallback("synthetic@example.invalid", "synthetic-password", failure)
		if !errors.Is(err, failure) || requests != 0 {
			t.Fatalf("hard failure retried: requests=%d err=%v", requests, err)
		}
	}
}

type fakeGrandSlam struct {
	steps     []string
	challenge *storeauth.GrandSlamChallenge
	trusted   *storeauth.GrandSlamSession
	submitErr error
}

func (g *fakeGrandSlam) Login(context.Context, string, string) (*storeauth.GrandSlamSession, error) {
	g.steps = append(g.steps, "login")
	if len(g.steps) == 1 {
		return nil, g.challenge
	}
	return g.trusted, nil
}
func (g *fakeGrandSlam) TriggerTwoFactor(context.Context, *storeauth.GrandSlamChallenge) error {
	g.steps = append(g.steps, "trigger")
	return nil
}
func (g *fakeGrandSlam) SubmitTwoFactor(_ context.Context, c *storeauth.GrandSlamChallenge, code string) error {
	g.steps = append(g.steps, "submit")
	if c != g.challenge || code != "123456" {
		return errors.New("wrong challenge/code")
	}
	return g.submitErr
}

func TestNativeAppStoreTwoFactorSession(t *testing.T) {
	as := NewAppStore(&AppStoreConfig{Context: t.Context()})
	gsa := &fakeGrandSlam{challenge: &storeauth.GrandSlamChallenge{ADSID: "synthetic-adsid", IDMSToken: "synthetic-idms"}, trusted: nativeTestSession()}
	session, err := as.grandSlamSession(gsa, "synthetic@example.invalid", "synthetic-password", func() (string, error) { gsa.steps = append(gsa.steps, "prompt"); return "123456", nil })
	if err != nil || session != gsa.trusted || strings.Join(gsa.steps, ",") != "login,trigger,prompt,submit,login" {
		t.Fatalf("steps=%v err=%v", gsa.steps, err)
	}
	gsa.steps = nil
	gsa.submitErr = errors.New("synthetic verification rejection")
	_, err = as.grandSlamSession(gsa, "synthetic@example.invalid", "synthetic-password", func() (string, error) { return "123456", nil })
	if !errors.Is(err, gsa.submitErr) || strings.Join(gsa.steps, ",") != "login,trigger,submit" {
		t.Fatalf("steps=%v err=%v", gsa.steps, err)
	}
}
