//go:build !ios

package download

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/99designs/keyring"
	"github.com/blacktop/ipsw/internal/storeauth"
)

const syntheticAppStoreLogin = `<plist version="1.0"><dict><key>dsPersonId</key><string>12345</string><key>passwordToken</key><string>synthetic-token</string></dict></plist>`

func (as *AppStore) signInRequest(username, password, code string, attempt int, pod, endpoint string, triedFallback bool, readCode func() (string, error), sign appStoreRequestSigner) error {
	return as.signInAttempt(username, password, code, attempt, pod, endpoint, triedFallback, readCode, sign, 0, 0, "")
}

func newTestAppStore(t *testing.T, roundTrip func(*http.Request) (*http.Response, error)) *AppStore {
	t.Helper()
	stored, err := json.Marshal(AppleAccountAuth{
		Credentials: credentials{Username: "synthetic@example.invalid", Password: "synthetic-password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	as := NewAppStore(&AppStoreConfig{Context: t.Context()})
	as.Client.Transport = adcRoundTripFunc(roundTrip)
	as.Vault = keyring.NewArrayKeyring([]keyring.Item{{Key: VaultName, Data: stored}})
	t.Cleanup(as.Close)
	return as
}

func appStoreTestResponse(req *http.Request, status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     http.Header{"Content-Type": {contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func TestAppStoreLoginRedirect(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, location := range []string{"/auth/v1/native/finish", "https://p42-buy.itunes.apple.com" + appStoreAuthPath} {
			t.Run(fmt.Sprintf("%d/%s", status, location), func(t *testing.T) {
				calls := 0
				as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Method != http.MethodPost {
						t.Errorf("method = %s, want POST", req.Method)
					}
					body, err := io.ReadAll(req.Body)
					if err != nil {
						return nil, err
					}
					var login loginRequest
					if err := decodePlistResponse(body, &login); err != nil {
						return nil, err
					}
					if login.Password != "synthetic-password123456" || login.Attempt != fmt.Sprint(calls) {
						t.Errorf("redirect did not preserve credentials and increment the attempt")
					}
					if calls == 1 {
						res := appStoreTestResponse(req, status, "text/html", "<html>redirect</html>")
						res.Header.Set("Location", location)
						res.Header.Set("pod", "42")
						res.Header.Set("X-Set-Apple-Store-Front", "123456-1,1")
						return res, nil
					}
					want := location
					if strings.HasPrefix(want, "/") {
						want = appStoreURL(appStoreAuthHost, want)
					}
					if req.URL.String() != want {
						t.Errorf("redirect endpoint = %s, want %s", req.URL, want)
					}
					return appStoreTestResponse(req, http.StatusOK, "text/xml", syntheticAppStoreLogin), nil
				})
				if err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "123 456", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false, readAppStoreCode, nil); err != nil {
					t.Fatal(err)
				}
				if calls != 2 || as.pod != "42" || as.storeFront != "123456-1,1" || as.token != "synthetic-token" {
					t.Errorf("login did not retain redirect routing and session state (calls=%d)", calls)
				}
			})
		}
	}
}

func TestAppStoreLoginLegacyFallback(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusForbidden, http.StatusNotFound, http.StatusMovedPermanently} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			posts, bags := 0, 0
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				if req.Method == http.MethodGet {
					bags++
					return appStoreTestResponse(req, http.StatusOK, "text/xml", `<plist version="1.0"><dict><key>authenticateAccount</key><string>`+appStoreURL(appStoreBuyHost, appStoreAuthPath)+`</string></dict></plist>`), nil
				}
				posts++
				if posts == 1 {
					if req.URL.String() != appStoreURL(appStoreBuyHost, appStoreAuthPath) {
						t.Errorf("initial endpoint = %s", req.URL)
					}
					body := "<html>missing endpoint</html>"
					if status == http.StatusNoContent {
						body = ""
					}
					return appStoreTestResponse(req, status, "text/html", body), nil
				}
				if req.URL.String() != appStoreURL(appStoreAuthHost, appStoreAuthNativePath) {
					t.Errorf("fallback endpoint = %s", req.URL)
				}
				return appStoreTestResponse(req, http.StatusOK, "text/xml", syntheticAppStoreLogin), nil
			})
			if err := as.signIn("synthetic@example.invalid", "synthetic-password", "", 1, "", nil); err != nil {
				t.Fatal(err)
			}
			if posts != 2 || bags != 1 || as.token != "synthetic-token" {
				t.Errorf("fallback posts=%d bags=%d; want one bag and two login requests", posts, bags)
			}
		})
	}
}

func TestDecodePlistResponseRejectsEmptyBody(t *testing.T) {
	for _, body := range []string{"", " \n\t"} {
		var response loginResponse
		if err := decodePlistResponse([]byte(body), &response); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("empty response error = %v", err)
		}
	}
}

func TestDecodePlistResponsePreservesBinary(t *testing.T) {
	// The offset table starts at 0x20, so the last trailer byte is an ASCII
	// space. Trimming the transport body would corrupt this valid binary plist.
	body, err := hex.DecodeString("62706c6973743030d101025576616c75655e7878787878787878787878787878080b110000000000000101000000000000000300000000000000000000000000000020")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := decodePlistResponse(body, &got); err != nil || got["value"] != strings.Repeat("x", 14) {
		t.Fatalf("binary response=%v error=%v", got, err)
	}
}

func TestAppStoreRejectsUnsafePods(t *testing.T) {
	const unsafePod = "2.example.invalid/"
	t.Run("login response", func(t *testing.T) {
		posts := 0
		as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
			posts++
			res := appStoreTestResponse(req, 200, "text/xml", syntheticAppStoreLogin)
			res.Header.Set("pod", unsafePod)
			return res, nil
		})
		as.pod = "42"
		err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "42", appStoreURL(appStoreBuyHost, appStoreAuthPath), false, nil, syntheticNativeSigner)
		if err == nil || posts != 1 || as.pod != "42" || as.token != "" || strings.Contains(err.Error(), unsafePod) {
			t.Fatalf("unsafe response changed authentication state: posts=%d error=%v", posts, err)
		}
	})
	t.Run("saved session", func(t *testing.T) {
		as := newTestAppStore(t, func(*http.Request) (*http.Response, error) {
			t.Fatal("loading a session sent a request")
			return nil, nil
		})
		stored, err := json.Marshal(AppleAccountAuth{
			Credentials:     credentials{Username: "synthetic@example.invalid", DsPersonID: "12345", PasswordToken: "synthetic-token", Pod: unsafePod},
			AppStoreSession: session{Cookies: []*http.Cookie{{Name: "mz_at0", Value: "synthetic-cookie", Domain: "itunes.apple.com", Path: "/", Secure: true}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := as.Vault.Set(keyring.Item{Key: VaultName, Data: stored}); err != nil {
			t.Fatal(err)
		}
		as.pod = "42"
		err = as.loadSession()
		if err == nil || as.pod != "42" || as.token != "" || len(as.Client.Jar.Cookies(&url.URL{Scheme: "https", Host: appStoreBuyHost})) != 0 || strings.Contains(err.Error(), unsafePod) {
			t.Fatalf("unsafe saved session changed authentication state: %v", err)
		}
	})
}

func TestSignedAppStoreLogin(t *testing.T) {
	posts, signs, prompts := 0, 0, 0
	var first []byte
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		posts++
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		signature, _ := syntheticNativeSigner(t.Context(), body)
		if req.Header.Get("X-Apple-ActionSignature") != base64.StdEncoding.EncodeToString(signature) || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("password request lost its signature or content type")
		}
		if posts == 1 {
			first = body
		} else if posts <= 3 && !bytes.Equal(first, body) {
			t.Error("routing or transport retry changed the signed body")
		}
		var login loginRequest
		if err := decodePlistResponse(body, &login); err != nil {
			return nil, err
		}
		wantPassword := "synthetic-password"
		if posts == 4 {
			wantPassword += "123456"
		}
		wantAttempt := "1"
		if posts == 4 {
			wantAttempt = "2"
		}
		if login.Attempt != wantAttempt || login.Password != wantPassword {
			t.Error("password retry did not encode the expected attempt and code")
		}
		switch posts {
		case 1:
			return appStoreTestResponse(req, 204, "text/html", ""), nil
		case 2:
			res := appStoreTestResponse(req, 302, "text/html", "")
			res.Header.Set("Location", "https://p42-buy.itunes.apple.com"+appStoreAuthPath+"/")
			return res, nil
		case 3:
			return appStoreTestResponse(req, 200, "text/xml", `<plist><dict><key>customerMessage</key><string>`+ErrLoginRequires2fa+`</string></dict></plist>`), nil
		default:
			return appStoreTestResponse(req, 200, "text/xml", syntheticAppStoreLogin), nil
		}
	})
	signer := func(ctx context.Context, body []byte) ([]byte, error) {
		signs++
		return syntheticNativeSigner(ctx, body)
	}
	readCode := func() (string, error) { prompts++; return "123 456", nil }
	if err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreBuyHost, appStoreAuthPath), false, readCode, signer); err != nil {
		t.Fatal(err)
	}
	if posts != 4 || signs != 4 || prompts != 1 || as.token != "synthetic-token" {
		t.Errorf("posts=%d signs=%d prompts=%d", posts, signs, prompts)
	}
}

func TestSignedAppStoreRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		status       int
		wait         time.Duration
		tooLong      bool
	}{
		{"seconds", "7", 429, 7 * time.Second, false},
		{"date", "Sat, 01 Jan 2000 00:00:09 GMT", 503, 9 * time.Second, false},
		{"invalid", "later", 429, time.Second, false},
		{"zero", "0", 429, time.Second, false},
		{"past", "Fri, 31 Dec 1999 23:59:59 GMT", 429, time.Second, false},
		{"at limit", "60", 429, maxSAPRetryDelay, false},
		{"over limit", "61", 429, 0, true},
		{"date over limit", "Sat, 01 Jan 2000 00:01:01 GMT", 429, 0, true},
		{"overflow", "18446744073709551616", 429, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				posts := 0
				as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
					posts++
					if posts == 1 {
						res := appStoreTestResponse(req, tc.status, "text/html", "")
						res.Header.Set("Retry-After", tc.header)
						return res, nil
					}
					return appStoreTestResponse(req, 200, "text/xml", syntheticAppStoreLogin), nil
				})
				err := as.signInAttempt("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreBuyHost, appStoreAuthPath), false, nil, syntheticNativeSigner, 0, 0, "020000000001")
				if tc.tooLong {
					if err == nil || !strings.Contains(err.Error(), "try again later") || posts != 1 {
						t.Fatalf("retried before the server deadline: posts=%d err=%v", posts, err)
					}
				} else if err != nil || posts != 2 || as.token != "synthetic-token" {
					t.Fatalf("retry failed: posts=%d err=%v", posts, err)
				}
				if elapsed := time.Since(start); elapsed != tc.wait {
					t.Fatalf("waited %s, want %s", elapsed, tc.wait)
				}
			})
		})
	}
	t.Run("canceled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			start := time.Now()
			if err := waitAppStoreAuthRetry(ctx, 0, "30"); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) != 3*time.Second {
				t.Fatalf("retry wait ignored cancellation: %v", err)
			}
			if err := waitAppStoreAuthRetry(ctx, 0, "61"); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("server delay hid an existing cancellation: %v", err)
			}
		})
	})
	t.Run("exhausted", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			start := time.Now()
			posts := 0
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				posts++
				res := appStoreTestResponse(req, 429, "text/html", "")
				res.Header.Set("Retry-After", "2")
				return res, nil
			})
			err := as.signInAttempt("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreBuyHost, appStoreAuthPath), false, nil, syntheticNativeSigner, 0, 0, "020000000001")
			if err == nil || posts != maxSAPRequestAttempts || time.Since(start) != 4*time.Second {
				t.Fatalf("retry limit changed: posts=%d elapsed=%s err=%v", posts, time.Since(start), err)
			}
		})
	})
}

func TestSignedAppStoreLoginStopsBeforeDispatch(t *testing.T) {
	posts, signs := 0, 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		posts++
		res := appStoreTestResponse(req, 302, "text/html", "")
		res.Header.Set("Location", "https://pbad-auth.itunes.apple.com/auth/v1/native/fast/")
		return res, nil
	})
	signer := func(ctx context.Context, body []byte) ([]byte, error) {
		signs++
		return syntheticNativeSigner(ctx, body)
	}
	err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreBuyHost, appStoreAuthPath), false, nil, signer)
	if err == nil || posts != 1 || signs != 1 {
		t.Errorf("unsafe redirect posts=%d signs=%d error=%v", posts, signs, err)
	}
	signFailure := errors.New("synthetic signing failure")
	err = as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreBuyHost, appStoreAuthPath), false, nil, func(context.Context, []byte) ([]byte, error) { return nil, signFailure })
	if !errors.Is(err, signFailure) || posts != 1 {
		t.Errorf("failed signer posts=%d error=%v", posts, err)
	}
}

func TestSAPAuthEndpoint(t *testing.T) {
	for _, version := range []string{"200", "210", ""} {
		as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
			return appStoreTestResponse(req, 200, "text/xml", `<plist><dict><key>authenticateAccount</key><string>https://auth.itunes.apple.com/auth/v1/native/</string><key>urlBag</key><dict><key>authenticateAccount</key><string>https://p42-buy.itunes.apple.com`+appStoreAuthPath+`?route=synthetic</string><key>sign-sap-version</key><string>`+version+`</string></dict></dict></plist>`), nil
		})
		endpoint, err := as.resolveSAPAuthEndpoint("020000000001")
		if version == "200" {
			if err != nil || endpoint != "https://p42-buy.itunes.apple.com"+appStoreAuthPath+"/?route=synthetic" {
				t.Errorf("endpoint=%q error=%v", endpoint, err)
			}
		} else if err == nil {
			t.Errorf("accepted SAP version %q", version)
		}
	}
	base, err := parseSAPAuthEndpoint(appStoreURL(appStoreBuyHost, appStoreAuthPath+"/"))
	if err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{
		"https://auth.itunes.apple.com/auth/v1/native/fast/",
		"https://p42-buy.itunes.apple.com/unrelated",
		"https://pbad-buy.itunes.apple.com" + appStoreAuthPath,
		appStoreAuthPath + "/../authenticate/",
		"/WebObjects/MZFinance.woa/wa/%61uthenticate/",
		appStoreAuthPath + "/#fragment",
	} {
		if _, err := resolveSAPAuthRedirect(base, destination); err == nil {
			t.Errorf("accepted unsafe SAP redirect %q", destination)
		}
	}
}

func TestAppStoreLoginHTTPError(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusForbidden, http.StatusNotFound, http.StatusOK} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			calls := 0
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				calls++
				return appStoreTestResponse(req, status, "text/html", "<html>synthetic-private-response</html>"), nil
			})
			err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false, readAppStoreCode, nil)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) || !strings.Contains(err.Error(), "text/html") || strings.Contains(err.Error(), "synthetic-private-response") {
				t.Errorf("error = %v, want HTTP metadata without response data", err)
			}
			if calls != 1 {
				t.Errorf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestAppStoreLogin404Challenge(t *testing.T) {
	endpoint := appStoreURL(appStoreBuyHost, appStoreAuthPath)
	calls := 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if req.URL.String() != endpoint {
			t.Errorf("2FA endpoint changed to %s", req.URL)
		}
		if calls == 1 {
			return appStoreTestResponse(req, http.StatusNotFound, "text/xml", `<plist version="1.0"><dict><key>customerMessage</key><string>`+ErrLoginRequires2fa+`</string></dict></plist>`), nil
		}
		return appStoreTestResponse(req, http.StatusOK, "text/xml", syntheticAppStoreLogin), nil
	})
	if err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "", endpoint, false, func() (string, error) { return "123456", nil }, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || as.token != "synthetic-token" {
		t.Errorf("2FA challenge made %d requests, want 2 and a saved session", calls)
	}
}

func TestAppStoreLoginDelayedNativeCode(t *testing.T) {
	const password = "synthetic password"
	const ambiguous = `<plist><dict><key>failureType</key><string>5020</string><key>customerMessage</key><string>Did you forget your password?</string></dict></plist>`
	posts, prompts := 0, 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		posts++
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		var login loginRequest
		if err := decodePlistResponse(body, &login); err != nil {
			return nil, err
		}
		wantPassword := password
		if posts == 3 {
			wantPassword += "123456"
		}
		if login.Password != wantPassword || login.Attempt != fmt.Sprint(posts) {
			t.Error("authentication changed the password or attempt")
		}
		if posts == 1 {
			if req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("legacy content type changed")
			}
			return appStoreTestResponse(req, 404, "text/html", "<html>retired</html>"), nil
		}
		if req.URL.String() != appStoreURL(appStoreAuthHost, appStoreAuthNativePath) || req.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("native request profile changed")
		}
		if posts == 2 {
			res := appStoreTestResponse(req, 200, "text/xml", ambiguous)
			res.Header.Add("Set-Cookie", "synthetic-auth=challenge; Path=/; Secure")
			return res, nil
		}
		cookie, err := req.Cookie("synthetic-auth")
		if err != nil || cookie.Value != "challenge" {
			t.Error("verification lost the authentication cookie")
		}
		return appStoreTestResponse(req, 200, "text/xml", syntheticAppStoreLogin), nil
	})
	err := as.signInRequest("synthetic@example.invalid", password, "", 1, "", appStoreURL(appStoreBuyHost, appStoreAuthPath), false, func() (string, error) {
		prompts++
		return "\x1b[200~123\u00a0456\x1b[201~\n", nil
	}, nil)
	if err != nil || posts != 3 || prompts != 1 || as.token != "synthetic-token" {
		t.Fatalf("posts=%d prompts=%d err=%v", posts, prompts, err)
	}
}

func TestAppStoreLoginNativeCodeDoesNotLoop(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		wantPosts   int
		invalidCode bool
	}{
		{"declined", "", 1, false},
		{"malformed", "private-code-sentinel", 1, true},
		{"rejected", "123456", 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			posts, prompts := 0, 0
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				posts++
				return appStoreTestResponse(req, 200, "text/xml", `<plist><dict><key>failureType</key><string>5020</string><key>customerMessage</key><string>Did you forget your password?</string></dict></plist>`), nil
			})
			err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false, func() (string, error) {
				prompts++
				return tc.input, nil
			}, nil)
			if err == nil || posts != tc.wantPosts || prompts != 1 || strings.Contains(err.Error(), "private-code-sentinel") || errors.Is(err, storeauth.ErrInvalidTwoFactorCode) != tc.invalidCode {
				t.Fatalf("posts=%d prompts=%d err=%v", posts, prompts, err)
			}
		})
	}
}

func TestAppStoreLoginRejectsMalformedCodeBeforeNetwork(t *testing.T) {
	requests := 0
	as := newTestAppStore(t, func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected request")
	})
	err := as.signIn("synthetic@example.invalid", "synthetic-password", "private-code-sentinel", 1, "", nil)
	if !errors.Is(err, storeauth.ErrInvalidTwoFactorCode) || requests != 0 || strings.Contains(err.Error(), "private-code-sentinel") {
		t.Fatalf("requests=%d err=%v", requests, err)
	}
}

func TestAppStoreLoginDoesNotPromptForPlainCredentialFailure(t *testing.T) {
	requests, prompts := 0, 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		requests++
		return appStoreTestResponse(req, 200, "text/xml", `<plist><dict><key>failureType</key><string>-5000</string><key>customerMessage</key><string>Invalid credentials</string></dict></plist>`), nil
	})
	err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false, func() (string, error) {
		prompts++
		return "123456", nil
	}, nil)
	if err == nil || requests != 2 || prompts != 0 {
		t.Fatalf("requests=%d prompts=%d err=%v", requests, prompts, err)
	}
}

func TestAppStoreLoginDoesNotConsumeCodeAfterAttemptLimit(t *testing.T) {
	for _, body := range []string{
		`<plist><dict><key>customerMessage</key><string>` + ErrLoginRequires2fa + `</string></dict></plist>`,
		`<plist><dict><key>failureType</key><string>5020</string></dict></plist>`,
	} {
		requests, prompts := 0, 0
		as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
			requests++
			return appStoreTestResponse(req, 200, "text/xml", body), nil
		})
		err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 4, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false, func() (string, error) {
			prompts++
			return "123456", nil
		}, nil)
		if err == nil || err.Error() != "too many authentication attempts" || requests != 1 || prompts != 0 {
			t.Fatalf("requests=%d prompts=%d err=%v", requests, prompts, err)
		}
	}
}

func TestAppStoreLoginInitialRetryKeepsProvidedCode(t *testing.T) {
	requests, prompts := 0, 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		requests++
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		var login loginRequest
		if err := decodePlistResponse(body, &login); err != nil {
			return nil, err
		}
		if login.Password != "synthetic-password123456" {
			t.Error("first-attempt workaround lost the verification code")
		}
		if requests == 1 {
			return appStoreTestResponse(req, 200, "text/xml", `<plist><dict><key>failureType</key><string>-5000</string></dict></plist>`), nil
		}
		return appStoreTestResponse(req, 200, "text/xml", syntheticAppStoreLogin), nil
	})
	err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "123 456", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false, func() (string, error) {
		prompts++
		return "", nil
	}, nil)
	if err != nil || requests != 2 || prompts != 0 || as.token != "synthetic-token" {
		t.Fatalf("requests=%d prompts=%d err=%v", requests, prompts, err)
	}
}

func TestAppStoreLoginRedirectLimit(t *testing.T) {
	calls := 0
	as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
		calls++
		res := appStoreTestResponse(req, http.StatusMovedPermanently, "text/html", "<html>redirect</html>")
		res.Header.Set("Location", appStoreAuthNativePath)
		return res, nil
	})
	err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false, readAppStoreCode, nil)
	if err == nil || err.Error() != "too many authentication attempts" || calls != 4 {
		t.Errorf("redirect loop made %d requests and returned %v", calls, err)
	}
}

func TestAppStoreLoginRejectsUnsafeRedirect(t *testing.T) {
	for _, location := range []string{
		"http://auth.itunes.apple.com/auth/v1/native/fast/",
		"https://auth.itunes.apple.com.example.invalid/",
		"https://auth.itunes.apple.com@other.example.invalid/",
		"https://auth.itunes.apple.com:8443/",
		"https://p42-buy.itunes.apple.com.example.invalid/",
	} {
		t.Run(location, func(t *testing.T) {
			calls := 0
			as := newTestAppStore(t, func(req *http.Request) (*http.Response, error) {
				calls++
				res := appStoreTestResponse(req, http.StatusTemporaryRedirect, "text/html", "<html>redirect</html>")
				res.Header.Set("Location", location)
				return res, nil
			})
			if err := as.signInRequest("synthetic@example.invalid", "synthetic-password", "", 1, "", appStoreURL(appStoreAuthHost, appStoreAuthNativePath), false, readAppStoreCode, nil); err == nil {
				t.Error("unsafe redirect succeeded")
			}
			if calls != 1 {
				t.Errorf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestNormalizeAuthEndpoint(t *testing.T) {
	for _, tc := range []struct{ endpoint, want string }{
		{"https://auth.itunes.apple.com/auth/v1/native", appStoreURL(appStoreAuthHost, appStoreAuthNativePath)},
		{"https://auth.itunes.apple.com/auth/v1/native/", appStoreURL(appStoreAuthHost, appStoreAuthNativePath)},
		{"https://auth.itunes.apple.com/auth/v1/native/fast?source=synthetic", appStoreURL(appStoreAuthHost, appStoreAuthNativePath) + "?source=synthetic"},
		{"https://auth.itunes.apple.com/auth/v1/native/finish", "https://auth.itunes.apple.com/auth/v1/native/finish"},
		{"https://other.example.invalid/auth.itunes.apple.com", "https://other.example.invalid/auth.itunes.apple.com"},
		{appStoreURL(appStoreBuyHost, appStoreAuthPath), appStoreURL(appStoreBuyHost, appStoreAuthPath)},
	} {
		if got := normalizeAuthEndpoint(tc.endpoint); got != tc.want {
			t.Errorf("normalizeAuthEndpoint(%q) = %q, want %q", tc.endpoint, got, tc.want)
		}
	}
}
