package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testUUID = "AAAABBBB-CCCC-DDDD-EEEE-FFFF00001111"
	testAddr = 4096
)

// recordedRequest captures the wire shape of a single symbol server request.
type recordedRequest struct {
	method string
	path   string
	query  string
	auth   []string
	body   int64
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(buf []byte) (int, error) {
	return f(buf)
}

// newMockSymbolServer returns a service that answers the six symbol server
// endpoints with synthetic payloads and records every request it receives.
func newMockSymbolServer(t *testing.T) (*httptest.Server, *[]recordedRequest) {
	t.Helper()
	var got []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, recordedRequest{
			method: r.Method,
			path:   r.URL.Path,
			query:  r.URL.RawQuery,
			auth:   r.Header.Values("Authorization"),
			body:   r.ContentLength,
		})
		switch {
		case r.URL.Path == "/v1/_ping", r.URL.Path == "/v1/syms/ipsw":
			w.WriteHeader(http.StatusOK)
		case strings.HasPrefix(r.URL.Path, "/v1/syms/macho/"):
			fmt.Fprint(w, `{"uuid":"`+testUUID+`","Path":{"path":"/usr/lib/synthetic.dylib"},"text_start":4096}`)
		case r.URL.Path == "/v1/syms/dsc/"+testUUID:
			fmt.Fprint(w, `{"uuid":"`+testUUID+`","shared_region_start":6442450944}`)
		case r.URL.Path == fmt.Sprintf("/v1/syms/dsc/%s/%d", testUUID, testAddr):
			fmt.Fprint(w, `{"uuid":"`+testUUID+`","Path":{"path":"/usr/lib/synthetic-dylib-in-cache.dylib"}}`)
		case r.URL.Path == fmt.Sprintf("/v1/syms/%s/%d", testUUID, testAddr):
			fmt.Fprint(w, `{"start":4096,"end":4200,"Name":{"name":"_synthetic_symbol"}}`)
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

// exerciseAll calls every symbol server endpoint once, failing on any error so a
// broken request shape surfaces as a test failure rather than a silent skip.
func exerciseAll(t *testing.T, s *Server) {
	t.Helper()
	if err := s.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if ok, err := s.HasIPSW("17.4", "21E219", "iPad14,3"); err != nil || !ok {
		t.Fatalf("HasIPSW: ok=%v err=%v", ok, err)
	}
	if m, err := s.GetMachO(testUUID); err != nil || m.GetPath() != "/usr/lib/synthetic.dylib" {
		t.Fatalf("GetMachO: %+v err=%v", m, err)
	}
	if dsc, err := s.GetDSC(testUUID); err != nil || dsc.SharedRegionStart != 6442450944 {
		t.Fatalf("GetDSC: %+v err=%v", dsc, err)
	}
	if img, err := s.GetDSCImage(testUUID, testAddr); err != nil || img.GetPath() != "/usr/lib/synthetic-dylib-in-cache.dylib" {
		t.Fatalf("GetDSCImage: %+v err=%v", img, err)
	}
	if sym, err := s.GetSymbol(testUUID, testAddr); err != nil || sym.GetName() != "_synthetic_symbol" {
		t.Fatalf("GetSymbol: %+v err=%v", sym, err)
	}
}

// wantShapes is the unchanged request contract: six bodyless GETs.
var wantShapes = []struct{ path, query string }{
	{"/v1/_ping", ""},
	{"/v1/syms/ipsw", "build=21E219&device=iPad14%2C3&version=17.4"},
	{"/v1/syms/macho/" + testUUID, ""},
	{"/v1/syms/dsc/" + testUUID, ""},
	{fmt.Sprintf("/v1/syms/dsc/%s/%d", testUUID, testAddr), ""},
	{fmt.Sprintf("/v1/syms/%s/%d", testUUID, testAddr), ""},
}

func assertShapes(t *testing.T, got []recordedRequest) {
	t.Helper()
	if len(got) != len(wantShapes) {
		t.Fatalf("got %d requests, want %d", len(got), len(wantShapes))
	}
	for i, want := range wantShapes {
		if got[i].method != http.MethodGet {
			t.Errorf("request %d: method = %q, want GET", i, got[i].method)
		}
		if got[i].path != want.path {
			t.Errorf("request %d: path = %q, want %q", i, got[i].path, want.path)
		}
		if got[i].query != want.query {
			t.Errorf("request %d: query = %q, want %q", i, got[i].query, want.query)
		}
		if got[i].body > 0 {
			t.Errorf("request %d: sent %d body bytes, want bodyless", i, got[i].body)
		}
	}
}

func TestNewServerSendsNoAuthorization(t *testing.T) {
	srv, got := newMockSymbolServer(t)

	exerciseAll(t, NewServer(srv.URL))

	assertShapes(t, *got)
	for i, r := range *got {
		if len(r.auth) != 0 {
			t.Errorf("request %d (%s): sent Authorization %q, want none", i, r.path, r.auth)
		}
	}
}

func TestNewServerWithTokenSendsBearer(t *testing.T) {
	const token = "sYnth3t1c.T0ken_VALUE-123"
	srv, got := newMockSymbolServer(t)

	s, err := NewServerWithToken(srv.URL, token)
	if err != nil {
		t.Fatalf("NewServerWithToken: %v", err)
	}
	exerciseAll(t, s)

	assertShapes(t, *got)
	for i, r := range *got {
		if len(r.auth) != 1 || r.auth[0] != "Bearer "+token {
			t.Errorf("request %d (%s): Authorization = %q, want exactly [%q]", i, r.path, r.auth, "Bearer "+token)
		}
	}
}

func TestNewServerWithEmptyTokenIsUnauthenticated(t *testing.T) {
	srv, got := newMockSymbolServer(t)

	s, err := NewServerWithToken(srv.URL, "")
	if err != nil {
		t.Fatalf("NewServerWithToken(empty): %v", err)
	}
	exerciseAll(t, s)

	assertShapes(t, *got)
	for i, r := range *got {
		if len(r.auth) != 0 {
			t.Errorf("request %d (%s): sent Authorization %q, want none", i, r.path, r.auth)
		}
	}
}

func TestHasIPSWStatusHandling(t *testing.T) {
	for name, tc := range map[string]struct {
		status  int
		wantErr bool
	}{
		"not found":    {status: http.StatusNotFound},
		"unauthorized": {status: http.StatusUnauthorized, wantErr: true},
		"forbidden":    {status: http.StatusForbidden, wantErr: true},
		"server error": {status: http.StatusInternalServerError, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)

			ok, err := NewServer(srv.URL).HasIPSW("17.4", "21E219", "iPad14,3")
			if ok {
				t.Error("HasIPSW reported data present")
			}
			if tc.wantErr && err == nil {
				t.Fatalf("HasIPSW status %d: want error, got nil", tc.status)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("HasIPSW status %d: %v", tc.status, err)
			}
			if err != nil && !strings.Contains(err.Error(), strconv.Itoa(tc.status)) {
				t.Errorf("error omits status %d: %v", tc.status, err)
			}
		})
	}
}

// secret is a distinctive marker embedded in every malformed token: no
// validation error may echo it back.
const secret = "Zx9q7Kv2Ln"

// malformedTokens covers each rejection rule with a token carrying secret.
var malformedTokens = map[string]string{
	"leading space":     " " + secret,
	"trailing space":    secret + " ",
	"leading tab":       "\t" + secret,
	"trailing newline":  secret + "\n",
	"embedded space":    secret + " " + secret,
	"embedded tab":      secret + "\t" + secret,
	"embedded cr":       secret + "\r" + secret,
	"embedded lf":       secret + "\n" + secret,
	"embedded comma":    secret + "," + secret,
	"embedded nul":      secret + "\x00" + secret,
	"embedded vtab":     secret + "\v" + secret,
	"embedded formfeed": secret + "\f" + secret,
	"embedded del":      secret + "\x7f" + secret,
	"header injection":  secret + "\r\nX-Evil: 1",
}

func TestNewServerWithTokenRejectsMalformedBeforeTransport(t *testing.T) {
	srv, got := newMockSymbolServer(t)

	for name, token := range malformedTokens {
		s, err := NewServerWithToken(srv.URL, token)
		if err == nil {
			t.Errorf("NewServerWithToken(%s): want error, got nil", name)
			continue
		}
		if s != nil {
			t.Errorf("NewServerWithToken(%s): want nil server on error", name)
		}
		if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error leaks the token: %v", name, err)
		}
	}
	if len(*got) != 0 {
		t.Errorf("malformed tokens reached the service: %d requests", len(*got))
	}
}

func TestValidateTokenRejectsMalformed(t *testing.T) {
	for name, token := range malformedTokens {
		t.Run(name, func(t *testing.T) {
			err := ValidateToken(token)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks the token: %v", err)
			}
		})
	}
	t.Run("only whitespace", func(t *testing.T) {
		if err := ValidateToken("   "); err == nil {
			t.Fatal("want error, got nil")
		}
	})
}

func TestValidateTokenRejectsEveryHTTPControlByte(t *testing.T) {
	controls := make([]byte, 0, 33)
	for b := range byte(' ') {
		controls = append(controls, b)
	}
	controls = append(controls, 0x7f)

	for _, control := range controls {
		t.Run(fmt.Sprintf("0x%02x", control), func(t *testing.T) {
			token := secret + string([]byte{control}) + "suffix"
			err := ValidateToken(token)
			if err == nil {
				t.Fatal("want error, got nil")
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks the token: %v", err)
			}
		})
	}
}

func TestValidateTokenAccepts(t *testing.T) {
	for name, token := range map[string]string{
		"empty is unauthenticated": "",
		"opaque token":             "abc123",
		"jwt-ish token":            "eyJhbGci.eyJzdWIi.SflKxwRJ",
		"punctuation allowed":      "~/.-_+=/token",
		"long JWT":                 "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + strings.Repeat("a", 128) + "." + strings.Repeat("b", 342),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateToken(token); err != nil {
				t.Fatalf("ValidateToken: %v", err)
			}
		})
	}
}

func TestAuthenticatedServerRejectsUnsafeOrMalformedURL(t *testing.T) {
	const token = "sYnth3t1c.T0ken_VALUE-123"

	for name, rawURL := range map[string]string{
		"HTTP hostname":      "http://symbols.example",
		"HTTP IPv4":          "http://192.0.2.1",
		"HTTP IPv6":          "http://[2001:db8::1]",
		"unsupported scheme": "ftp://symbols.example",
		"missing host":       "https:///v1/syms",
		"malformed URL":      "http://[::1",
	} {
		t.Run(name, func(t *testing.T) {
			s, err := NewServerWithToken(rawURL, token)
			if err == nil {
				t.Fatal("want URL validation error, got nil")
			}
			if s != nil {
				t.Fatal("want nil server on error")
			}
			if strings.Contains(err.Error(), token) {
				t.Errorf("error leaks the token: %v", err)
			}
		})
	}
}

func TestAuthenticatedServerAllowsHTTPSAndLoopbackHTTP(t *testing.T) {
	const token = "sYnth3t1c.T0ken_VALUE-123"

	for name, rawURL := range map[string]string{
		"HTTPS":     "https://symbols.example",
		"localhost": "http://localhost:8080",
		"IPv4":      "http://127.0.0.1:8080",
		"IPv6":      "http://[::1]:8080",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewServerWithToken(rawURL, token); err != nil {
				t.Fatalf("NewServerWithToken: %v", err)
			}
		})
	}

	if _, err := NewServerWithToken("http://symbols.example", ""); err != nil {
		t.Fatalf("unauthenticated HTTP URL rejected: %v", err)
	}
}

func TestAuthenticatedServerPreservesDefaultClientSettings(t *testing.T) {
	const token = "sYnth3t1c.T0ken"
	requested := false
	original := http.DefaultClient
	http.DefaultClient = &http.Client{
		Timeout: 37 * time.Second,
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			requested = true
			if got := req.Header.Get("Authorization"); got != bearerPrefix+token {
				t.Errorf("Authorization = %q, want bearer credential", got)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     make(http.Header),
				Body:       http.NoBody,
				Request:    req,
			}, nil
		}),
	}
	t.Cleanup(func() { http.DefaultClient = original })

	s, err := NewServerWithToken("https://symbols.example", token)
	if err != nil {
		t.Fatalf("NewServerWithToken: %v", err)
	}
	if s.client == http.DefaultClient {
		t.Fatal("authenticated server reused the default client instead of cloning its settings")
	}
	if s.client.Timeout != http.DefaultClient.Timeout {
		t.Errorf("timeout = %s, want %s", s.client.Timeout, http.DefaultClient.Timeout)
	}
	if s.client.CheckRedirect == nil {
		t.Fatal("authenticated server lost its redirect guard")
	}
	if err := s.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !requested {
		t.Fatal("authenticated server did not preserve the default transport")
	}
}

func TestUnauthenticatedServerUsesCurrentDefaultClient(t *testing.T) {
	s := NewServer("http://symbols.example")
	requested := false
	original := http.DefaultClient
	http.DefaultClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requested = true
		if got := req.Header.Values("Authorization"); len(got) != 0 {
			t.Errorf("Authorization = %q, want none", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	})}
	t.Cleanup(func() { http.DefaultClient = original })

	if err := s.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !requested {
		t.Fatal("unauthenticated server did not use the current default client")
	}
}

func TestAuthenticatedServerRevalidatesURLBeforeRequest(t *testing.T) {
	const token = "sYnth3t1c.T0ken_VALUE-123"
	s, err := NewServerWithToken("https://symbols.example", token)
	if err != nil {
		t.Fatalf("NewServerWithToken: %v", err)
	}

	requested := false
	s.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		requested = true
		return nil, errors.New("unexpected request")
	})}
	s.URL = "http://symbols.example"

	err = s.Ping()
	if err == nil {
		t.Fatal("want TLS validation error, got nil")
	}
	if requested {
		t.Fatal("request reached the plaintext transport")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaks the token: %v", err)
	}
}

func TestResponseErrorsIgnoreServerReasonPhrase(t *testing.T) {
	const token = "sYnth3t1c.T0ken_VALUE-123"

	operations := map[string]func(*Server) error{
		"Ping": func(s *Server) error { return s.Ping() },
		"HasIPSW": func(s *Server) error {
			_, err := s.HasIPSW("17.4", "21E219", "iPad14,3")
			return err
		},
		"GetMachO": func(s *Server) error {
			_, err := s.GetMachO(testUUID)
			return err
		},
		"GetDSC": func(s *Server) error {
			_, err := s.GetDSC(testUUID)
			return err
		},
		"GetDSCImage": func(s *Server) error {
			_, err := s.GetDSCImage(testUUID, testAddr)
			return err
		},
		"GetSymbol": func(s *Server) error {
			_, err := s.GetSymbol(testUUID, testAddr)
			return err
		},
	}

	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			s, err := NewServerWithToken("https://symbols.example", token)
			if err != nil {
				t.Fatalf("NewServerWithToken: %v", err)
			}
			s.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if got := req.Header.Get("Authorization"); got != bearerPrefix+token {
					t.Errorf("Authorization = %q, want bearer credential", got)
				}
				return &http.Response{
					StatusCode: http.StatusTeapot,
					Status:     "418 Bearer " + token,
					Header:     make(http.Header),
					Body:       http.NoBody,
					Request:    req,
				}, nil
			})}

			err = operation(s)
			if err == nil {
				t.Fatal("want response error, got nil")
			}
			if strings.Contains(err.Error(), token) {
				t.Errorf("error leaks the token: %v", err)
			}
			if !strings.Contains(err.Error(), "418") {
				t.Errorf("error omits safe status code: %v", err)
			}
		})
	}
}

func TestTransportErrorRedactsBearerToken(t *testing.T) {
	const token = "sYnth3t1c.T0ken_VALUE-123"
	s, err := NewServerWithToken("https://symbols.example", token)
	if err != nil {
		t.Fatalf("NewServerWithToken: %v", err)
	}
	s.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("upstream echoed Bearer " + token)
	})}

	err = s.Ping()
	if err == nil {
		t.Fatal("want transport error, got nil")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaks the token: %v", err)
	}
	if !errors.Is(err, errSensitiveRequest) {
		t.Errorf("error = %v, want errSensitiveRequest", err)
	}
}

func TestResponseBodyErrorRedactsBearerToken(t *testing.T) {
	const token = "sYnth3t1c.T0ken_VALUE-123"
	s, err := NewServerWithToken("https://symbols.example", token)
	if err != nil {
		t.Fatalf("NewServerWithToken: %v", err)
	}
	s.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Header:     make(http.Header),
			Body: io.NopCloser(readerFunc(func([]byte) (int, error) {
				return 0, errors.New("upstream body error echoed Bearer " + token)
			})),
			Request: req,
		}, nil
	})}

	_, err = s.GetMachO(testUUID)
	if err == nil {
		t.Fatal("want response body error, got nil")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("error leaks the token: %v", err)
	}
	if !errors.Is(err, errSensitiveRequest) {
		t.Errorf("error = %v, want errSensitiveRequest", err)
	}
}

// TestCachedLookupsIssueNoSecondRequest pins that routing the six GETs through a
// shared helper did not disturb the per-UUID response caches.
func TestCachedLookupsIssueNoSecondRequest(t *testing.T) {
	srv, got := newMockSymbolServer(t)

	s, err := NewServerWithToken(srv.URL, "sYnth3t1c.T0ken")
	if err != nil {
		t.Fatalf("NewServerWithToken: %v", err)
	}
	exerciseAll(t, s)
	exerciseAll(t, s) // every lookup but Ping and HasIPSW must be served from cache

	// Ping and HasIPSW are uncached, so the replay adds exactly those two.
	if want := len(wantShapes) + 2; len(*got) != want {
		t.Errorf("got %d requests, want %d (cached lookups must not re-request)", len(*got), want)
	}
}

func TestLongBearerTokenIsSent(t *testing.T) {
	srv, got := newMockSymbolServer(t)

	token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + strings.Repeat("a", 128) + "." + strings.Repeat("b", 342)
	s, err := NewServerWithToken(srv.URL, token)
	if err != nil {
		t.Fatalf("long token rejected: %v", err)
	}
	if err := s.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if len(*got) != 1 || len((*got)[0].auth) != 1 || (*got)[0].auth[0] != bearerPrefix+token {
		t.Errorf("Authorization header did not preserve the long bearer token")
	}
}

// TestAuthenticatedRequestRefusesRedirect proves the bearer credential is never
// replayed to a host the symbol server redirects to.
func TestAuthenticatedRequestRefusesRedirect(t *testing.T) {
	const token = "sYnth3t1c.T0ken_VALUE-123"

	var targetAuth [][]string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetAuth = append(targetAuth, r.Header.Values("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	var originAuth [][]string
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originAuth = append(originAuth, r.Header.Values("Authorization"))
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	s, err := NewServerWithToken(origin.URL, token)
	if err != nil {
		t.Fatalf("NewServerWithToken: %v", err)
	}
	err = s.Ping()
	if err == nil {
		t.Fatal("Ping followed the redirect, want a refusal")
	}
	if !errors.Is(err, errRedirectNotAllowed) {
		t.Errorf("error = %v, want errRedirectNotAllowed", err)
	}
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), bearerPrefix+token) {
		t.Errorf("error leaks the credential: %v", err)
	}
	if len(originAuth) != 1 || len(originAuth[0]) != 1 || originAuth[0][0] != bearerPrefix+token {
		t.Errorf("origin Authorization = %q, want the credential (the auth path must be the one under test)", originAuth)
	}
	if len(targetAuth) != 0 {
		t.Errorf("redirect target was requested %d time(s) with Authorization %q, want none", len(targetAuth), targetAuth)
	}
}

// TestUnauthenticatedRequestStillFollowsRedirect pins that the redirect refusal
// is scoped to authenticated clients and does not change the default.
func TestUnauthenticatedRequestStillFollowsRedirect(t *testing.T) {
	var targetHits int
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits++
		if len(r.Header.Values("Authorization")) != 0 {
			t.Errorf("unauthenticated client sent Authorization %q", r.Header.Values("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	t.Cleanup(origin.Close)

	if err := NewServer(origin.URL).Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if targetHits != 1 {
		t.Errorf("redirect target hit %d time(s), want 1", targetHits)
	}
}

// TestValidTokenSurvivesHeaderWrite guards the boundary rules against Go's own
// header validation: an accepted token must be writable as a request header.
func TestValidTokenSurvivesHeaderWrite(t *testing.T) {
	srv, got := newMockSymbolServer(t)

	const token = "~/.-_+=/tok3n"
	s, err := NewServerWithToken(srv.URL, token)
	if err != nil {
		t.Fatalf("NewServerWithToken: %v", err)
	}
	if err := s.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if len(*got) != 1 || len((*got)[0].auth) != 1 || (*got)[0].auth[0] != "Bearer "+token {
		t.Fatalf("Authorization = %q, want [%q]", (*got)[0].auth, "Bearer "+token)
	}
}
