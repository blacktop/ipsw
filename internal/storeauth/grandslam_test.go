package storeauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/blacktop/go-plist"
)

type grandSlamRoundTripFunc func(*http.Request) (*http.Response, error)

func (f grandSlamRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestGrandSlamLoginAuthenticatesServerAndDecryptsSession(t *testing.T) {
	for _, protocol := range []string{"s2k", "s2k_fo"} {
		t.Run(protocol, func(t *testing.T) {
			server := newGrandSlamTestServer(t, protocol, "")
			client, err := NewGrandSlamClient(&http.Client{Transport: server}, http.Header{"X-Apple-I-Md": {"synthetic-machine-data"}})
			if err != nil {
				t.Fatal(err)
			}
			session, err := client.Login(context.Background(), "synthetic@example.test", "synthetic-password")
			if err != nil {
				t.Fatal(err)
			}
			if session.ADSID != "synthetic-adsid" || session.PET != "synthetic-pet" || session.DSID != 12345678901 || session.StorefrontCountry != "US" {
				t.Fatal("unexpected session fields")
			}
			if server.requests != 2 {
				t.Fatalf("requests = %d, want 2", server.requests)
			}
		})
	}
}

func TestGrandSlamRequiresValidServerProofBeforeSPD(t *testing.T) {
	server := newGrandSlamTestServer(t, "s2k", "bad-m2")
	client, err := NewGrandSlamClient(&http.Client{Transport: server}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Login(context.Background(), "synthetic@example.test", "synthetic-password")
	if err == nil || !strings.Contains(err.Error(), "GrandSlam server proof is invalid") || !errors.Is(err, ErrGrandSlamUnavailable) {
		t.Fatalf("Login error = %v", err)
	}
}

func TestGrandSlamPreProofFallbackClassification(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		code                     int64
		message                  string
		unavailable, credentials bool
	}{
		{"anisette", -20101, "synthetic infrastructure error", true, false},
		{"credential code", -22406, "TOKEN-SENTINEL", false, true},
		{"password message", -20101, "synthetic PASSWORD failure TOKEN-SENTINEL", false, true},
		{"incorrect message", -20101, "synthetic InCoRrEcT account TOKEN-SENTINEL", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewGrandSlamClient(&http.Client{Transport: grandSlamRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				return grandSlamTestResponse(t, request, map[string]any{"Response": map[string]any{"Status": map[string]any{"ec": tc.code, "em": tc.message}}}), nil
			})}, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Login(context.Background(), "synthetic@example.test", "synthetic-password")
			var server *GrandSlamServerError
			if !errors.As(err, &server) || server.Code != tc.code || errors.Is(err, ErrGrandSlamUnavailable) != tc.unavailable || errors.Is(err, ErrGrandSlamInvalidCredentials) != tc.credentials {
				t.Fatalf("unexpected failure classification: %v", err)
			}
			if strings.Contains(fmt.Sprintf("%v %#v", err, server), "TOKEN-SENTINEL") {
				t.Fatal("server message leaked")
			}
		})
	}
}

func TestGrandSlamProofBoundaryControlsFallback(t *testing.T) {
	for _, tc := range []struct {
		mode                     string
		unavailable, credentials bool
	}{
		{"server-unavailable", true, false},
		{"server-credentials", false, true},
		{"bad-m2", true, false},
		{"bad-spd", false, false},
		{"missing-pet", false, false},
		{"2fa", false, false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			client, err := NewGrandSlamClient(&http.Client{Transport: newGrandSlamTestServer(t, "s2k", tc.mode)}, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Login(context.Background(), "synthetic@example.test", "synthetic-password")
			if err == nil || errors.Is(err, ErrGrandSlamUnavailable) != tc.unavailable || errors.Is(err, ErrGrandSlamInvalidCredentials) != tc.credentials {
				t.Fatalf("unexpected proof-boundary classification: %v", err)
			}
		})
	}
}

func TestGrandSlamCancellationNeverAllowsFallback(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			client, err := NewGrandSlamClient(&http.Client{Transport: grandSlamRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, cause })}, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Login(context.Background(), "synthetic@example.test", "synthetic-password")
			if !errors.Is(err, cause) || errors.Is(err, ErrGrandSlamUnavailable) {
				t.Fatalf("cancellation classification = %v", err)
			}
		})
	}
}

func TestGrandSlamTrustedDeviceChallengeAndValidation(t *testing.T) {
	server := newGrandSlamTestServer(t, "s2k", "2fa")
	client, err := NewGrandSlamClient(&http.Client{Transport: server}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Login(context.Background(), "synthetic@example.test", "synthetic-password")
	var challenge *GrandSlamChallenge
	if !errors.As(err, &challenge) || challenge.ADSID != "synthetic-adsid" || challenge.IDMSToken != "synthetic-idms" {
		t.Fatalf("Login challenge = %v", err)
	}
	if err := client.TriggerTwoFactor(context.Background(), challenge); err != nil {
		t.Fatal(err)
	}
	if err := client.SubmitTwoFactor(context.Background(), challenge, " \x1b[200~012\u00a0345\x1b[201~\r\n"); err != nil {
		t.Fatal(err)
	}
	if server.requests != 4 {
		t.Fatalf("requests = %d, want 4", server.requests)
	}
	if strings.Contains(challenge.Error(), "synthetic-idms") {
		t.Fatal("challenge error exposed a token")
	}
}

func TestGrandSlamRejectsMalformedCodesBeforeNetwork(t *testing.T) {
	requests := 0
	client, err := NewGrandSlamClient(&http.Client{Transport: grandSlamRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected network")
	})}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"", " ", "12345", "1234567", "１２３４５６", "TOKEN-SENTINEL", strings.Repeat("1", 129)} {
		if err := client.SubmitTwoFactor(context.Background(), nil, code); !errors.Is(err, ErrInvalidTwoFactorCode) {
			t.Fatalf("SubmitTwoFactor error = %v", err)
		}
	}
	if requests != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}

func TestGrandSlamRequiresAffirmativeTwoFactorStatus(t *testing.T) {
	for _, response := range []map[string]any{
		{},
		{"Status": map[string]any{}},
		{"Status": "invalid", "ec": int64(0)},
		{"Status": map[string]any{"ec": "0"}},
		{"Status": map[string]any{"ec": int64(-1)}},
	} {
		client, err := NewGrandSlamClient(&http.Client{Transport: grandSlamRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return grandSlamTestResponse(t, request, response), nil
		})}, nil)
		if err != nil {
			t.Fatal(err)
		}
		challenge := &GrandSlamChallenge{ADSID: "synthetic-adsid", IDMSToken: "synthetic-idms"}
		if err := client.SubmitTwoFactor(context.Background(), challenge, "012345"); !errors.Is(err, ErrInvalidTwoFactorCode) {
			t.Fatalf("non-affirmative status accepted: %v", err)
		}
	}
}

func TestGrandSlamClientKeepsTransportAndBoundsRequests(t *testing.T) {
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "caller")
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	redirects, requests := 0, 0
	transport := grandSlamRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if request.Context().Value(contextKey{}) != "caller" {
			t.Error("caller context was lost")
		}
		deadline, ok := request.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > grandSlamTimeout {
			t.Error("request deadline is not bounded")
		}
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {"https://untrusted.example.test/secret"}}, Body: io.NopCloser(strings.NewReader("TOKEN-SENTINEL")), Request: request}, nil
	})
	sourceHeaders := http.Header{"X-Apple-I-Md": {"original"}}
	sourceClient := &http.Client{Transport: transport, Jar: jar, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { redirects++; return nil }}
	client, err := NewGrandSlamClient(sourceClient, sourceHeaders)
	if err != nil {
		t.Fatal(err)
	}
	sourceHeaders.Set("X-Apple-I-MD", "changed")
	if client.client.Jar != jar || sourceClient.Timeout != 2*time.Minute || client.client.Timeout != grandSlamTimeout || client.cpd()["X-Apple-I-MD"] != "original" {
		t.Fatal("caller configuration was lost or modified")
	}
	_, err = client.post(ctx, map[string]any{"o": "init"})
	if err == nil || !strings.Contains(err.Error(), "302") || strings.Contains(err.Error(), "TOKEN-SENTINEL") {
		t.Fatalf("redirect error = %v", err)
	}
	if requests != 1 || redirects != 0 {
		t.Fatalf("requests=%d redirects=%d, want 1/0", requests, redirects)
	}
}

func TestGrandSlamRejectsBodyAndCryptoLimits(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response *http.Response
	}{
		{"content length", &http.Response{StatusCode: 200, ContentLength: grandSlamBodyLimit + 1, Body: io.NopCloser(strings.NewReader(""))}},
		{"stream length", &http.Response{StatusCode: 200, ContentLength: -1, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", grandSlamBodyLimit+1)))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewGrandSlamClient(&http.Client{Transport: grandSlamRoundTripFunc(func(*http.Request) (*http.Response, error) { return tc.response, nil })}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.post(context.Background(), map[string]any{"o": "init"}); err == nil {
				t.Fatal("oversized body accepted")
			}
		})
	}
	for _, encrypted := range [][]byte{nil, {1}, make([]byte, grandSlamBodyLimit+aes.BlockSize), make([]byte, aes.BlockSize)} {
		if _, err := decryptGrandSlamSPD([]byte("synthetic-key"), encrypted); err == nil {
			t.Fatal("invalid encrypted SPD accepted")
		}
	}
	for _, iterations := range []int64{0, -1, 1_000_001} {
		requests := 0
		client, err := NewGrandSlamClient(&http.Client{Transport: grandSlamRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests++
			return grandSlamTestResponse(t, request, map[string]any{"Response": map[string]any{"s": []byte("salt"), "B": []byte{3}, "i": iterations, "c": "cookie", "sp": "s2k"}}), nil
		})}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Login(context.Background(), "synthetic@example.test", "synthetic-password"); err == nil || requests != 1 {
			t.Fatalf("iterations=%d err=%v requests=%d", iterations, err, requests)
		}
	}
}

func TestGrandSlamStatusRedactsServerMessage(t *testing.T) {
	err := grandSlamStatus(map[string]any{"Status": map[string]any{"ec": int64(-20101), "em": "TOKEN-SENTINEL"}})
	var server *GrandSlamServerError
	if !errors.As(err, &server) || server.Code != -20101 || strings.Contains(fmt.Sprintf("%v %#v", err, err), "TOKEN-SENTINEL") {
		t.Fatalf("status error = %v", err)
	}
}

func TestGrandSlamPlistPreflight(t *testing.T) {
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		body, err := plist.Marshal(map[string]any{"Response": map[string]any{"value": "synthetic"}}, format)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeGrandSlamPlist(body); err != nil {
			t.Fatalf("valid format %d: %v", format, err)
		}
	}
	deep := []byte("<plist><dict><key>nested</key>" + strings.Repeat("<array>", 40) + "<true/>" + strings.Repeat("</array>", 40) + "</dict></plist>")
	wide := []byte("<plist><dict><key>nested</key><array>" + strings.Repeat("<true/>", grandSlamPlistNodeLimit) + "</array></dict></plist>")
	alias := grandSlamBinaryFixture([][]byte{grandSlamCountedObject(0xa0, 1024, bytes.Repeat([]byte{1}, 1024)), grandSlamCountedObject(0x40, 2048, make([]byte, 2048))})
	cycle := grandSlamBinaryFixture([][]byte{{0xa1, 0}})
	truncated := grandSlamBinaryFixture([][]byte{{0x4f, 0x13, 0xff}})
	for _, body := range [][]byte{deep, wide, alias, cycle, truncated, []byte("<html><body>secret</body></html>"), []byte("not a plist")} {
		if _, err := decodeGrandSlamPlist(body); err == nil {
			t.Fatal("hostile plist accepted")
		}
	}
}

func FuzzGrandSlamPlist(f *testing.F) {
	f.Add([]byte("<plist><dict><key>Response</key><dict/></dict></plist>"))
	f.Add(grandSlamBinaryFixture([][]byte{{0xd0}}))
	f.Add(grandSlamBinaryFixture([][]byte{{0xa1, 0}}))
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > grandSlamBodyLimit {
			return
		}
		_, _ = decodeGrandSlamPlist(body)
	})
}

func grandSlamCountedObject(kind byte, count uint32, contents []byte) []byte {
	object := []byte{kind | 0xf, 0x12, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(object[2:], count)
	return append(object, contents...)
}

func grandSlamBinaryFixture(objects [][]byte) []byte {
	body := []byte("bplist00")
	offsets := make([]uint32, len(objects))
	for i, object := range objects {
		offsets[i] = uint32(len(body))
		body = append(body, object...)
	}
	table := uint64(len(body))
	for _, offset := range offsets {
		body = binary.BigEndian.AppendUint32(body, offset)
	}
	body = append(body, 0, 0, 0, 0, 0, 0, 4, 1)
	body = binary.BigEndian.AppendUint64(body, uint64(len(objects)))
	body = binary.BigEndian.AppendUint64(body, 0)
	return binary.BigEndian.AppendUint64(body, table)
}

type grandSlamTestServer struct {
	t                         *testing.T
	protocol, mode            string
	requests                  int
	salt, b, key, m1, m2      []byte
	verifier, secret, modulus *big.Int
}

func newGrandSlamTestServer(t *testing.T, protocol, mode string) *grandSlamTestServer {
	t.Helper()
	// RFC 5054's 2048-bit group. The server side is independent of the
	// production SRP client and consumes its fresh random public key.
	const modulus = "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
	n, ok := new(big.Int).SetString(modulus, 16)
	if !ok {
		t.Fatal("invalid test group")
	}
	g := big.NewInt(2)
	salt := []byte("synthetic-salt")
	digest := sha256.Sum256([]byte("synthetic-password"))
	password, err := pbkdf2.Key(sha256.New, string(digest[:]), salt, 17, sha256.Size)
	if err != nil {
		t.Fatal(err)
	}
	if protocol == "s2k_fo" {
		password = []byte(hex.EncodeToString(password))
	}
	x := new(big.Int).SetBytes(grandSlamHash(salt, grandSlamHash([]byte(":"), password)))
	v := new(big.Int).Exp(g, x, n)
	paddedG := make([]byte, 256)
	paddedG[255] = 2
	k := new(big.Int).SetBytes(grandSlamHash(n.Bytes(), paddedG))
	b := new(big.Int).SetBytes(bytes.Repeat([]byte{9}, 32))
	public := new(big.Int).Add(new(big.Int).Mul(k, v), new(big.Int).Exp(g, b, n))
	public.Mod(public, n)
	return &grandSlamTestServer{t: t, protocol: protocol, mode: mode, salt: salt, b: public.Bytes(), verifier: v, secret: b, modulus: n}
}

func (s *grandSlamTestServer) RoundTrip(request *http.Request) (*http.Response, error) {
	s.requests++
	if request.URL.String() == grandSlamTrustedDevice || request.URL.String() == grandSlamValidate {
		if request.Method != http.MethodGet || request.Header.Get("X-Apple-Identity-Token") != base64.StdEncoding.EncodeToString([]byte("synthetic-adsid:synthetic-idms")) || request.Header.Get("User-Agent") != "Xcode" {
			s.t.Fatal("incorrect 2FA request")
		}
		if request.URL.String() == grandSlamValidate && request.Header.Get("security-code") != "012345" {
			s.t.Fatal("incorrect normalized 2FA code")
		}
		return grandSlamTestResponse(s.t, request, map[string]any{"Status": map[string]any{"ec": 0}}), nil
	}
	if request.URL.String() != grandSlamEndpoint || request.Method != http.MethodPost {
		s.t.Fatal("unexpected GrandSlam endpoint")
	}
	data, err := io.ReadAll(request.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	var envelope map[string]any
	if _, err := plist.Unmarshal(data, &envelope); err != nil {
		s.t.Fatal(err)
	}
	header, _ := envelope["Header"].(map[string]any)
	fields, _ := envelope["Request"].(map[string]any)
	cpd, _ := fields["cpd"].(map[string]any)
	if header["Version"] != "1.0.1" || fields["u"] != "synthetic@example.test" || cpd["svct"] != "iCloud" || cpd["pbe"] != "false" {
		s.t.Fatal("incorrect GrandSlam envelope")
	}
	if _, ok := cpd["X-Apple-I-MD"]; !ok {
		s.t.Fatal("CPD lost exact anisette key spelling")
	}
	switch fields["o"] {
	case "init":
		aBytes, ok := fields["A2k"].([]byte)
		if !ok {
			s.t.Fatal("missing A2k")
		}
		a := new(big.Int).SetBytes(aBytes)
		u := new(big.Int).SetBytes(grandSlamHash(a.Bytes(), s.b))
		base := new(big.Int).Mul(a, new(big.Int).Exp(s.verifier, u, s.modulus))
		shared := new(big.Int).Exp(base, s.secret, s.modulus)
		s.key = grandSlamHash(shared.Bytes())
		paddedG := make([]byte, 256)
		paddedG[255] = 2
		hashN, hashG := grandSlamHash(s.modulus.Bytes()), grandSlamHash(paddedG)
		for i := range hashN {
			hashN[i] ^= hashG[i]
		}
		s.m1 = grandSlamHash(hashN, grandSlamHash([]byte("synthetic@example.test")), s.salt, a.Bytes(), s.b, s.key)
		s.m2 = grandSlamHash(a.Bytes(), s.m1, s.key)
		return grandSlamTestResponse(s.t, request, map[string]any{"Response": map[string]any{"s": s.salt, "B": s.b, "i": 17, "c": "synthetic-cookie", "sp": s.protocol}}), nil
	case "complete":
		m1, _ := fields["M1"].([]byte)
		if !hmac.Equal(m1, s.m1) || fields["c"] != "synthetic-cookie" {
			s.t.Fatal("incorrect client proof")
		}
		if s.mode == "server-unavailable" || s.mode == "server-credentials" {
			code := -20101
			if s.mode == "server-credentials" {
				code = -22406
			}
			return grandSlamTestResponse(s.t, request, map[string]any{"Response": map[string]any{"Status": map[string]any{"ec": code}}}), nil
		}
		spd := map[string]any{"adsid": "synthetic-adsid", "GsIdmsToken": "synthetic-idms", "DsPrsId": "12345678901", "countryCode": " US ", "t": map[string]any{"com.apple.gs.idms.pet": map[string]any{"token": "synthetic-pet"}}}
		status := map[string]any{"ec": 0}
		if s.mode == "2fa" {
			status["au"] = "trustedDeviceSecondaryAuth"
			delete(spd, "t")
		}
		if s.mode == "missing-pet" {
			delete(spd, "t")
		}
		m2 := bytes.Clone(s.m2)
		if s.mode == "bad-m2" {
			m2[0] ^= 0xff
		}
		encrypted := grandSlamEncryptSPD(s.t, s.key, spd)
		if s.mode == "bad-spd" {
			encrypted = []byte{1}
		}
		return grandSlamTestResponse(s.t, request, map[string]any{"Response": map[string]any{"Status": status, "M2": m2, "spd": encrypted}}), nil
	default:
		s.t.Fatal("unexpected GrandSlam operation")
	}
	return nil, errors.New("unreachable")
}

func grandSlamHash(parts ...[]byte) []byte {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write(part)
	}
	return h.Sum(nil)
}

func grandSlamEncryptSPD(t *testing.T, key []byte, spd map[string]any) []byte {
	t.Helper()
	body, err := plist.Marshal(spd, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write([]byte(label))
		return mac.Sum(nil)
	}
	block, err := aes.NewCipher(derive("extra data key:"))
	if err != nil {
		t.Fatal(err)
	}
	padding := aes.BlockSize - len(body)%aes.BlockSize
	body = append(body, bytes.Repeat([]byte{byte(padding)}, padding)...)
	iv := derive("extra data iv:")
	cipher.NewCBCEncrypter(block, iv[:aes.BlockSize]).CryptBlocks(body, body)
	return body
}

func grandSlamTestResponse(t *testing.T, request *http.Request, value map[string]any) *http.Response {
	t.Helper()
	body, err := plist.Marshal(value, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request}
}
