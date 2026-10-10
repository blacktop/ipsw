package storeauth

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/srp"
)

const (
	grandSlamEndpoint       = "https://gsa.apple.com/grandslam/GsService2"
	grandSlamTrustedDevice  = "https://gsa.apple.com/auth/verify/trusteddevice"
	grandSlamValidate       = "https://gsa.apple.com/grandslam/GsService2/validate"
	grandSlamContentType    = "text/x-xml-plist"
	grandSlamUserAgent      = "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0"
	grandSlamBodyLimit      = 1 << 20
	grandSlamPlistNodeLimit = 16_384
	grandSlamPlistDepth     = 32
	grandSlamTimeout        = 30 * time.Second
)

var (
	ErrInvalidTwoFactorCode = errors.New("invalid 2FA code")
	// ErrGrandSlamUnavailable marks a failure before the server proved the
	// credentials. The caller may attempt its legacy authentication path.
	ErrGrandSlamUnavailable        = errors.New("GrandSlam authentication is unavailable")
	ErrGrandSlamInvalidCredentials = errors.New("invalid GrandSlam credentials")
)

// GrandSlamSession contains only the tokens and account facts needed by the
// Store bridge. Decrypted server-provided data is never retained wholesale.
type GrandSlamSession struct {
	ADSID             string
	PET               string
	DSID              int64
	StorefrontCountry string
}

// GrandSlamChallenge is returned by Login when a trusted-device code is needed.
type GrandSlamChallenge struct {
	ADSID     string
	IDMSToken string
}

func (c *GrandSlamChallenge) Error() string {
	return "two-factor authentication required"
}

type GrandSlamServerError struct {
	Code               int64
	invalidCredentials bool
}

func (e *GrandSlamServerError) Error() string {
	return fmt.Sprintf("GrandSlam server error %d", e.Code)
}

func (e *GrandSlamServerError) Is(target error) bool {
	return target == ErrGrandSlamInvalidCredentials && (e.Code == -22406 || e.invalidCredentials)
}

type grandSlamTransportError struct{ cause error }

func (e *grandSlamTransportError) Error() string {
	return "GrandSlam HTTP request failed"
}

func (e *grandSlamTransportError) Unwrap() error {
	return e.cause
}

type GrandSlamClient struct {
	client  *http.Client
	headers http.Header
}

func NewGrandSlamClient(client *http.Client, headers http.Header) (*GrandSlamClient, error) {
	if client == nil {
		return nil, errors.New("GrandSlam HTTP client is nil")
	}
	bounded := *client
	if bounded.Timeout <= 0 || bounded.Timeout > grandSlamTimeout {
		bounded.Timeout = grandSlamTimeout
	}
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cloned := headers.Clone()
	if cloned == nil {
		cloned = make(http.Header)
	}
	return &GrandSlamClient{client: &bounded, headers: cloned}, nil
}

// Login proves the credentials and authenticates the server before decrypting
// the account's server-provided data.
func (c *GrandSlamClient) Login(ctx context.Context, email, password string) (session *GrandSlamSession, err error) {
	if ctx == nil {
		return nil, errors.New("GrandSlam context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if email == "" || len(email) > 4096 || password == "" || len(password) > 4096 {
		return nil, ErrGrandSlamInvalidCredentials
	}
	proven := false
	defer func() {
		if !proven {
			err = grandSlamPreProofError(err)
		}
	}()
	handshake, err := srp.NewGrandSlam()
	if err != nil {
		return nil, errors.New("GrandSlam SRP initialization failed")
	}
	initial, err := c.post(ctx, map[string]any{
		"A2k": handshake.PublicKey(), "cpd": c.cpd(), "o": "init",
		"ps": []string{"s2k", "s2k_fo"}, "u": email,
	})
	if err != nil {
		return nil, err
	}
	salt, err := grandSlamData(initial, "s")
	if err != nil {
		return nil, err
	}
	serverKey, err := grandSlamData(initial, "B")
	if err != nil {
		return nil, err
	}
	iterations, ok := grandSlamInt(initial["i"])
	if !ok || iterations <= 0 || iterations > 1_000_000 {
		return nil, errors.New("malformed GrandSlam SRP iteration count")
	}
	cookie, err := grandSlamString(initial, "c")
	if err != nil {
		return nil, err
	}
	protocol, ok := initial["sp"].(string)
	if !ok || (protocol != string(srp.ProtocolS2K) && protocol != string(srp.ProtocolS2KFO)) {
		return nil, errors.New("unsupported GrandSlam password protocol")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	proof, err := handshake.Complete(email, password, salt, serverKey, int(iterations), srp.PasswordProtocol(protocol))
	if err != nil {
		return nil, errors.New("GrandSlam SRP handshake failed")
	}
	complete, err := c.post(ctx, map[string]any{
		"M1": proof.Proof(), "cpd": c.cpd(), "c": cookie, "o": "complete", "u": email,
	})
	if err != nil {
		return nil, err
	}
	m2, err := grandSlamData(complete, "M2")
	if err != nil {
		return nil, err
	}
	if err := proof.VerifyServer(m2); err != nil {
		return nil, errors.New("GrandSlam server proof is invalid")
	}
	proven = true
	encrypted, err := grandSlamData(complete, "spd")
	if err != nil {
		return nil, err
	}
	spd, err := decryptGrandSlamSPD(proof.SessionKey(), encrypted)
	if err != nil {
		return nil, err
	}
	adsid, err := grandSlamString(spd, "adsid")
	if err != nil {
		return nil, err
	}
	idms, err := grandSlamString(spd, "GsIdmsToken")
	if err != nil {
		return nil, err
	}
	if status, ok := complete["Status"].(map[string]any); ok && status["au"] == "trustedDeviceSecondaryAuth" {
		return nil, &GrandSlamChallenge{ADSID: adsid, IDMSToken: idms}
	}
	tokens, _ := spd["t"].(map[string]any)
	petToken, _ := tokens["com.apple.gs.idms.pet"].(map[string]any)
	pet, err := grandSlamString(petToken, "token")
	if err != nil {
		return nil, errors.New("malformed GrandSlam response: missing PET token")
	}
	dsid, _ := grandSlamInt(spd["DsPrsId"])
	if raw, ok := spd["DsPrsId"].(string); ok {
		dsid, _ = strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	}
	if dsid < 0 {
		dsid = 0
	}
	country, _ := spd["countryCode"].(string)
	if strings.TrimSpace(country) == "" {
		country, _ = spd["c"].(string)
	}
	return &GrandSlamSession{ADSID: adsid, PET: pet, DSID: dsid, StorefrontCountry: strings.Clone(strings.TrimSpace(country))}, nil
}

func grandSlamPreProofError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrGrandSlamInvalidCredentials) || errors.Is(err, ErrInvalidTwoFactorCode) {
		return err
	}
	if _, ok := errors.AsType[*GrandSlamChallenge](err); ok {
		return err
	}
	return fmt.Errorf("%w: %w", ErrGrandSlamUnavailable, err)
}

func (c *GrandSlamClient) TriggerTwoFactor(ctx context.Context, challenge *GrandSlamChallenge) error {
	headers, err := c.twoFactorHeaders(challenge)
	if err != nil {
		return err
	}
	_, err = c.request(ctx, http.MethodGet, grandSlamTrustedDevice, headers, nil)
	return err
}

// SubmitTwoFactor marks the trusted device as verified. Call Login again to
// obtain the password-equivalent token for that trusted session.
func (c *GrandSlamClient) SubmitTwoFactor(ctx context.Context, challenge *GrandSlamChallenge, code string) error {
	code, err := NormalizeTwoFactorCode(code)
	if err != nil {
		return err
	}
	headers, err := c.twoFactorHeaders(challenge)
	if err != nil {
		return err
	}
	headers.Set("security-code", code)
	body, err := c.request(ctx, http.MethodGet, grandSlamValidate, headers, nil)
	if err != nil {
		return err
	}
	response, err := decodeGrandSlamPlist(body)
	if err != nil {
		return err
	}
	status := response
	if raw, present := response["Status"]; present {
		var ok bool
		status, ok = raw.(map[string]any)
		if !ok {
			return ErrInvalidTwoFactorCode
		}
	}
	codeValue, valid := grandSlamInt(status["ec"])
	if !valid || codeValue != 0 {
		return ErrInvalidTwoFactorCode
	}
	return nil
}

func (c *GrandSlamClient) cpd() map[string]any {
	values := map[string]any{"bootstrap": "true", "icscrec": "true", "loc": "en_GB", "pbe": "false", "prkgen": "true", "svct": "iCloud"}
	// Plist dictionary keys are case-sensitive, unlike http.Header. Preserve
	// Apple's spelling even when net/http canonicalizes the supplied headers.
	for _, key := range []string{"X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-RINFO", "X-Apple-I-MD-LU", "X-Apple-I-Client-Time", "X-Apple-I-TimeZone", "X-Apple-Locale", "X-Mme-Device-Id", "X-Apple-I-SRL-NO", "X-MMe-Client-Info"} {
		values[key] = c.headers.Get(key)
	}
	return values
}

func (c *GrandSlamClient) post(ctx context.Context, fields map[string]any) (map[string]any, error) {
	body, err := plist.Marshal(map[string]any{"Header": map[string]string{"Version": "1.0.1"}, "Request": fields}, plist.XMLFormat)
	if err != nil {
		return nil, errors.New("GrandSlam request could not be encoded")
	}
	headers := c.headers.Clone()
	headers.Set("Content-Type", grandSlamContentType)
	headers.Set("Accept", "*/*")
	headers.Set("User-Agent", grandSlamUserAgent)
	data, err := c.request(ctx, http.MethodPost, grandSlamEndpoint, headers, body)
	if err != nil {
		return nil, err
	}
	top, err := decodeGrandSlamPlist(data)
	if err != nil {
		return nil, err
	}
	response, ok := top["Response"].(map[string]any)
	if !ok {
		return nil, errors.New("malformed GrandSlam response: missing Response dictionary")
	}
	if err := grandSlamStatus(response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *GrandSlamClient) twoFactorHeaders(challenge *GrandSlamChallenge) (http.Header, error) {
	if challenge == nil || challenge.ADSID == "" || challenge.IDMSToken == "" || len(challenge.ADSID) > grandSlamBodyLimit || len(challenge.IDMSToken) > grandSlamBodyLimit {
		return nil, errors.New("invalid GrandSlam 2FA challenge")
	}
	headers := c.headers.Clone()
	headers.Set("X-Apple-Identity-Token", base64.StdEncoding.EncodeToString([]byte(challenge.ADSID+":"+challenge.IDMSToken)))
	headers.Set("User-Agent", "Xcode")
	headers.Set("Accept", grandSlamContentType)
	return headers, nil
}

func (c *GrandSlamClient) request(ctx context.Context, method, endpoint string, headers http.Header, body []byte) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("GrandSlam context is nil")
	}
	if c == nil || c.client == nil {
		return nil, errors.New("GrandSlam client is nil")
	}
	if len(body) > grandSlamBodyLimit {
		return nil, errors.New("GrandSlam request exceeds size limit")
	}
	ctx, cancel := context.WithTimeout(ctx, grandSlamTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, &grandSlamTransportError{cause: err}
	}
	request.Header = headers
	response, err := c.client.Do(request)
	if err != nil {
		return nil, &grandSlamTransportError{cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("GrandSlam HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > grandSlamBodyLimit {
		return nil, errors.New("GrandSlam response exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, grandSlamBodyLimit+1))
	if err != nil {
		return nil, &grandSlamTransportError{cause: err}
	}
	if len(data) > grandSlamBodyLimit {
		return nil, errors.New("GrandSlam response exceeds size limit")
	}
	return data, nil
}

func grandSlamStatus(response map[string]any) error {
	if status, ok := response["Status"].(map[string]any); ok {
		response = status
	}
	if value, present := response["ec"]; present {
		code, ok := grandSlamInt(value)
		if !ok {
			return errors.New("malformed GrandSlam status code")
		}
		if code != 0 {
			message, _ := response["em"].(string)
			message = strings.ToLower(message)
			badCredentials := code == -22406 || strings.Contains(message, "password") || strings.Contains(message, "incorrect")
			return &GrandSlamServerError{Code: code, invalidCredentials: badCredentials}
		}
	}
	return nil
}

func grandSlamInt(value any) (int64, bool) {
	switch value := value.(type) {
	case int64:
		return value, true
	case uint64:
		if value <= math.MaxInt64 {
			return int64(value), true
		}
	case int:
		return int64(value), true
	}
	return 0, false
}

func grandSlamData(dict map[string]any, key string) ([]byte, error) {
	value, ok := dict[key].([]byte)
	if !ok || len(value) == 0 {
		return nil, errors.New("malformed GrandSlam response: missing " + key)
	}
	return value, nil
}

func grandSlamString(dict map[string]any, key string) (string, error) {
	value, ok := dict[key].(string)
	if !ok || value == "" {
		return "", errors.New("malformed GrandSlam response: missing " + key)
	}
	// The binary plist decoder uses zero-copy strings. Copy extracted values
	// so a short session token cannot retain the whole decrypted SPD buffer.
	return strings.Clone(value), nil
}

// NormalizeTwoFactorCode accepts one six-digit code, including pasted codes
// containing whitespace or terminal bracketed-paste markers.
func NormalizeTwoFactorCode(input string) (string, error) {
	if len(input) > 128 {
		return "", ErrInvalidTwoFactorCode
	}
	input = strings.ReplaceAll(strings.ReplaceAll(input, "\x1b[200~", ""), "\x1b[201~", "")
	var code strings.Builder
	for _, char := range input {
		if unicode.IsSpace(char) {
			continue
		}
		if char < '0' || char > '9' || code.Len() >= 6 {
			return "", ErrInvalidTwoFactorCode
		}
		code.WriteByte(byte(char))
	}
	if code.Len() != 6 {
		return "", ErrInvalidTwoFactorCode
	}
	return code.String(), nil
}

func decryptGrandSlamSPD(sessionKey, encrypted []byte) (map[string]any, error) {
	if len(encrypted) == 0 || len(encrypted) > grandSlamBodyLimit || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("invalid GrandSlam encrypted session data")
	}
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, sessionKey)
		_, _ = mac.Write([]byte(label))
		return mac.Sum(nil)
	}
	key, iv := derive("extra data key:"), derive("extra data iv:")
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("GrandSlam session decryption failed")
	}
	plain := make([]byte, len(encrypted))
	// go-plist's binary parser copies its reader with io.ReadAll; any zero-copy
	// strings in its result refer to that separate allocation.
	defer clear(plain)
	cipher.NewCBCDecrypter(block, iv[:aes.BlockSize]).CryptBlocks(plain, encrypted)
	padding := int(plain[len(plain)-1])
	valid := subtle.ConstantTimeLessOrEq(1, padding) & subtle.ConstantTimeLessOrEq(padding, aes.BlockSize)
	for index := 1; index <= aes.BlockSize; index++ {
		mustMatch := subtle.ConstantTimeLessOrEq(index, padding)
		valid &= subtle.ConstantTimeSelect(mustMatch, subtle.ConstantTimeByteEq(plain[len(plain)-index], byte(padding)), 1)
	}
	if valid != 1 {
		return nil, errors.New("GrandSlam session decryption failed")
	}
	return decodeGrandSlamPlist(plain[:len(plain)-padding])
}

func decodeGrandSlamPlist(body []byte) (map[string]any, error) {
	if len(body) == 0 || len(body) > grandSlamBodyLimit {
		return nil, errors.New("GrandSlam plist exceeds size limit")
	}
	var preflight error
	if bytes.HasPrefix(body, []byte("bplist00")) {
		preflight = preflightGrandSlamBinary(body)
	} else {
		preflight = preflightGrandSlamXML(body)
	}
	if preflight != nil {
		return nil, errors.New("GrandSlam plist response could not be decoded")
	}
	var dict map[string]any
	format, err := plist.Unmarshal(body, &dict)
	if err != nil || (format != plist.XMLFormat && format != plist.BinaryFormat) || dict == nil {
		return nil, errors.New("GrandSlam plist response could not be decoded")
	}
	return dict, nil
}

func preflightGrandSlamXML(body []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	depth, nodes := 0, 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch token := token.(type) {
		case xml.StartElement:
			depth++
			nodes++
			if depth > grandSlamPlistDepth || nodes > grandSlamPlistNodeLimit {
				return errors.New("plist complexity limit")
			}
			switch token.Name.Local {
			case "plist", "dict", "array", "key", "string", "data", "integer", "real", "true", "false", "date":
			default:
				return errors.New("invalid plist element")
			}
		case xml.EndElement:
			depth--
		}
	}
	if nodes == 0 || depth != 0 {
		return errors.New("invalid plist document")
	}
	return nil
}

// Preflight bounds the decoded object graph before go-plist allocates it. Its
// graph walk also counts repeated references because decoding aliases can
// materialize a much larger tree than the binary file itself.
func preflightGrandSlamBinary(body []byte) error {
	bad := errors.New("invalid binary plist")
	if len(body) < 40 {
		return bad
	}
	trailer := body[len(body)-32:]
	offsetSize, refSize := int(trailer[6]), int(trailer[7])
	validWidth := func(width int) bool { return width == 1 || width == 2 || width == 4 || width == 8 }
	if !validWidth(offsetSize) || !validWidth(refSize) {
		return bad
	}
	count := binary.BigEndian.Uint64(trailer[8:16])
	top := binary.BigEndian.Uint64(trailer[16:24])
	table := binary.BigEndian.Uint64(trailer[24:32])
	if count == 0 || count > grandSlamPlistNodeLimit || top >= count || table < 9 || table > uint64(len(body)-32) || count*uint64(offsetSize) != uint64(len(body)-32)-table {
		return bad
	}
	readUint := func(data []byte) uint64 {
		var value uint64
		for _, b := range data {
			value = value<<8 | uint64(b)
		}
		return value
	}
	offsets := make([]uint64, int(count))
	for i := range offsets {
		start := table + uint64(i*offsetSize)
		offsets[i] = readUint(body[start : start+uint64(offsetSize)])
		if offsets[i] < 8 || offsets[i] >= table {
			return bad
		}
	}
	type item struct {
		index uint64
		depth int
	}
	stack := []item{{top, 0}}
	nodes, scalarBytes := 0, uint64(0)
	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		nodes++
		if nodes > grandSlamPlistNodeLimit || current.depth > grandSlamPlistDepth || current.index >= count {
			return bad
		}
		position := offsets[current.index]
		tag := body[position]
		kind, length := tag&0xf0, uint64(tag&0x0f)
		position++
		switch kind {
		case 0:
			if tag != 8 && tag != 9 {
				return bad
			}
			continue
		case 0x10:
			if length > 4 {
				return bad
			}
			length = 1 << length
		case 0x20:
			if length != 2 && length != 3 {
				return bad
			}
			length = 1 << length
		case 0x30:
			if length != 3 {
				return bad
			}
			length = 8
		case 0x80:
			length++
			if length > 8 && length != 16 {
				return bad
			}
		case 0x40, 0x50, 0x60, 0xa0, 0xd0:
			if length == 15 {
				if position >= table || body[position]&0xf0 != 0x10 || body[position]&0x0f > 3 {
					return bad
				}
				width := uint64(1) << (body[position] & 0x0f)
				position++
				if width > table-position {
					return bad
				}
				length = readUint(body[position : position+width])
				position += width
			}
			if kind == 0x60 {
				if length > grandSlamBodyLimit/2 {
					return bad
				}
				length *= 2
			}
			if kind == 0xa0 || kind == 0xd0 {
				if kind == 0xd0 {
					if length > grandSlamPlistNodeLimit/2 {
						return bad
					}
					length *= 2
				}
				if length > uint64(grandSlamPlistNodeLimit-nodes-len(stack)) || length > (table-position)/uint64(refSize) {
					return bad
				}
				for i := uint64(0); i < length; i++ {
					start := position + i*uint64(refSize)
					reference := readUint(body[start : start+uint64(refSize)])
					if reference >= count {
						return bad
					}
					stack = append(stack, item{reference, current.depth + 1})
				}
				continue
			}
		default:
			return bad
		}
		if length > table-position {
			return bad
		}
		scalarBytes += length
		if scalarBytes > grandSlamBodyLimit {
			return bad
		}
	}
	return nil
}
