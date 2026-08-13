package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/blacktop/ipsw/internal/model"
)

const bearerPrefix = "Bearer "

// errRedirectNotAllowed is returned instead of following a redirect on an
// authenticated request. It is deliberately generic: it names neither the token
// nor the Authorization value.
var errRedirectNotAllowed = errors.New("symbol server redirected an authenticated request: refusing to forward credentials")

var errSensitiveRequest = errors.New("symbol server request failed: sensitive details omitted")

// refuseRedirect stops the client before it replays the bearer credential to
// whatever host the symbol server points at.
func refuseRedirect(*http.Request, []*http.Request) error {
	return errRedirectNotAllowed
}

// ValidateToken reports whether token is usable as a symbol server bearer
// credential. An empty token is valid and means "send no Authorization header".
//
// Errors are generic and never include the token itself, so validation cannot
// echo it into logs or bug reports.
func ValidateToken(token string) error {
	if token == "" {
		return nil
	}
	if strings.TrimSpace(token) != token {
		return errors.New("invalid symbol server token: must not have leading or trailing whitespace")
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= ' ' || token[i] == 0x7f || token[i] == ',' {
			return errors.New("invalid symbol server token: must not contain spaces, control characters or commas")
		}
	}
	return nil
}

type cache struct {
	MachOs  map[string]*model.Macho
	DSCs    map[string]*model.DyldSharedCache
	Dylibs  map[string]map[uint64]*model.Macho
	Symbols map[string]map[uint64]*model.Symbol
}

type Server struct {
	URL string

	token  string
	client *http.Client
	cache  *cache
}

func NewServer(url string) *Server {
	cache := &cache{
		MachOs:  make(map[string]*model.Macho),
		DSCs:    make(map[string]*model.DyldSharedCache),
		Dylibs:  make(map[string]map[uint64]*model.Macho),
		Symbols: make(map[string]map[uint64]*model.Symbol),
	}
	return &Server{URL: url, cache: cache}
}

// NewServerWithToken returns a symbol server client that sends
// `Authorization: Bearer <token>` with every request. An empty token yields an
// unauthenticated client identical to NewServer. A malformed token is rejected
// here, before any request is made. Authenticated endpoints must use HTTPS,
// except that loopback HTTP is allowed for local services and tests.
//
// An authenticated client refuses to follow redirects, so the credential is
// never replayed to a host the symbol server chose.
func NewServerWithToken(url, token string) (*Server, error) {
	if err := ValidateToken(token); err != nil {
		return nil, err
	}
	if token == "" {
		return NewServer(url), nil
	}
	if err := validateAuthenticatedURL(url); err != nil {
		return nil, err
	}

	s := NewServer(url)
	client := *http.DefaultClient
	client.CheckRedirect = refuseRedirect
	s.token = token
	s.client = &client
	return s, nil
}

// validateAuthenticatedURL prevents credentials from crossing a plaintext
// network. Loopback HTTP remains available for local mock services.
func validateAuthenticatedURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return errors.New("invalid authenticated symbol server URL")
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(u.Scheme, "http") {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback()) {
			return nil
		}
	}
	return errors.New("authenticated symbol server URL must use HTTPS or loopback HTTP")
}

// safeStatus renders only locally defined status text, never a server-supplied
// HTTP reason phrase.
func safeStatus(code int) string {
	if text := http.StatusText(code); text != "" {
		return fmt.Sprintf("%d %s", code, text)
	}
	return strconv.Itoa(code)
}

// redactError discards a server or transport error if a peer echoed the token
// into it. Wrapping the original error would retain the credential.
func (s Server) redactError(err error) error {
	if err != nil && s.token != "" && strings.Contains(err.Error(), s.token) {
		return errSensitiveRequest
	}
	return err
}

// get issues a bodyless GET to rawURL, attaching the bearer credential when one
// is configured.
func (s Server) get(rawURL string) (*http.Response, error) {
	if s.token != "" {
		// URL is exported, so validate the actual target again after constructor
		// preflight in case a caller changed it.
		if err := validateAuthenticatedURL(rawURL); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, s.redactError(err)
	}
	if s.token != "" {
		req.Header.Set("Authorization", bearerPrefix+s.token)
	}
	client := s.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if errors.Is(err, errRedirectNotAllowed) {
		// Drop the *url.Error wrapper so the redirect target cannot ride along
		// into logs; the client already closed the response for us.
		return nil, errRedirectNotAllowed
	}
	return resp, s.redactError(err)
}

func (s Server) Ping() error {
	resp, err := s.get(s.URL + "/v1/_ping")
	if err != nil {
		return fmt.Errorf("failed to ping symbol server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to ping symbol server: got response %s", safeStatus(resp.StatusCode))
	}
	return nil
}

func (s Server) HasIPSW(version, build, device string) (bool, error) {
	// Parse the base URL
	u, err := url.Parse(s.URL + "/v1/syms/ipsw")
	if err != nil {
		return false, fmt.Errorf("failed to parse URL: %w", s.redactError(err))
	}
	// Add query parameters
	q := url.Values{}
	q.Add("version", version)
	q.Add("build", build)
	q.Add("device", device)
	u.RawQuery = q.Encode()
	// Create the GET request
	resp, err := s.get(u.String())
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("failed to check IPSW: symbol server response: %s", safeStatus(resp.StatusCode))
	}
	return true, nil
}

func (s Server) GetMachO(uuid string) (*model.Macho, error) {
	// check cache first
	if macho, ok := s.cache.MachOs[uuid]; ok {
		return macho, nil
	}
	resp, err := s.get(s.URL + "/v1/syms/macho/" + uuid)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get MachO: symbol server response: %s", safeStatus(resp.StatusCode))
	}
	var macho model.Macho
	if err := json.NewDecoder(resp.Body).Decode(&macho); err != nil {
		return nil, s.redactError(err)
	}
	// add to cache
	s.cache.MachOs[uuid] = &macho
	return &macho, nil
}

func (s Server) GetDSC(uuid string) (*model.DyldSharedCache, error) {
	// check cache first
	if dsc, ok := s.cache.DSCs[uuid]; ok {
		return dsc, nil
	}
	resp, err := s.get(s.URL + "/v1/syms/dsc/" + uuid)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get DSC: symbol server response: %s", safeStatus(resp.StatusCode))
	}
	var dsc model.DyldSharedCache
	if err := json.NewDecoder(resp.Body).Decode(&dsc); err != nil {
		return nil, s.redactError(err)
	}
	// add to cache
	s.cache.DSCs[uuid] = &dsc
	return &dsc, nil
}

func (s Server) GetDSCImage(uuid string, addr uint64) (*model.Macho, error) {
	// check cache first
	if dsc, ok := s.cache.Dylibs[uuid]; ok {
		if dylib, ok := dsc[addr]; ok {
			return dylib, nil
		}
	}
	resp, err := s.get(s.URL + fmt.Sprintf("/v1/syms/dsc/%s/%d", uuid, addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get DSC image: symbol server response: %s", safeStatus(resp.StatusCode))
	}
	var dylib model.Macho
	if err := json.NewDecoder(resp.Body).Decode(&dylib); err != nil {
		return nil, s.redactError(err)
	}
	// add to cache
	if _, ok := s.cache.Dylibs[uuid]; !ok {
		s.cache.Dylibs[uuid] = make(map[uint64]*model.Macho)
	}
	s.cache.Dylibs[uuid][addr] = &dylib
	return &dylib, nil
}

func (s Server) GetSymbol(uuid string, addr uint64) (*model.Symbol, error) {
	// check cache first
	if dsc, ok := s.cache.Symbols[uuid]; ok {
		if sym, ok := dsc[addr]; ok {
			return sym, nil
		}
	}
	resp, err := s.get(s.URL + fmt.Sprintf("/v1/syms/%s/%d", uuid, addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get DSC image: symbol server response: %s", safeStatus(resp.StatusCode))
	}
	var sym model.Symbol
	if err := json.NewDecoder(resp.Body).Decode(&sym); err != nil {
		return nil, s.redactError(err)
	}
	// add to cache
	if _, ok := s.cache.Symbols[uuid]; !ok {
		s.cache.Symbols[uuid] = make(map[uint64]*model.Symbol)
	}
	s.cache.Symbols[uuid][addr] = &sym
	return &sym, nil
}
