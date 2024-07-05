package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/blacktop/ipsw/internal/model"
)

type cache struct {
	MachOs  map[string]*model.Macho
	DSCs    map[string]*model.DyldSharedCache
	Dylibs  map[string]map[uint64]*model.Macho
	Symbols map[string]map[uint64]*model.Symbol
}

type Server struct {
	URL string

	cache *cache
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

func (s Server) Ping() error {
	resp, err := http.Get(s.URL + "/v1/_ping")
	if err != nil {
		return fmt.Errorf("failed to ping symbol server: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to ping symbol server: got response %s", resp.Status)
	}
	return nil
}

func (s Server) HasIPSW(version, build, device string) (bool, error) {
	// Parse the base URL
	u, err := url.Parse(s.URL + "/v1/syms/ipsw")
	if err != nil {
		return false, fmt.Errorf("failed to parse URL: %w", err)
	}
	// Add query parameters
	q := url.Values{}
	q.Add("version", version)
	q.Add("build", build)
	q.Add("device", device)
	u.RawQuery = q.Encode()
	// Create the GET request
	resp, err := http.Get(u.String())
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	return true, nil
}

func (s Server) GetMachO(uuid string) (*model.Macho, error) {
	// check cache first
	if macho, ok := s.cache.MachOs[uuid]; ok {
		return macho, nil
	}
	resp, err := http.Get(s.URL + "/v1/syms/macho/" + uuid)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get MachO: symbol server response: %s", resp.Status)
	}
	var macho model.Macho
	if err := json.NewDecoder(resp.Body).Decode(&macho); err != nil {
		return nil, err
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
	resp, err := http.Get(s.URL + "/v1/syms/dsc/" + uuid)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get DSC: symbol server response: %s", resp.Status)
	}
	var dsc model.DyldSharedCache
	if err := json.NewDecoder(resp.Body).Decode(&dsc); err != nil {
		return nil, err
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
	resp, err := http.Get(s.URL + fmt.Sprintf("/v1/syms/dsc/%s/%d", uuid, addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get DSC image: symbol server response: %s", resp.Status)
	}
	var dylib model.Macho
	if err := json.NewDecoder(resp.Body).Decode(&dylib); err != nil {
		return nil, err
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
	resp, err := http.Get(s.URL + fmt.Sprintf("/v1/syms/%s/%d", uuid, addr))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get DSC image: symbol server response: %s", resp.Status)
	}
	var sym model.Symbol
	if err := json.NewDecoder(resp.Body).Decode(&sym); err != nil {
		return nil, err
	}
	// add to cache
	if _, ok := s.cache.Symbols[uuid]; !ok {
		s.cache.Symbols[uuid] = make(map[uint64]*model.Symbol)
	}
	s.cache.Symbols[uuid][addr] = &sym
	return &sym, nil
}
