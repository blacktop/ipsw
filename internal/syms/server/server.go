package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/blacktop/ipsw/internal/model"
)

type Server struct {
	URL string
}

func NewServer(url string) *Server {
	return &Server{URL: url}
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

func (s Server) GetMachO(uuid string) (*model.Macho, error) {
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
	return &macho, nil
}

func (s Server) GetDSC(uuid string) (*model.DyldSharedCache, error) {
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
	return &dsc, nil
}

func (s Server) GetDSCImage(uuid string, addr uint64) (*model.Macho, error) {
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
	return &dylib, nil
}

func (s Server) GetSymbol(uuid string, addr uint64) (*model.Symbol, error) {
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
	return &sym, nil
}
