// Package dsc provides the /dsc route and handlers
package dsc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/gin-gonic/gin"

	"github.com/blacktop/ipsw/api/types"
	cmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/internal/demangle"
	"github.com/blacktop/ipsw/internal/swift"
	"github.com/blacktop/ipsw/pkg/dyld"
)

// swagger:parameters postDscAddrToOff
type dscAddrToOffParams struct {
	// path to dyld_shared_cache
	// in:query
	// required: true
	Path string `json:"path" binding:"required"`
	// address to convert
	// in:query
	// required: true
	Addr uint64 `json:"addr" binding:"required"`
}

// swagger:response
type dscAddrToOffResponse struct {
	// The DSC offset
	// in:body
	cmd.Offset
}

func dscAddrToOff(c *gin.Context) {
	var params dscAddrToOffParams
	if err := c.ShouldBindJSON(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	f, err := dyld.Open(filepath.Clean(params.Path))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	off, err := cmd.ConvertAddressToOffset(f, params.Addr)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscAddrToOffResponse{*off})
}

// swagger:parameters postDscAddrToSym
type dscAddrsToSymsParams struct {
	// path to dyld_shared_cache
	// in:query
	// required: true
	Path string `json:"path" binding:"required"`
	// address to convert
	// in:query
	// required: true
	Addrs []uint64 `json:"addrs" binding:"required"`
}

// swagger:response dscAddrToSymResponse
type dscAddrToSymResponse struct {
	// in:body
	Body []cmd.SymbolLookup `json:"body"`
}

func dscAddrToSym(c *gin.Context) {
	var params dscAddrsToSymsParams
	if err := c.ShouldBindJSON(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	f, err := dyld.Open(filepath.Clean(params.Path))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	w := c.Writer
	enc := json.NewEncoder(w)
	header := w.Header()
	header.Set("Transfer-Encoding", "chunked")
	header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	var syms []cmd.SymbolLookup
	for _, addr := range params.Addrs {
		sym, err := cmd.LookupSymbol(f, addr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		sym.Demanged = demangle.Do(sym.Symbol, false, false)
		sym.Demanged = swift.DemangleBlob(sym.Demanged)
		enc.Encode(sym)
		w.(http.Flusher).Flush()
	}

	c.IndentedJSON(http.StatusOK, syms)
}

// swagger:response
type dscImportsResponse struct {
	// The path to the DSC file
	Path string `json:"path,omitempty"`
	// The list of dylibs/apps that import the specified dylib
	ImportedBy *cmd.ImportedBy `json:"imported_by,omitempty"`
}

func dscImports(c *gin.Context) {
	dscPath := c.Query("path")
	if dscPath == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing required 'path' query parameter"})
		return
	}
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	imps, err := cmd.GetDylibsThatImport(f, c.Query("dylib"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscImportsResponse{Path: dscPath, ImportedBy: imps})
}

// swagger:response
type dscInfoResponse struct {
	Path string    `json:"path,omitempty"`
	Info *cmd.Info `json:"info,omitempty"`
}

func dscInfo(c *gin.Context) {
	dscPath := c.Query("path")
	if dscPath == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "missing required 'path' query parameter"})
		return
	}
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	info, err := cmd.GetInfo(f)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscInfoResponse{Path: dscPath, Info: info})
}

// swagger:response
type dscMachoResponse struct {
	Path  string      `json:"path,omitempty"`
	Macho *macho.File `json:"macho,omitempty"`
}

func dscMacho(c *gin.Context) {
	dscPath := c.Query("path")
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	image, err := f.Image(c.Query("dylib"))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	m, err := image.GetMacho()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscMachoResponse{Path: dscPath, Macho: m})
}

// swagger:parameters postDscOffToAddr
type dscOffToAddrParams struct {
	// path to dyld_shared_cache
	// in:query
	// required: true
	Path string `json:"path" binding:"required"`
	// offset to convert
	// in:query
	// required: true
	Offset uint64 `json:"off" binding:"required"`
}

// swagger:response
type dscOffToAddrResponse struct {
	// The DSC address
	// in:body
	// swagger:allOf
	cmd.Address
}

func dscOffToAddr(c *gin.Context) {
	var params dscOffToAddrParams
	if err := c.ShouldBindJSON(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	f, err := dyld.Open(filepath.Clean(params.Path))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	addr, err := cmd.ConvertOffsetToAddress(f, params.Offset)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscOffToAddrResponse{*addr})
}

// swagger:parameters getDscSlideInfo
type dscSlideInfoParams struct {
	// path to dyld_shared_cache
	// in: query
	// required: true
	Path string `form:"path" json:"path" binding:"required"`
	// filter by mapping type
	// pattern: ="auth"
	// in: query
	Type string `form:"type" json:"type"`
}

// swagger:response
type dscSlideInfoResponse struct {
	Mapping *dyld.CacheMappingWithSlideInfo `json:"mapping,omitempty"`
	Rebases []dyld.Rebase                   `json:"rebases,omitempty"`
}

func dscSlideInfo(c *gin.Context) {
	var params dscSlideInfoParams
	if err := c.ShouldBindJSON(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	var auth bool
	if strings.EqualFold(params.Type, "auth") {
		auth = true
	}

	f, err := dyld.Open(filepath.Clean(params.Path))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	w := c.Writer
	enc := json.NewEncoder(w)
	header := w.Header()
	header.Set("Transfer-Encoding", "chunked")
	header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	for uuid := range f.Mappings {
		if f.Headers[uuid].SlideInfoOffsetUnused > 0 {
			mapping := &dyld.CacheMappingWithSlideInfo{CacheMappingAndSlideInfo: dyld.CacheMappingAndSlideInfo{
				Address:         f.Mappings[uuid][1].Address,
				Size:            f.Mappings[uuid][1].Size,
				FileOffset:      f.Mappings[uuid][1].FileOffset,
				SlideInfoOffset: f.Headers[uuid].SlideInfoOffsetUnused,
				SlideInfoSize:   f.Headers[uuid].SlideInfoSizeUnused,
			}, Name: "__DATA"}
			if mapping.SlideInfoSize > 0 {
				rebases, err := f.GetRebaseInfoForPages(uuid, mapping, 0, 0)
				if err != nil {
					c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
					return
				}
				enc.Encode(dscSlideInfoResponse{Mapping: mapping, Rebases: rebases})
				w.(http.Flusher).Flush()
			}
		} else {
			for _, mapping := range f.MappingsWithSlideInfo[uuid] {
				if auth && !mapping.Flags.IsAuthData() {
					continue
				}
				if mapping.SlideInfoSize > 0 {
					rebases, err := f.GetRebaseInfoForPages(uuid, mapping, 0, 0)
					if err != nil {
						c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
						return
					}
					enc.Encode(dscSlideInfoResponse{Mapping: mapping, Rebases: rebases})
					w.(http.Flusher).Flush()
				}
			}
		}
	}
}

// swagger:parameters getDscSplit
type dscSplitParams struct {
	// path to dyld_shared_cache
	// in: query
	// required: true
	Path string `form:"path" json:"path" binding:"required"`
	// the folder to output the split dylibs
	// in: query
	Output string `form:"output" json:"output"`
	// the path to the Xcode.app to use for splitting
	// in: query
	XCodePath string `form:"xcode_path" json:"xcode_path"`
}

// swagger:response
type dscSplitResponse struct {
	Path   string   `json:"path,omitempty"`
	Dylibs []string `json:"dylibs,omitempty"`
}

func dscSplit(c *gin.Context) {
	if runtime.GOOS != "darwin" {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: "dyld_shared_cache splitting only works on macOS with Xcode installed"})
		return
	}

	var params dscSplitParams
	if err := c.ShouldBindJSON(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	if len(params.Output) == 0 {
		params.Output = filepath.Dir(filepath.Clean(params.Path))
	}

	if err := os.MkdirAll(params.Output, 0750); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: fmt.Sprintf("failed to create output directory %s: %v", params.Output, err)})
		return
	}

	if err := dyld.Split(filepath.Clean(params.Path), filepath.Clean(params.Output), filepath.Clean(params.XCodePath), false); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: "dyld_shared_cache splitting only works on macOS with Xcode installed"})
		return
	}

	var dylibs []string
	if err := filepath.Walk(filepath.Join(params.Output, "System"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			dylibs = append(dylibs, path)
		}
		return nil
	}); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}
	if err := filepath.Walk(filepath.Join(params.Output, "usr"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			dylibs = append(dylibs, path)
		}
		return nil
	}); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscSplitResponse{Path: params.Path, Dylibs: dylibs})
}

// swagger:response
type dscStringsResponse struct {
	Path    string       `json:"path,omitempty"`
	Strings []cmd.String `json:"strings,omitempty"`
}

func dscStrings(c *gin.Context) {
	dscPath := c.Query("path")
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	pattern := c.Query("pattern")
	strs, err := cmd.GetStrings(f, pattern)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscStringsResponse{Path: dscPath, Strings: strs})
}

// swagger:parameters getDscSymbols
type dscSymbolsRequest struct {
	// path to dyld_shared_cache
	// in: query
	// required: true
	Path string `json:"path,omitempty"`
	// symbols to lookup
	// in: query
	// required: true
	// swagger:allOf
	Lookups []cmd.Symbol `json:"lookups,omitempty"`
}

// swagger:response
type dscSymbolsResponse struct {
	Path    string       `json:"path,omitempty"`
	Symbols []cmd.Symbol `json:"symbols,omitempty"`
}

func dscSymbols(c *gin.Context) {
	var params dscSymbolsRequest
	if err := c.ShouldBindJSON(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	f, err := dyld.Open(params.Path)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	syms, err := cmd.GetSymbols(f, params.Lookups)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscSymbolsResponse{Path: params.Path, Symbols: syms})
}

// swagger:response
type dscWebkitResponse struct {
	Path   string `json:"path,omitempty"`
	Webkit string `json:"webkit,omitempty"`
}

func dscWebkit(c *gin.Context) {
	dscPath := c.Query("path")
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	version, err := cmd.GetWebkitVersion(f)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscWebkitResponse{Path: dscPath, Webkit: version})
}
