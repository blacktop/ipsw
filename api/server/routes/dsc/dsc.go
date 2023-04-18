// Package dsc provides the /dsc route and handlers
package dsc

import (
	"net/http"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/api/types"
	cmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/gin-gonic/gin"
)

// swagger:response
type dscImportsResponse struct {
	Path string `json:"path,omitempty"`
	// swagger:allOf
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
	Path string `json:"path,omitempty"`
	// swagger:allOf
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
	Path string `json:"path,omitempty"`
	// swagger:allOf
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

// swagger:response
type dscStringsResponse struct {
	Path string `json:"path,omitempty"`
	// swagger:allOf
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

// swagger:response
type dscSymbolsResponse struct {
	Path string `json:"path,omitempty"`
	// swagger:allOf
	Symbols []cmd.Symbol `json:"symbols,omitempty"`
}

func dscSymbols(c *gin.Context) {
	dscPath := c.Query("path")
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer f.Close()

	var lookups []cmd.Symbol
	if err := c.ShouldBindJSON(&lookups); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	syms, err := cmd.GetSymbols(f, lookups)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, dscSymbolsResponse{Path: dscPath, Symbols: syms})
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
