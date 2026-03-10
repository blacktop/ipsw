package kernel

import (
	"net/http"
	"path/filepath"
	"strings"

	"github.com/blacktop/ipsw/api/types"
	mcmd "github.com/blacktop/ipsw/internal/commands/macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/blacktop/ipsw/pkg/kernelcache/cpp"
	"github.com/blacktop/ipsw/pkg/signature"
	"github.com/gin-gonic/gin"
)

type kernelPathParams struct {
	Path string `form:"path" json:"path" binding:"required"`
	Arch string `form:"arch" json:"arch"`
}

type kernelCPPParams struct {
	Path  string   `form:"path" json:"path" binding:"required"`
	Arch  string   `form:"arch" json:"arch"`
	Entry []string `form:"entry" json:"entry"`
	Class string   `form:"class" json:"class"`
	Limit int      `form:"limit" json:"limit"`
}

type kernelSymbolicateParams struct {
	Path       string `form:"path" json:"path" binding:"required"`
	Arch       string `form:"arch" json:"arch"`
	Signatures string `form:"signatures" json:"signatures"`
}

// swagger:response kernelKextsResponse
type kernelKextsResponse struct {
	Path  string                 `json:"path"`
	Kexts []kernelcache.CFBundle `json:"kexts"`
}

// swagger:response kernelCPPResponse
type kernelCPPResponse struct {
	Path    string      `json:"path"`
	Arch    string      `json:"arch,omitempty"`
	Count   int         `json:"count"`
	Classes []cpp.Class `json:"classes"`
}

// swagger:response kernelSymbolicateResponse
type kernelSymbolicateResponse struct {
	Path    string              `json:"path"`
	Arch    string              `json:"arch,omitempty"`
	Symbols signature.SymbolMap `json:"symbols"`
}

func openKernel(path, arch string) (*mcmd.MachO, string, error) {
	kernelPath := filepath.Clean(path)
	m, err := mcmd.OpenMachONonInteractive(kernelPath, arch, false)
	if err != nil {
		return nil, "", err
	}
	return m, kernelPath, nil
}

func listKexts(c *gin.Context) {
	var params kernelPathParams
	if err := c.BindQuery(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	m, kernelPath, err := openKernel(params.Path, params.Arch)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer m.Close()

	bundles, err := kernelcache.GetKexts(m.File)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, kernelKextsResponse{Path: kernelPath, Kexts: bundles})
}

// swagger:response kernelSyscallsResponse
type kernelSyscallsResponse struct {
	Path     string               `json:"path"`
	Syscalls []kernelcache.Sysent `json:"syscalls"`
}

func getSyscalls(c *gin.Context) {
	var params kernelPathParams
	if err := c.BindQuery(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	m, kernelPath, err := openKernel(params.Path, params.Arch)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer m.Close()

	syscalls, err := kernelcache.GetSyscallTable(m.File)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, kernelSyscallsResponse{Path: kernelPath, Syscalls: syscalls})
}

// swagger:response kernelVersionResponse
type kernelVersionResponse struct {
	Path    string               `json:"path"`
	Version *kernelcache.Version `json:"version"`
}

func getVersion(c *gin.Context) {
	var params kernelPathParams
	if err := c.BindQuery(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	m, kernelPath, err := openKernel(params.Path, params.Arch)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer m.Close()

	v, err := kernelcache.GetVersion(m.File)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"path": kernelPath, "version": v})
}

func kernelCPP(c *gin.Context) {
	var params kernelCPPParams
	if err := c.BindQuery(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	m, kernelPath, err := openKernel(params.Path, params.Arch)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer m.Close()

	classes, err := cpp.NewScanner(m.File, cpp.Config{
		Entries:   params.Entry,
		ClassName: strings.TrimSpace(params.Class),
	}).Scan()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	if params.Limit > 0 && params.Limit < len(classes) {
		classes = classes[:params.Limit]
	}

	c.IndentedJSON(http.StatusOK, kernelCPPResponse{
		Path:    kernelPath,
		Arch:    params.Arch,
		Count:   len(classes),
		Classes: classes,
	})
}

func symbolicateKernel(c *gin.Context) {
	var params kernelSymbolicateParams
	if err := c.BindQuery(&params); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
		return
	}

	m, kernelPath, err := openKernel(params.Path, params.Arch)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer m.Close()

	var sigs []signature.Symbolicator
	if params.Signatures != "" {
		sigs, err = signature.Parse(filepath.Clean(params.Signatures))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
	}

	smap := signature.NewSymbolMap()
	if err := smap.SymbolicateMachO(m.File, filepath.Base(kernelPath), sigs, true); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, kernelSymbolicateResponse{
		Path:    kernelPath,
		Arch:    params.Arch,
		Symbols: smap,
	})
}
