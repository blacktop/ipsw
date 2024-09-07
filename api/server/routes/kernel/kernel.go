package kernel

import (
	"net/http"

	"github.com/blacktop/go-macho"
	"github.com/gin-gonic/gin"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/pkg/kernelcache"
)

// swagger:response kernelKextsResponse
type kernelKextsResponse struct {
	Path  string                 `json:"path"`
	Kexts []kernelcache.CFBundle `json:"kexts"`
}

func listKexts(c *gin.Context) {
	kernelPath := c.Query("path")

	m, err := macho.Open(kernelPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer m.Close()

	bundles, err := kernelcache.GetKexts(m)
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
	kernelPath := c.Query("path")

	m, err := macho.Open(kernelPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer m.Close()

	syscalls, err := kernelcache.GetSyscallTable(m)
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
	kernelPath := c.Query("path")

	m, err := macho.Open(kernelPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	defer m.Close()

	v, err := kernelcache.GetVersion(m)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"path": kernelPath, "version": v})
}
