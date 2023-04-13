package kernel

import (
	"net/http"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/gin-gonic/gin"
)

func listKexts(c *gin.Context) {
	kernelPath := c.Query("path")

	m, err := macho.Open(kernelPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	defer m.Close()

	bundles, err := kernelcache.GetKexts(m)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"path": kernelPath, "kexts": bundles})
}

func getSyscalls(c *gin.Context) {
	kernelPath := c.Query("path")
	m, err := macho.Open(kernelPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	defer m.Close()
	syscalls, err := kernelcache.GetSyscallTable(m)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"path": kernelPath, "syscalls": syscalls})
}

func getVersion(c *gin.Context) {
	kernelPath := c.Query("path")
	m, err := macho.Open(kernelPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	defer m.Close()
	v, err := kernelcache.GetVersion(m)
	if err != nil {
		c.JSON(http.StatusInternalServerError, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"path": kernelPath, "version": v})
}
