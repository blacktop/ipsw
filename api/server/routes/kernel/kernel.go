package kernel

import (
	"net/http"

	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/pkg/kernelcache"
	"github.com/gin-gonic/gin"
)

func listKexts(c *gin.Context) {
	kernelPath := c.Query("kernel_path")

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

	c.JSON(http.StatusOK, gin.H{"kernel_path": kernelPath, "kexts": bundles})
}
