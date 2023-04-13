package macho

import (
	"net/http"
	"strings"

	"github.com/blacktop/go-macho"
	"github.com/gin-gonic/gin"
)

// Info is the struct for the macho info route parameters
type Info struct {
	Path string `form:"path" json:"path" binding:"required"`
	Arch string `form:"arch" json:"arch"`
}

func machoInfo(c *gin.Context) {
	var m *macho.File
	var params Info

	if err := c.BindQuery(&params); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	fat, err := macho.OpenFat(params.Path)
	if err != nil {
		if err == macho.ErrNotFat { // not a fat binary
			m, err = macho.Open(params.Path)
			if err != nil {
				c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
		} else {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else { // fat binary
		if params.Arch == "" {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"error": "'arch' query parameter is required for universal binaries"})
			return
		}
		for _, farch := range fat.Arches {
			if strings.EqualFold(farch.SubCPU.String(farch.CPU), params.Arch) {
				m = farch.File
			}
		}
	}
	c.IndentedJSON(http.StatusOK, gin.H{"info": m})
}
