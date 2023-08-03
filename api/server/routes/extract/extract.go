package extract

import (
	"fmt"
	"net/http"

	"github.com/blacktop/ipsw/internal/commands/extract"
	cmd "github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/gin-gonic/gin"
)

// The extract response message
// swagger:response extractReponse
type extractReponse struct {
	// The list of extracted files
	// min items: 0
	Artifacts []string `json:"artifacts"`
}

// The extract kernels response message
// swagger:response extractKernelsReponse
type extractKernelsReponse struct {
	// The list of extracted kernels and what devices they are for
	// min items: 0
	Artifacts map[string][]string `json:"artifacts"`
}

func extractDSC(c *gin.Context) {
	var query extract.Config
	if err := c.ShouldBindJSON(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	artifacts, err := cmd.DSC(&query)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: artifacts})
}

func extractDMG(c *gin.Context) {
	var query cmd.Config
	if err := c.ShouldBindJSON(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !utils.StrSliceHas([]string{"app", "sys", "fs"}, query.DmgType) {
		c.IndentedJSON(http.StatusBadRequest, fmt.Errorf("invalid dmg type: %s", query.DmgType))
		return
	}
	artifacts, err := cmd.DMG(&query)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: artifacts})
}

func extractKBAG(c *gin.Context) {
	var query cmd.Config
	if err := c.ShouldBindJSON(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	artifacts, err := cmd.Keybags(&query)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: []string{artifacts}})
}

func extractKernel(c *gin.Context) {
	var query cmd.Config
	if err := c.ShouldBindJSON(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	artifacts, err := cmd.Kernelcache(&query)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, extractKernelsReponse{Artifacts: artifacts})
}

func extractPattern(c *gin.Context) {
	var query cmd.Config
	if err := c.ShouldBindJSON(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	artifacts, err := cmd.Search(&query)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: artifacts})
}

func extractSPTM(c *gin.Context) {
	var query cmd.Config
	if err := c.ShouldBindJSON(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	artifacts, err := cmd.SPTM(&query)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: artifacts})
}
