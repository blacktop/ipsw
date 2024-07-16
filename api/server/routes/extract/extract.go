package extract

import (
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/blacktop/ipsw/internal/commands/extract"
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

func extractDSC(pemDB string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var query extract.Config
		if err := c.ShouldBindJSON(&query); err != nil {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if query.PemDB == "" && pemDB != "" {
			query.PemDB = filepath.Clean(pemDB)
		}
		artifacts, err := extract.DSC(&query)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: artifacts})
	}
}

func extractDMG(c *gin.Context) {
	var query extract.Config
	if err := c.ShouldBindJSON(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !utils.StrSliceHas([]string{"app", "sys", "fs"}, query.DmgType) {
		c.IndentedJSON(http.StatusBadRequest, fmt.Errorf("invalid dmg type: %s", query.DmgType))
		return
	}
	artifacts, err := extract.DMG(&query)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: artifacts})
}

func extractKBAG(pemDB string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var query extract.Config
		if err := c.ShouldBindJSON(&query); err != nil {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if query.PemDB == "" && pemDB != "" {
			query.PemDB = filepath.Clean(pemDB)
		}
		artifacts, err := extract.Keybags(&query)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: []string{artifacts}})
	}
}

func extractKernel(c *gin.Context) {
	var query extract.Config
	if err := c.ShouldBindJSON(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	artifacts, err := extract.Kernelcache(&query)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, extractKernelsReponse{Artifacts: artifacts})
}

func extractPattern(pemDB string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var query extract.Config
		if err := c.ShouldBindJSON(&query); err != nil {
			c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if query.PemDB == "" && pemDB != "" {
			query.PemDB = filepath.Clean(pemDB)
		}
		artifacts, err := extract.Search(&query)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: artifacts})
	}
}

func extractSPTM(c *gin.Context) {
	var query extract.Config
	if err := c.ShouldBindJSON(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	artifacts, err := extract.SPTM(&query)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.IndentedJSON(http.StatusOK, extractReponse{Artifacts: artifacts})
}
