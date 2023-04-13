package extract

import (
	"fmt"
	"net/http"

	"github.com/blacktop/ipsw/internal/commands/extract"
	cmd "github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/gin-gonic/gin"
)

func extractDSC(c *gin.Context) {
	var query extract.Config
	if err := c.BindQuery(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, err)
		return
	}
	artifacts, err := cmd.DSC(&query)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"query": query, "artifacts": artifacts})
}

func extractDMG(c *gin.Context) {
	var query cmd.Config
	if err := c.BindQuery(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, err)
		return
	}
	if !utils.StrSliceHas([]string{"app", "sys", "fs"}, query.DmgType) {
		c.IndentedJSON(http.StatusBadRequest, fmt.Errorf("invalid dmg type: %s", query.DmgType))
		return
	}
	artifacts, err := cmd.DMG(&query)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"query": query, "artifacts": artifacts})
}

func extractKBAG(c *gin.Context) {
	var query cmd.Config
	if err := c.BindQuery(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, err)
		return
	}
	artifacts, err := cmd.Keybags(&query)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"query": query, "artifacts": artifacts})
}

func extractKernel(c *gin.Context) {
	var query cmd.Config
	if err := c.BindQuery(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, err)
		return
	}
	artifacts, err := cmd.Kernelcache(&query)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"query": query, "artifacts": artifacts})
}

func extractPattern(c *gin.Context) {
	var query cmd.Config
	if err := c.BindQuery(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, err)
		return
	}
	artifacts, err := cmd.Search(&query)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	c.IndentedJSON(http.StatusOK, gin.H{"query": query, "artifacts": artifacts})
}
