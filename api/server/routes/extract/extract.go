package extract

import (
	"fmt"
	"net/http"

	cmd "github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/gin-gonic/gin"
)

// ExtractParams contains all the bound params for the extract operations
// typically these are obtained from a http.Request
//
// swagger:parameters getExtractDsc
type ExtractParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	// Parameters for the extract operation
	// in: body
	Body *cmd.Config
}

func extractDSC(c *gin.Context) {
	var query ExtractParams
	if err := c.BindQuery(&query); err != nil {
		c.IndentedJSON(http.StatusBadRequest, err)
		return
	}
	artifacts, err := cmd.DSC(query.Body)
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
