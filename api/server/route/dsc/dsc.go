// Package dsc provides the /dsc route and handlers
package dsc

import (
	"net/http"

	cmd "github.com/blacktop/ipsw/internal/commands/dsc"
	"github.com/blacktop/ipsw/pkg/dyld"
	"github.com/gin-gonic/gin"
)

func dscImports(c *gin.Context) {
	dscPath := c.Query("path")
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	defer f.Close()

	imps, err := cmd.GetDylibsThatImport(f, c.Query("dylib"))
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{"path": dscPath, "imported_by": imps})
}

func dscInfo(c *gin.Context) {
	dscPath := c.Query("path")
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	defer f.Close()

	info, err := cmd.GetInfo(f)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{"path": dscPath, "info": info})
}

func dscSymbols(c *gin.Context) {
	dscPath := c.Query("path")
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	defer f.Close()

	var lookups []cmd.Symbol
	if err := c.ShouldBindJSON(&lookups); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	syms, err := cmd.GetSymbols(f, lookups)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{"path": dscPath, "symbols": syms})
}

func dscStrings(c *gin.Context) {
	dscPath := c.Query("path")
	f, err := dyld.Open(dscPath)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	defer f.Close()

	pattern := c.Query("pattern")
	strs, err := cmd.GetStrings(f, pattern)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}

	c.IndentedJSON(http.StatusOK, gin.H{"path": dscPath, "strings": strs})
}
