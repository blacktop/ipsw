// Package extract provides the /extract API route
package extract

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dl := rg.Group("/extract")

	// swagger:route GET /extract/dsc Extract getExtractDsc
	//
	// DSC
	//
	// Extract dyld_shared_caches from an IPSW.
	dl.GET("/dsc", extractDSC)
	// swagger:route GET /extract/dmg Extract getExtractDmg
	//
	// DMG
	//
	// Extract DMGs from an IPSW.
	dl.GET("/dmg", extractDMG)
	// swagger:route GET /extract/kbag Extract getExtractKbags
	//
	// KBAG
	//
	// Extract KBAGs from an IPSW.
	dl.GET("/kbag", extractKBAG)
	// swagger:route GET /extract/kernel Extract getExtractKernel
	//
	// Kernel
	//
	// Extract kernelcaches from an IPSW.
	dl.GET("/kernel", extractKernel)
	// swagger:route GET /extract/pattern Extract getExtractPattern
	//
	// Pattern
	//
	// Extract files from an IPSW that match a given pattern.
	dl.GET("/pattern", extractPattern)
}
