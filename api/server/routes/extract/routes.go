// Package extract provides the /extract API route
package extract

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	er := rg.Group("/extract")
	// swagger:operation GET /extract/dsc Extract getExtractDsc
	//
	// DSC
	//
	// Extract dyld_shared_caches from an IPSW.
	//
	// ---
	// consumes:
	//   - "application/json"
	// produces:
	//   - "application/json"
	// parameters:
	//   -
	//     in: "body"
	//     name: "body"
	//     description: "Extraction options"
	//     required: true
	//     schema:
	//       type: object
	//       properties:
	//         ipsw:
	//           type: string
	//         url:
	//           type: string
	//         pattern:
	//           type: string
	//         arches:
	//           type: array
	//           items:
	//           	type: string
	//           	minLength: 1
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         dmgs:
	//           type: boolean
	//         dmg_type:
	//           type: string
	//           pattern: ^(app|sys|fs)$
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	er.GET("/dsc", extractDSC)
	// swagger:operation GET /extract/dmg Extract getExtractDmg
	//
	// DMG
	//
	// Extract DMGs from an IPSW.
	//
	// ---
	// consumes:
	//   - "application/json"
	// produces:
	//   - "application/json"
	// parameters:
	//   -
	//     in: "body"
	//     name: "body"
	//     description: "Extraction options"
	//     required: true
	//     schema:
	//       type: object
	//       properties:
	//         ipsw:
	//           type: string
	//         url:
	//           type: string
	//         pattern:
	//           type: string
	//         arches:
	//           type: array
	//           items:
	//           	type: string
	//           	minLength: 1
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         dmgs:
	//           type: boolean
	//         dmg_type:
	//           type: string
	//           pattern: ^(app|sys|fs)$
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	er.GET("/dmg", extractDMG)
	// swagger:operation GET /extract/kbag Extract getExtractKbags
	//
	// KBAG
	//
	// Extract KBAGs from an IPSW.
	//
	// ---
	// consumes:
	//   - "application/json"
	// produces:
	//   - "application/json"
	// parameters:
	//   -
	//     in: "body"
	//     name: "body"
	//     description: "Extraction options"
	//     required: true
	//     schema:
	//       type: object
	//       properties:
	//         ipsw:
	//           type: string
	//         url:
	//           type: string
	//         pattern:
	//           type: string
	//         arches:
	//           type: array
	//           items:
	//           	type: string
	//           	minLength: 1
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         dmgs:
	//           type: boolean
	//         dmg_type:
	//           type: string
	//           pattern: ^(app|sys|fs)$
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	er.GET("/kbag", extractKBAG)
	// swagger:operation GET /extract/kernel Extract getExtractKernel
	//
	// Kernel
	//
	// Extract kernelcaches from an IPSW.
	//
	// ---
	// consumes:
	//   - "application/json"
	// produces:
	//   - "application/json"
	// parameters:
	//   -
	//     in: "body"
	//     name: "body"
	//     description: "Extraction options"
	//     required: true
	//     schema:
	//       type: object
	//       properties:
	//         ipsw:
	//           type: string
	//         url:
	//           type: string
	//         pattern:
	//           type: string
	//         arches:
	//           type: array
	//           items:
	//           	type: string
	//           	minLength: 1
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         dmgs:
	//           type: boolean
	//         dmg_type:
	//           type: string
	//           pattern: ^(app|sys|fs)$
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	er.POST("/kernel", extractKernel)
	// swagger:operation GET /extract/pattern Extract getExtractPattern
	//
	// Pattern
	//
	// Extract files from an IPSW that match a given pattern.
	//
	// ---
	// consumes:
	//   - "application/json"
	// produces:
	//   - "application/json"
	// parameters:
	//   -
	//     in: "body"
	//     name: "body"
	//     description: "Extraction options"
	//     required: true
	//     schema:
	//       type: object
	//       properties:
	//         ipsw:
	//           type: string
	//         url:
	//           type: string
	//         pattern:
	//           type: string
	//         arches:
	//           type: array
	//           items:
	//           	type: string
	//           	minLength: 1
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         dmgs:
	//           type: boolean
	//         dmg_type:
	//           type: string
	//           pattern: ^(app|sys|fs)$
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	er.GET("/pattern", extractPattern)
}
