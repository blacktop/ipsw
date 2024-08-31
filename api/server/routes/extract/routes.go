// Package extract provides the /extract API route
package extract

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup, pemDB string) {
	er := rg.Group("/extract")
	// swagger:operation POST /extract/dsc Extract getExtractDsc
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
	//         arches:
	//           type: array
	//           items:
	//           	type: string
	//           	minLength: 1
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	// responses:
	//   '200':
	//     description: extraction response
	//     schema:
	//       $ref: '#/responses/extractReponse'
	er.POST("/dsc", extractDSC(pemDB))
	// swagger:operation POST /extract/dmg Extract getExtractDmg
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
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         dmg_type:
	//           type: string
	//           pattern: ^(app|sys|fs)$
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	// responses:
	//   '200':
	//     description: extraction response
	//     schema:
	//       $ref: '#/responses/extractReponse'
	er.POST("/dmg", extractDMG)
	// swagger:operation POST /extract/kbag Extract getExtractKbags
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
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	// responses:
	//   '200':
	//     description: extraction response
	//     schema:
	//       $ref: '#/responses/extractReponse'
	er.POST("/kbag", extractKBAG(pemDB))
	// swagger:operation POST /extract/kernel Extract getExtractKernel
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
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	// responses:
	//   '200':
	//     description: extraction response
	//     schema:
	//       $ref: '#/responses/extractReponse'
	er.POST("/kernel", extractKernel)
	// swagger:operation POST /extract/pattern Extract getExtractPattern
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
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         dmgs:
	//           type: boolean
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	// responses:
	//   '200':
	//     description: extraction response
	//     schema:
	//       $ref: '#/responses/extractReponse'
	er.POST("/pattern", extractPattern(pemDB))
	// swagger:operation POST /extract/sptm Extract getExtractSPTM
	//
	// SPTM
	//
	// Extract SPTM and TXM Firmwares.
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
	//         proxy:
	//           type: string
	//         insecure:
	//           type: boolean
	//         dmgs:
	//           type: boolean
	//         flatten:
	//           type: boolean
	//         output:
	//           type: string
	// responses:
	//   '200':
	//     description: extraction response
	//     schema:
	//       $ref: '#/responses/extractReponse'
	er.POST("/sptm", extractSPTM)
}
