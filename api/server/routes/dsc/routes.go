//go:build darwin

package dsc

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dr := rg.Group("/dsc")

	// dr.GET("/a2f", handler)     // TODO: implement this

	// swagger:route POST /dsc/a2o DSC postDscAddrToOff
	//
	// a2o
	//
	// Convert virtual address to file offset.
	//
	//     Produces:
	//     - application/json
	//
	//     Responses:
	//       200: dscAddrToOffResponse
	//       500: genericError
	dr.POST("/a2o", dscAddrToOff)
	// swagger:route POST /dsc/a2s DSC postDscAddrToSym
	//
	// a2s
	//
	// Convert virtual address to symbol.
	//
	//     Produces:
	//     - application/json
	//
	//     Responses:
	//       200: dscAddrToSymResponse
	//       500: genericError
	dr.POST("/a2s", dscAddrToSym)

	// dr.GET("/disass", handler)  // TODO: implement this
	// dr.GET("/dump", handler)    // TODO: implement this
	// dr.GET("/extract", handler) // TODO: implement this
	// dr.GET("/ida", handler)     // TODO: implement this
	// dr.GET("/image", handler)   // TODO: implement this

	// swagger:route GET /dsc/imports DSC getDscImports
	//
	// Imports
	//
	// Get list of dylibs that import a given dylib.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to dyld_shared_cache
	//         required: true
	//         type: string
	//	    + name: dylib
	//         in: query
	//         description: dylib to search for
	//         required: true
	//         type: string
	//     Responses:
	//       200: dscImportsResponse
	//       500: genericError
	dr.GET("/imports", dscImports)
	// swagger:route GET /dsc/info DSC getDscInfo
	//
	// Info
	//
	// Get info about a given DSC
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to dyld_shared_cache
	//         required: true
	//         type: string
	//     Responses:
	//       200: dscInfoResponse
	//       500: genericError
	dr.GET("/info", dscInfo)
	// swagger:route GET /dsc/macho DSC getDscMacho
	//
	// MachO
	//
	// Get MachO info for a given dylib in the DSC.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to dyld_shared_cache
	//         required: true
	//         type: string
	//	    + name: dylib
	//         in: query
	//         description: dylib to search for
	//         required: true
	//         type: string
	//     Responses:
	//       200: dscMachoResponse
	//       500: genericError
	dr.GET("/macho", dscMacho)

	// swagger:route POST /dsc/o2a DSC postDscOffToAddr
	//
	// o2a
	//
	// Convert file offset to virtual address
	//
	//     Produces:
	//     - application/json
	//
	//     Responses:
	//       200: dscOffToAddrResponse
	//       500: genericError
	dr.POST("/o2a", dscOffToAddr)

	// dr.GET("/objc", handler)    // TODO: implement this
	// dr.GET("/patches", handler) // TODO: implement this
	// dr.GET("/search", handler)  // TODO: implement this

	// swagger:route POST /dsc/slide DSC getDscSlideInfo
	//
	// Slide Info
	//
	// Get slide info for the DSC.
	//
	//     Produces:
	//     - application/json
	//
	//     Responses:
	//       200: dscSlideInfoResponse
	//       500: genericError
	dr.POST("/slide", dscSlideInfo)
	// swagger:route POST /dsc/split DSC getDscSplit
	//
	// Split
	//
	// Split the DSC into its constituent dylibs using Xcode's <code>dsc_extractor.bundle</code>
	//
	// <b>NOTE:</b> darwin ONLY
	//
	//     Produces:
	//     - application/json
	//
	//     Responses:
	//       200: dscSplitResponse
	//       500: genericError
	dr.POST("/split", dscSplit)

	// swagger:route GET /dsc/str DSC getDscStrings
	//
	// Strings
	//
	// Get strings in the DSC that match a given pattern.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to dyld_shared_cache
	//         required: true
	//         type: string
	//	    + name: pattern
	//         in: query
	//         description: regex to search for
	//         required: true
	//         type: string
	//     Responses:
	//       200: dscStringsResponse
	//       500: genericError
	dr.GET("/str", dscStrings)
	// dr.GET("/stubs", handler) // TODO: implement this
	// dr.GET("/swift", handler) // TODO: implement this

	// swagger:route POST /dsc/symaddr DSC getDscSymbols
	//
	// Symbols
	//
	// Get symbols addresses in the DSC that match a given lookup JSON payload.
	//
	//     Produces:
	//     - application/json
	//
	//     Responses:
	//       200: dscSymbolsResponse
	//       500: genericError
	dr.POST("/symaddr", dscSymbols)
	// dr.GET("/tbd", handler)    // TODO: implement this

	// swagger:route GET /dsc/webkit DSC getDscWebkit
	//
	// Webkit
	//
	// Get <code>webkit</code> version from dylib in the DSC.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to dyld_shared_cache
	//         required: true
	//         type: string
	//     Responses:
	//       200: dscWebkitResponse
	//       500: genericError
	dr.GET("/webkit", dscWebkit) // TODO: implement this
	// dr.GET("/xref", handler)   // TODO: implement this
}
