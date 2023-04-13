package dsc

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	dr := rg.Group("/dsc")

	// dr.GET("/a2f", handler)     // TODO: implement this
	// dr.GET("/a2o", handler)     // TODO: implement this
	// dr.GET("/a2s", handler)     // TODO: implement this
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
	//         description: path to IPSW
	//         required: true
	//         type: string
	//	    + name: dylib
	//         in: query
	//         description: dylib to search for
	//         required: true
	//         type: string
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
	//         description: path to IPSW
	//         required: true
	//         type: string
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
	//         description: path to IPSW
	//         required: true
	//         type: string
	//	    + name: dylib
	//         in: query
	//         description: dylib to search for
	//         required: true
	//         type: string
	dr.GET("/macho", dscMacho)
	// dr.GET("/o2a", handler)     // TODO: implement this
	// dr.GET("/objc", handler)    // TODO: implement this
	// dr.GET("/patches", handler) // TODO: implement this
	// dr.GET("/search", handler)  // TODO: implement this
	// dr.GET("/slide", handler)   // TODO: implement this
	// dr.GET("/split", handler)   // TODO: implement this

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
	//         description: path to IPSW
	//         required: true
	//         type: string
	//	    + name: pattern
	//         in: query
	//         description: regex to search for
	//         required: true
	//         type: string
	dr.GET("/str", dscStrings)
	// dr.GET("/stubs", handler) // TODO: implement this
	// dr.GET("/swift", handler) // TODO: implement this

	// swagger:route GET /dsc/symaddr DSC getDscSymbols
	//
	// Symbols
	//
	// Get symbols addresses in the DSC that match a given lookup JSON payload.
	//
	//     Consumes:
	//     - application/json
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to IPSW
	//         required: true
	//         type: string
	dr.POST("/symaddr", dscSymbols)
	// dr.GET("/tbd", handler)    // TODO: implement this
	// dr.GET("/webkit", handler) // TODO: implement this
	// dr.GET("/xref", handler)   // TODO: implement this
}
