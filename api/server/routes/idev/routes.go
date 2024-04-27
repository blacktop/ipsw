package idev

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	ig := rg.Group("/idev")

	// ig.GET("/afc", handler)       // TODO: implement this
	// ig.GET("/afc/cat", handler)   // TODO:
	// ig.GET("/afc/ls", handler)    // TODO:
	// ig.GET("/afc/mkdir", handler) // TODO:
	// ig.GET("/afc/pull", handler)  // TODO:
	// ig.GET("/afc/push", handler)  // TODO:
	// ig.GET("/afc/rm", handler)    // TODO:
	// ig.GET("/afc/tree", handler)  // TODO:

	// ig.GET("/amfi", handler)    // TODO:
	ig.GET("/amfi/dev", idevAmfiDev)

	// ig.GET("/apps", handler)           // TODO: implement this
	// ig.GET("/apps/install", handler)   // TODO: implement this
	// ig.GET("/apps/ls", handler)        // TODO: implement this
	// ig.GET("/apps/uninstall", handler) // TODO: implement this

	// ig.GET("/comp", handler) // TODO: implement this

	// ig.GET("/crash", handler)       // TODO: implement this
	// ig.GET("/crash/clear", handler) // TODO: implement this
	// ig.GET("/crash/ls", handler)    // TODO: implement this
	// ig.GET("/crash/pull", handler)  // TODO: implement this

	// ig.GET("/diag", handler)          // TODO: implement this
	// ig.GET("/diag/bat", handler)      // TODO:
	// ig.GET("/diag/info", handler)     // TODO:
	// ig.GET("/diag/ioreg", handler)    // TODO:
	// ig.GET("/diag/mg", handler)       // TODO:
	// ig.GET("/diag/restart", handler)  // TODO:
	// ig.GET("/diag/shutdown", handler) // TODO:
	// ig.GET("/diag/sleep", handler)    // TODO:

	// ig.GET("/fsyms", handler) // TODO: implement this

	// ig.GET("/img", handler)         // TODO: implement this
	// ig.GET("/img/lookup", handler)  // TODO: implement this
	// ig.GET("/img/ls", handler)      // TODO: implement this
	// ig.GET("/img/mount", handler)   // TODO: implement this
	// ig.GET("/img/unmount", handler) // TODO: implement this

	// swagger:route GET /idev/info USB getIdevInfo
	//
	// Info
	//
	// Get info about USB connected devices.
	//
	//     Responses:
	//       200: idevInfoResponse
	//       500: genericError
	ig.GET("/info", idevInfo) // `ipsw idev list`

	// ig.GET("/loc", handler)       // TODO: implement this
	// ig.GET("/loc/clear", handler) // TODO: implement this
	// ig.GET("/loc/play", handler)  // TODO: implement this
	// ig.GET("/loc/set", handler)   // TODO: implement this

	// ig.GET("/noti", handler) // TODO: implement this

	// ig.GET("/pcap", handler) // TODO: implement this

	// ig.GET("/prof", handler)         // TODO: implement this
	// ig.GET("/prof/cloud", handler)   // TODO: implement this
	// ig.GET("/prof/install", handler) // TODO: implement this
	// ig.GET("/prof/ls", handler)      // TODO: implement this
	// ig.GET("/prof/rm", handler)      // TODO: implement this
	// ig.GET("/prof/wifi", handler)    // TODO: implement this

	// ig.GET("/prov", handler)         // TODO: implement this
	// ig.GET("/prov/clear", handler)   // TODO: implement this
	// ig.GET("/prov/dump", handler)    // TODO: implement this
	// ig.GET("/prov/install", handler) // TODO: implement this
	// ig.GET("/prov/ls", handler)      // TODO: implement this
	// ig.GET("/prov/rm", handler)      // TODO: implement this

	// ig.GET("/proxy", handler) // TODO: implement this

	// ig.GET("/ps", handler) // TODO: implement this

	// ig.GET("/restore", handler)       // TODO: implement this
	// ig.GET("/restore/enter", handler) // TODO: implement this
	// ig.GET("/restore/exit", handler)  // TODO: implement this

	// ig.GET("/screen", handler) // TODO: implement this

	// ig.GET("/springb", handler)           // TODO: implement this
	// ig.GET("/springb/icon", handler)      // TODO: implement this
	// ig.GET("/springb/orient", handler)    // TODO: implement this
	// ig.GET("/springb/wallpaper", handler) // TODO: implement this

	// ig.GET("/syslog", handler) // TODO: implement this

	// ig.GET("/wifi", handler)   // TODO: implement this
}
