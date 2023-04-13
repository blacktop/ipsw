package info

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	ig := rg.Group("/info")
	// swagger:route GET /info/ipsw Info getIpswInfo
	//
	// IPSW
	//
	// Get IPSW info.
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
	ig.GET("/ipsw", getInfo)
	// swagger:route GET /info/ota Info getOtaInfo
	//
	// OTA
	//
	// Get OTA info.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to OTA
	//         required: true
	//         type: string
	ig.GET("/ota", getInfo)
	// swagger:route GET /info/ipsw/remote Info getRemoteIpswInfo
	//
	// Remote IPSW
	//
	// Get remote IPSW info.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: url
	//         in: query
	//         description: url to IPSW
	//         required: true
	//         type: string
	//       + name: proxy
	//         in: query
	//         description: http proxy to use
	//         type: string
	//       + name: insecure
	//         in: query
	//         description: ignore TLS errors
	//         type: boolean
	ig.GET("/ipsw/remote", getRemoteInfo)
	// swagger:route GET /info/ota/remote Info getRemoteOtaInfo
	//
	// Remote OTA
	//
	// Get remote OTA info.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: url
	//         in: query
	//         description: url to OTA
	//         required: true
	//         type: string
	//       + name: proxy
	//         in: query
	//         description: http proxy to use
	//         type: string
	//       + name: insecure
	//         in: query
	//         description: ignore TLS errors
	//         type: boolean
	ig.GET("/ota/remote", getRemoteInfo)
}
