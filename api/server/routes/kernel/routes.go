// Package kernel provides the /kernel routes
package kernel

import (
	"github.com/gin-gonic/gin"
)

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup) {
	kg := rg.Group("/kernel")
	// kg.GET("/ctfdump", handler) // TODO: implement this
	// kg.GET("/dec", handler)     // TODO: implement this
	// kg.GET("/dwarf", handler)   // TODO: implement this
	// kg.GET("/extract", handler) // TODO: implement this

	// swagger:route GET /kernel/kexts Kernel getKernelKexts
	//
	// Kexts
	//
	// Get kernelcache KEXTs info.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to kernelcache
	//         required: true
	//         type: string
	//     Responses:
	//       200: kernelKextsResponse
	//       500: genericError
	kg.GET("/kexts", listKexts)
	// kg.GET("/sbopts", handler)     // TODO: implement this
	// kg.GET("/symbolsets", handler) // TODO: implement this

	// swagger:route GET /kernel/syscall Kernel getKernelSyscalls
	//
	// Syscalls
	//
	// Get kernelcache syscalls info.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to kernelcache
	//         required: true
	//         type: string
	//     Responses:
	//       200: kernelSyscallsResponse
	//       500: genericError
	kg.GET("/syscall", getSyscalls)
	// swagger:route GET /kernel/version Kernel getKernelVersion
	//
	// Version
	//
	// Get kernelcache version.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: path
	//         in: query
	//         description: path to kernelcache
	//         required: true
	//         type: string
	//     Responses:
	//       200: kernelVersionResponse
	//       500: genericError
	kg.GET("/version", getVersion)
}
