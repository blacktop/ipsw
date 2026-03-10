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

	// swagger:route GET /kernel/cpp Kernel getKernelCpp
	//
	// Cpp
	//
	// Discover C++ classes from a kernelcache.
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
	//       + name: arch
	//         in: query
	//         description: architecture for universal Mach-O inputs
	//         required: false
	//         type: string
	//       + name: entry
	//         in: query
	//         description: fileset bundle/entry filter (repeatable)
	//         required: false
	//         type: array
	//         items:
	//           type: string
	//       + name: class
	//         in: query
	//         description: return only the named class
	//         required: false
	//         type: string
	//       + name: limit
	//         in: query
	//         description: maximum number of classes to return
	//         required: false
	//         type: integer
	//     Responses:
	//       200: kernelCPPResponse
	//       500: genericError
	kg.GET("/cpp", kernelCPP)
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

	// swagger:route GET /kernel/symbolicate Kernel getKernelSymbolicate
	//
	// Symbolicate
	//
	// Build a kernel symbol map from built-in sources, the C++ scanner, and optional signatures.
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
	//       + name: arch
	//         in: query
	//         description: architecture for universal Mach-O inputs
	//         required: false
	//         type: string
	//       + name: signatures
	//         in: query
	//         description: optional path to a kernel signature directory
	//         required: false
	//         type: string
	//     Responses:
	//       200: kernelSymbolicateResponse
	//       500: genericError
	kg.GET("/symbolicate", symbolicateKernel)
}
