// Package routes contains all the routes for the API
package routes

import (
	"github.com/blacktop/ipsw/api/server/routes/daemon"
	"github.com/blacktop/ipsw/api/server/routes/devicelist"
	"github.com/blacktop/ipsw/api/server/routes/diff"
	"github.com/blacktop/ipsw/api/server/routes/download"
	"github.com/blacktop/ipsw/api/server/routes/dsc"
	"github.com/blacktop/ipsw/api/server/routes/extract"
	"github.com/blacktop/ipsw/api/server/routes/idev"
	"github.com/blacktop/ipsw/api/server/routes/info"
	"github.com/blacktop/ipsw/api/server/routes/ipsw"
	"github.com/blacktop/ipsw/api/server/routes/kernel"
	"github.com/blacktop/ipsw/api/server/routes/macho"
	"github.com/blacktop/ipsw/api/server/routes/mount"
	"github.com/gin-gonic/gin"
)

// Add adds the command routes to the router
func Add(rg *gin.RouterGroup, pemDB string) {
	daemon.AddRoutes(rg)
	devicelist.AddRoutes(rg)
	diff.AddRoutes(rg)
	download.AddRoutes(rg)
	// dtree.AddRoutes(rg) // TODO: add dtree routes
	dsc.AddRoutes(rg)
	extract.AddRoutes(rg, pemDB)
	idev.AddRoutes(rg)
	// img4.AddRoutes(rg) // TODO: add img4 routes
	info.AddRoutes(rg)
	ipsw.AddRoutes(rg, pemDB)
	kernel.AddRoutes(rg)
	macho.AddRoutes(rg)
	// mdevs.AddRoutes(rg) // TODO: add mdevs routes
	mount.AddRoutes(rg, pemDB)
	// ota.AddRoutes(rg) // TODO: add ota routes
	// pongo.AddRoutes(rg) // TODO: add pongo routes
	// sepfw.AddRoutes(rg) // TODO: add sepfw routes
	// symbolicate.AddRoutes(rg) // TODO: add symbolicate routes
}
