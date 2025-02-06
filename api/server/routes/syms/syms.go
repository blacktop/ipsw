// Package syms provides the /syms API route
package syms

import (
	"errors"
	"net/http"
	"path/filepath"

	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/db"
	"github.com/blacktop/ipsw/internal/model"
	"github.com/blacktop/ipsw/internal/syms"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cast"
	"gorm.io/gorm"
)

// swagger:response
type successResponse struct {
	Success bool `json:"success,omitempty"`
}

// swagger:response
type createdResponse struct {
	Created bool `json:"created,omitempty"`
}

// swagger:response
type symIpswResponse *model.Ipsw

// swagger:response
type symMachoResponse *model.Macho

// swagger:response
type symDscResponse *model.DyldSharedCache

// swagger:response
type symResponse *model.Symbol

// swagger:response
type symsResponse []*model.Symbol

type IpswParams struct {
	Version string `form:"version" json:"version" binding:"required"`
	Build   string `form:"build" json:"build" binding:"required"`
	Device  string `form:"device" json:"device" binding:"required"`
}

// AddRoutes adds the syms routes to the router
func AddRoutes(rg *gin.RouterGroup, db db.Database, pemDB, sigsDir string) {
	// swagger:route POST /syms/scan Syms postScan
	//
	// Scan
	//
	// Scan symbols for a given IPSW.
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
	//       + name: pem_db
	//         in: query
	//         description: path to AEA pem DB JSON file
	//         required: false
	//         type: string
	//       + name: sig_dir
	//         in: query
	//         description: path to symbolication signatures directory
	//         required: false
	//         type: string
	//     Responses:
	//       200: successResponse
	//       409: genericError
	//       500: genericError
	rg.POST("/syms/scan", func(c *gin.Context) {
		ipswPath, ok := c.GetQuery("path")
		if !ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: "missing path query parameter"})
			return
		} else {
			ipswPath = filepath.Clean(ipswPath)
		}
		pemDbPath, ok := c.GetQuery("pem_db")
		if ok {
			pemDbPath = filepath.Clean(pemDbPath)
		} else {
			if pemDB != "" {
				pemDbPath = filepath.Clean(pemDB)
			}
		}
		signaturesDir, ok := c.GetQuery("sig_dir")
		if ok {
			signaturesDir = filepath.Clean(signaturesDir)
		} else {
			if sigsDir != "" {
				signaturesDir = filepath.Clean(sigsDir)
			}
		}
		if err := syms.Scan(ipswPath, pemDbPath, signaturesDir, db); err != nil {
			if errors.Is(err, gorm.ErrDuplicatedKey) {
				c.AbortWithStatusJSON(http.StatusConflict, types.GenericError{Error: err.Error()})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, successResponse{Success: true})
	})
	// swagger:route PUT /syms/rescan Syms putRescan
	//
	// Rescan
	//
	// Rescan symbols for a given IPSW.
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
	//       + name: pem_db
	//         in: query
	//         description: path to AEA pem DB JSON file
	//         required: false
	//         type: string
	//       + name: sig_dir
	//         in: query
	//         description: path to symbolication signatures directory
	//         required: false
	//         type: string
	//     Responses:
	//       201: createdResponse
	//       500: genericError
	rg.PUT("/syms/rescan", func(c *gin.Context) {
		ipswPath, ok := c.GetQuery("path")
		if !ok {
			c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: "missing path query parameter"})
			return
		} else {
			ipswPath = filepath.Clean(ipswPath)
		}
		pemDbPath, ok := c.GetQuery("pem_db")
		if ok {
			pemDbPath = filepath.Clean(pemDbPath)
		} else {
			if pemDB != "" {
				pemDbPath = filepath.Clean(pemDB)
			}
		}
		signaturesDir, ok := c.GetQuery("sig_dir")
		if ok {
			signaturesDir = filepath.Clean(signaturesDir)
		} else {
			if sigsDir != "" {
				signaturesDir = filepath.Clean(sigsDir)
			}
		}
		if err := syms.Rescan(ipswPath, pemDbPath, signaturesDir, db); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusCreated, createdResponse{Created: true})
	})
	// swagger:route GET /syms/ipsw Syms getIPSW
	//
	// IPSW
	//
	// Get IPSW for a given version OR build AND device.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: version
	//         in: query
	//         description: version of IPSW
	//         required: true
	//         type: string
	//	    + name: build
	//         in: query
	//         description: build of IPSW
	//         required: true
	//         type: string
	//	    + name: device
	//         in: query
	//         description: device of IPSW
	//         required: true
	//         type: string
	//
	//     Responses:
	//       200: symIpswResponse
	//       500: genericError
	rg.GET("/syms/ipsw", func(c *gin.Context) {
		var params IpswParams
		if err := c.BindQuery(&params); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, types.GenericError{Error: err.Error()})
			return
		}
		ipsw, err := syms.GetIPSW(params.Version, params.Build, params.Device, db)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				c.AbortWithStatusJSON(http.StatusNotFound, types.GenericError{Error: err.Error()})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, symIpswResponse(ipsw))
	})
	// swagger:route GET /syms/macho/{uuid} Syms getMachO
	//
	// MachO
	//
	// Get MachO for a given uuid.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: uuid
	//         in: path
	//         description: machO UUID
	//         required: true
	//         type: string
	//
	//     Responses:
	//       200: symMachoResponse
	//       500: genericError
	rg.GET("/syms/macho/:uuid", func(c *gin.Context) {
		uuid := c.Param("uuid")
		m, err := syms.GetMachO(uuid, db)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				c.AbortWithStatusJSON(http.StatusNotFound, types.GenericError{Error: err.Error()})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, symMachoResponse(m))
	})
	// swagger:route GET /syms/dsc/{uuid} Syms getDSC
	//
	// DSC
	//
	// Get dyld_shared_cache for a given uuid.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: uuid
	//         in: path
	//         description: dsc UUID
	//         required: true
	//         type: string
	//
	//     Responses:
	//       200: symDscResponse
	//       500: genericError
	rg.GET("/syms/dsc/:uuid", func(c *gin.Context) {
		uuid := c.Param("uuid")
		dsc, err := syms.GetDSC(uuid, db)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				c.AbortWithStatusJSON(http.StatusNotFound, types.GenericError{Error: err.Error()})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, symDscResponse(dsc))
	})
	// swagger:route GET /syms/dsc/{uuid}/{addr} Syms getDylib
	//
	// Dylib
	//
	// Get image from a DSC for a given uuid and address.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: uuid
	//         in: path
	//         description: dsc UUID
	//         required: true
	//         type: string
	//       + name: addr
	//         in: path
	//         description: pointer address
	//         required: true
	//         type: integer
	//
	//     Responses:
	//       200: symMachoResponse
	//       500: genericError
	rg.GET("/syms/dsc/:uuid/:addr", func(c *gin.Context) {
		uuid := c.Param("uuid")
		addr := c.Param("addr")
		dylib, err := syms.GetDSCImage(uuid, cast.ToUint64(addr), db)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				c.AbortWithStatusJSON(http.StatusNotFound, types.GenericError{Error: err.Error()})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, symMachoResponse(dylib))
	})
	// swagger:route GET /syms/{uuid}/{addr} Syms getSymbol
	//
	// Symbol
	//
	// Get symbol for a given uuid and address.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: uuid
	//         in: path
	//         description: file UUID
	//         required: true
	//         type: string
	//       + name: addr
	//         in: path
	//         description: symbol address
	//         required: true
	//         type: integer
	//
	//     Responses:
	//       200: symResponse
	//       500: genericError
	rg.GET("/syms/:uuid/:addr", func(c *gin.Context) {
		uuid := c.Param("uuid")
		addr := c.Param("addr")
		sym, err := syms.GetForAddr(uuid, cast.ToUint64(addr), db)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				c.AbortWithStatusJSON(http.StatusNotFound, types.GenericError{Error: err.Error()})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, symResponse(sym))
	})
	// swagger:route GET /syms/{uuid} Syms getSymbols
	//
	// Symbols
	//
	// Get symbols for a given uuid.
	//
	//     Produces:
	//     - application/json
	//
	//     Parameters:
	//       + name: uuid
	//         in: path
	//         description: file UUID
	//         required: true
	//         type: string
	//
	//     Responses:
	//       200: symsResponse
	//       500: genericError
	rg.GET("/syms/:uuid", func(c *gin.Context) {
		uuid := c.Param("uuid")
		syms, err := syms.Get(uuid, db)
		if err != nil {
			if errors.Is(err, model.ErrNotFound) {
				c.AbortWithStatusJSON(http.StatusNotFound, types.GenericError{Error: err.Error()})
				return
			}
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, symsResponse(syms))
	})
}
