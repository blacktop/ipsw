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
)

// swagger:response
type successResponse struct {
	Success bool `json:"success,omitempty"`
}

// swagger:response
type symResponse *model.Symbol

// swagger:response
type symsResponse []*model.Symbol

// AddRoutes adds the syms routes to the router
func AddRoutes(rg *gin.RouterGroup, db db.Database) {
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
	//
	//     Responses:
	//       200: successResponse
	//       500: genericError
	rg.POST("/syms/scan", func(c *gin.Context) {
		ipswPath := filepath.Clean(c.Query("path"))
		if err := syms.Scan(ipswPath, db); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, successResponse{Success: true})
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
