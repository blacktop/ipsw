// Package aea provides the /aea API route
package aea

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// swagger:response
type aeaPemResponse []byte

// AddRoutes adds the download routes to the router
func AddRoutes(rg *gin.RouterGroup, pemDbPath string) {
	// swagger:route GET /aea/fcs-keys/{key} AEA getFcsKeys
	//
	// FcsKeys
	//
	// Get fsc-keys PEM bytes for a given key.
	//
	//     Produces:
	//     - application/octet-stream
	//     Parameters:
	//       + name: key
	//         in: path
	//         description: fcs-keys.json PEM lookup key
	//         required: true
	//         type: string
	//     Responses:
	//       200: aeaPemResponse
	//       500: genericError
	rg.GET("/aea/fcs-keys/:key", func(c *gin.Context) {
		key := c.Param("key")
		if key == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "'key' not provided as URL param"})
			return
		}
		f, err := os.Open(pemDbPath)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Errorf("failed to open pem DB '%s': %w", pemDbPath, err),
			})
			return
		}
		defer f.Close()
		var pemDb map[string]string
		if err := json.NewDecoder(f).Decode(&pemDb); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Errorf("failed to decode pem DB JSON'%s': %w", pemDbPath, err),
			})
			return
		}
		if b64PEM, ok := pemDb[key]; ok {
			pem, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(b64PEM)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
					"error": fmt.Errorf("failed to decode base64 PEM key: %w", err),
				})
				return
			}
			c.Data(http.StatusOK, "application/octet-stream", aeaPemResponse(pem))
		} else {
			c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "key not found"})
		}
	})
}
