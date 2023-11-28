package ipsw

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/api/types"
	"github.com/blacktop/ipsw/internal/commands/ent"
	"github.com/blacktop/ipsw/internal/commands/extract"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/blacktop/ipsw/pkg/info"
	"github.com/gin-gonic/gin"
)

// swagger:model
type File struct {
	Name    string
	Size    int64
	Mode    string
	ModTime time.Time
}

// FS files response
// swagger:response
type getFsFilesResponse struct {
	// The path to the IPSW
	Path string `json:"path"`
	// The files in the IPSW filesystem
	Files []File `json:"files"`
}

func getFsFiles(c *gin.Context) {
	ipswPath := c.Query("path")
	ipswPath = filepath.Clean(ipswPath)

	i, err := info.Parse(ipswPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	dmgPath, err := i.GetFileSystemOsDmg()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}
	if _, err := os.Stat(dmgPath); os.IsNotExist(err) {
		// extract filesystem DMG
		dmgs, err := utils.Unzip(ipswPath, "", func(f *zip.File) bool {
			return strings.EqualFold(filepath.Base(f.Name), dmgPath)
		})
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: fmt.Sprintf("failed to extract %s from IPSW: %v", dmgPath, err)})
		}
		if len(dmgs) == 0 {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: fmt.Sprintf("failed to find %s in IPSW", dmgPath)})
		}
		defer os.Remove(filepath.Clean(dmgs[0]))
	} else {
		utils.Indent(log.Debug, 2)(fmt.Sprintf("Found extracted %s", dmgPath))
	}

	// mount filesystem DMG
	utils.Indent(log.Info, 2)(fmt.Sprintf("Mounting %s", dmgPath))
	mountPoint, alreadyMounted, err := utils.MountDMG(dmgPath)
	if err != nil {
		if !errors.Is(err, utils.ErrMountResourceBusy) {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: fmt.Sprintf("failed to mount DMG: %v", err)})
		}
	}
	if alreadyMounted {
		utils.Indent(log.Info, 3)(fmt.Sprintf("%s already mounted", dmgPath))
	} else {
		defer func() {
			utils.Indent(log.Info, 2)(fmt.Sprintf("Unmounting %s", dmgPath))
			if err := utils.Retry(3, 2*time.Second, func() error {
				return utils.Unmount(mountPoint, false)
			}); err != nil {
				log.Errorf("failed to unmount %s at %s: %v", dmgPath, mountPoint, err)
			}
		}()
	}

	var files []File
	if err := filepath.Walk(mountPoint, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("prevent panic by handling failure accessing a path %q: %v", path, err)
		}
		if info.IsDir() {
			return nil
			// return filepath.SkipDir
		}
		fpath, err := filepath.Rel(mountPoint, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path for %s: %v", path, err)
		}
		files = append(files, File{
			Name:    fpath,
			Size:    info.Size(),
			Mode:    info.Mode().String(),
			ModTime: info.ModTime(),
		})
		return nil
	}); err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, getFsFilesResponse{Path: ipswPath, Files: files})
}

// swagger:response
type getFsEntitlementsResponse struct {
	Path         string                    `json:"path"`
	Entitlements map[string]map[string]any `json:"entitlements"`
}

func getFsEntitlements(c *gin.Context) {
	ipswPath := c.Query("path")
	ipswPath = filepath.Clean(ipswPath)

	ents, err := ent.GetDatabase(&ent.Config{IPSW: ipswPath})
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	entDB := make(map[string]map[string]any)

	for f, ent := range ents {
		ents := make(map[string]any)
		if err := plist.NewDecoder(bytes.NewReader([]byte(ent))).Decode(&ents); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: fmt.Sprintf("failed to decode entitlements plist for %s: %v", f, err)})
		}
		entDB[f] = ents
	}

	c.IndentedJSON(http.StatusOK, getFsEntitlementsResponse{Path: ipswPath, Entitlements: entDB})
}

// swagger:response
type getFsLaunchdConfigResponse struct {
	Path          string `json:"path"`
	LaunchdConfig string `json:"launchd_config"`
}

func getFsLaunchdConfig(c *gin.Context) {
	ipswPath := c.Query("path")

	ldconf, err := extract.LaunchdConfig(ipswPath)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, types.GenericError{Error: err.Error()})
		return
	}

	c.IndentedJSON(http.StatusOK, getFsLaunchdConfigResponse{Path: ipswPath, LaunchdConfig: ldconf})
}
