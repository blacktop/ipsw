package afc

import (
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
)

func (c *Client) Walk(root string, walkFn filepath.WalkFunc) error {
	info, err := c.GetFileInfo(root)
	if err != nil {
		return err
	}
	return c.walk(root, info, walkFn)
}

func (c *Client) walk(path string, info os.FileInfo, walkFn filepath.WalkFunc) error {
	if !info.IsDir() {
		return walkFn(path, info, nil)
	}

	names, err := c.ReadDir(path)
	err1 := walkFn(path, info, err)
	// If err != nil, walk can't walk into this directory.
	// err1 != nil means walkFn want walk to skip this directory or stop walking.
	// Therefore, if one of err and err1 isn't nil, walk will return.
	if err != nil || err1 != nil {
		// The caller's behavior is controlled by the return value, which is decided
		// by walkFn. walkFn may ignore err and return nil.
		// If walkFn returns SkipDir, it will be handled by the caller.
		// So walk should return whatever walkFn returns.
		return err1
	}

	sort.Strings(names)
	for _, name := range names {
		if name == "." || name == ".." {
			continue
		}
		filename := pathpkg.Join(path, name)
		fileInfo, err := c.GetFileInfo(filename)
		if err != nil {
			if err := walkFn(filename, fileInfo, err); err != nil && err != filepath.SkipDir {
				return err
			}
		} else {
			err = c.walk(filename, fileInfo, walkFn)
			if err != nil {
				if !fileInfo.IsDir() || err != filepath.SkipDir {
					return err
				}
			}
		}
	}

	return nil
}

// CopyFileToDevice copies a source local file to the device
func (c *Client) CopyFileToDevice(dst, src string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := c.FileRefOpen(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return nil
}

func (c *Client) CopyFileFromDevice(dst, src string) error {
	srcFile, err := c.FileRefOpen(src, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	return nil
}

type CopyCallbackFunc func(dst, src string, info os.FileInfo)

func (c *Client) CopyToDevice(dst, src string, copyCbFn CopyCallbackFunc) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}
	if srcInfo.IsDir() {
		return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			targetPath := pathpkg.Join(dst, path)
			fmt.Println(targetPath, path)
			if info.IsDir() {
				return c.MakeDir(targetPath)
			}
			if err := c.CopyFileToDevice(targetPath, path); err != nil {
				return err
			}
			if copyCbFn != nil {
				copyCbFn(targetPath, src, info)
			}
			return nil
		})
	}

	target := dst
	if dstInfo, err := c.GetFileInfo(dst); err == nil {
		if dstInfo.IsDir() {
			target = pathpkg.Join(dst, pathpkg.Base(src))
		}
	}
	return c.CopyFileToDevice(target, src)
}

func (c *Client) CopyFromDevice(dst, src string, copyCbFn CopyCallbackFunc) error {
	srcInfo, err := c.GetFileInfo(src)
	if err != nil {
		return err
	}
	if srcInfo.IsDir() {
		return c.Walk(src, func(path string, info os.FileInfo, err error) error {
			// If destination is a directory, append the path to it
			targetPath := pathpkg.Join(dst, path)
			if info.IsDir() {
				_ = os.Mkdir(targetPath, 0755)
				return nil
			}
			if copyCbFn != nil {
				copyCbFn(targetPath, src, info)
			}
			return c.CopyFileFromDevice(targetPath, path)
		})
	}

	target := dst
	if dstInfo, err := os.Stat(dst); err == nil {
		if dstInfo.IsDir() {
			target = pathpkg.Join(dst, pathpkg.Base(src))
		}
	}
	return c.CopyFileFromDevice(target, src)
}

func (c *Client) RemoveAll(path string) error {
	err := c.Walk(path, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		return c.RemovePath(path)
	})
	if err != nil {
		return err
	}
	return c.Walk(path, func(path string, info os.FileInfo, err error) error {
		return c.RemovePath(path)
	})
}
