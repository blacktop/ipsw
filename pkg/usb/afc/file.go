package afc

import (
	"encoding/binary"
	"io"
	"os"
	"path"
	"strconv"
	"time"
)

const (
	afcOpStatus             = 0x00000001
	afcOpData               = 0x00000002 /* Data */
	afcOpReadDir            = 0x00000003 /* ReadDir */
	afcOpReadFile           = 0x00000004 /* ReadFile */
	afcOpWriteFile          = 0x00000005 /* WriteFile */
	afcOpWritePart          = 0x00000006 /* WritePart */
	afcOpTruncateFile       = 0x00000007 /* TruncateFile */
	afcOpRemovePath         = 0x00000008 /* RemovePath */
	afcOpMakeDir            = 0x00000009 /* MakeDir */
	afcOpGetFileInfo        = 0x0000000a /* GetFileInfo */
	afcOpGetDeviceInfo      = 0x0000000b /* GetDeviceInfo */
	afcOpWriteFileAtomic    = 0x0000000c /* WriteFileAtomic (tmp file+rename) */
	afcOpFileRefOpen        = 0x0000000d /* FileRefOpen */
	afcOpFileRefOpenRes     = 0x0000000e /* FileRefOpenResult */
	afcOpFileRefRead        = 0x0000000f /* FileRefRead */
	afcOpFileRefWrite       = 0x00000010 /* FileRefWrite */
	afcOpFileRefSeek        = 0x00000011 /* FileRefSeek */
	afcOpFileRefTell        = 0x00000012 /* FileRefTell */
	afcOpFileRefTellRes     = 0x00000013 /* FileRefTellResult */
	afcOpFileRefClose       = 0x00000014 /* FileRefClose */
	afcOpFileRefSetSize     = 0x00000015 /* FileRefSetFileSize (ftruncate) */
	afcOpGetConInfo         = 0x00000016 /* GetConnectionInfo */
	afcOpSetConOptions      = 0x00000017 /* SetConnectionOptions */
	afcOpRenamePath         = 0x00000018 /* RenamePath */
	afcOpSetFSBlockSize     = 0x00000019 /* SetFSBlockSize (0x800000) */
	afcOpSetSocketBlockSize = 0x0000001A /* SetSocketBlockSize (0x800000) */
	afcOpFileRefLock        = 0x0000001B /* FileRefLock */
	afcOpMakeLink           = 0x0000001C /* MakeLink */
	afcOpSetFileTime        = 0x0000001E /* set st_mtime */
)

type FileRef struct {
	c   *Client
	ref uint64
}

func (f *FileRef) Read(p []byte) (int, error) {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	if err := f.c.sendRequest(afcOpFileRefRead, nil, f.ref, uint64(len(p))); err != nil {
		return 0, err
	}
	resp, err := f.c.recvResponseTo(p)
	if resp.payloadSize == 0 {
		err = io.EOF
	}
	return int(resp.payloadSize), err
}

func (f *FileRef) Write(p []byte) (n int, err error) {
	if err := f.c.requestNoReply(afcOpFileRefWrite, p, f.ref); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *FileRef) Seek(offset int64, whence int) (int64, error) {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	// Fast path for querying the current offset
	if offset != 0 && whence != io.SeekCurrent {
		_, err := f.c.requestNoLock(afcOpFileRefSeek, nil, f.ref, uint64(whence), uint64(offset))
		if err != nil {
			return 0, err
		}
	}
	resp, err := f.c.requestNoLock(afcOpFileRefTell, nil, f.ref)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(resp.data)), nil
}

func (f *FileRef) Close() error {
	return f.c.requestNoReply(afcOpFileRefClose, nil, f.ref)
}

func (c *Client) ReadDir(dir string) ([]string, error) {
	return c.requestStringList(afcOpReadDir, nil, dir)
}

func (c *Client) WriteFile(name string, data []byte) error {
	return nil
}

func (c *Client) TruncateFile(name string) error {
	return c.requestNoReply(afcOpTruncateFile, nil, name)
}

func (c *Client) RemovePath(path string) error {
	return c.requestNoReply(afcOpRemovePath, nil, path)
}

func (c *Client) MakeDir(dir string) error {
	return c.requestNoReply(afcOpMakeDir, nil, dir)
}

func (c *Client) GetFileInfo(name string) (os.FileInfo, error) {
	info, err := c.requestStringList(afcOpGetFileInfo, nil, name)
	if err != nil {
		return nil, err
	}
	return newFileInfo(name, info)
}

func (c *Client) GetDeviceInfo() (map[string]string, error) {
	info, err := c.requestStringList(afcOpGetDeviceInfo, nil)
	if err != nil {
		return nil, err
	}
	return listToDict(info), nil
}

func (c *Client) WriteFileAtomic(name string, data []byte) error {
	return nil
}

func (c *Client) FileRefOpen(name string, flags int) (*FileRef, error) {
	resp, err := c.request(afcOpFileRefOpen, nil, openFlagsToAfcFlags(flags), name)
	if err != nil {
		return nil, err
	}
	fr := &FileRef{
		c:   c,
		ref: binary.LittleEndian.Uint64(resp.data),
	}
	return fr, nil
}

func (c *Client) FileRefSetFileSize(ref int, size int64) error {
	return nil
}

func (c *Client) GetConnectionInfo() error {
	return nil
}

func (c *Client) SetConnectionOptions() error {
	return nil
}

func (c *Client) RenamePath(from, to string) error {
	return c.requestNoReply(afcOpRenamePath, nil, from, to)
}

func (c *Client) SetFSBlockSize() error {
	return nil
}

func (c *Client) SetSocketBlockSize() error {
	return nil
}

func (c *Client) FileRefLock(ref int) error {
	return nil
}

func (c *Client) SetFileTime(ref int) error {
	return nil
}

func (c *Client) MakeLink(from, to string) error {
	return c.requestNoReply(afcOpMakeLink, nil, from, to)
}

type fileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func newFileInfo(name string, infoList []string) (*fileInfo, error) {
	fi := &fileInfo{
		name: path.Base(name),
	}
	var err error
	info := listToDict(infoList)
	fi.size, err = strconv.ParseInt(info["st_size"], 10, 64)
	if err != nil {
		return nil, err
	}
	mtime, err := strconv.ParseInt(info["st_mtime"], 10, 64)
	if err != nil {
		return nil, err
	}
	fi.modTime = time.Unix(0, mtime)
	switch info["st_ifmt"] {
	case "S_IFBLK":
		fi.mode |= os.ModeDevice
	case "S_IFCHR":
		fi.mode |= os.ModeDevice | os.ModeCharDevice
	case "S_IFDIR":
		fi.mode |= os.ModeDir
	case "S_IFIFO":
		fi.mode |= os.ModeNamedPipe
	case "S_IFLNK":
		fi.mode |= os.ModeSymlink
	case "S_IFREG":
		// nothing to do
	case "S_IFSOCK":
		fi.mode |= os.ModeSocket
	}
	return fi, nil
}

func (f *fileInfo) Name() string {
	return f.name
}

func (f *fileInfo) Size() int64 {
	return f.size
}

func (f *fileInfo) Mode() os.FileMode {
	return f.mode
}

func (f *fileInfo) ModTime() time.Time {
	return f.modTime
}

func (f *fileInfo) IsDir() bool {
	return f.mode&os.ModeDir != 0
}

func (f *fileInfo) Sys() interface{} {
	return nil
}
