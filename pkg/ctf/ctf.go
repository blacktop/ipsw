package ctf

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// CTF is the Compact ANSI-C Type Format object
type CTF struct {
	Header header

	data []byte
	sr   *io.SectionReader
}

// Parse parses the CTF data and returns an CTF object pointer
func Parse(data []byte) (*CTF, error) {

	var err error
	var c CTF

	c.data = data
	c.sr = io.NewSectionReader(bytes.NewReader(data), 0, 1<<63-1)

	if err := binary.Read(c.sr, binary.LittleEndian, &c.Header.header_t); err != nil {
		return nil, fmt.Errorf("failed to read ctf_header_t: %v", err)
	}

	if (c.Header.Preamble.Flags & CTF_F_COMPRESS) != 0 {
		zr, err := zlib.NewReader(c.sr)
		if err != nil {
			return nil, fmt.Errorf("failed to create zlib reader: %v", err)
		}
		var out bytes.Buffer
		io.Copy(&out, zr)
		c.data = out.Bytes()
		// ioutil.WriteFile("ctf_uncompressed.bin", c.data, 0755)
		c.sr = io.NewSectionReader(bytes.NewReader(out.Bytes()), 0, 1<<63-1)
	}

	c.Header.ParentLabel, err = c.getString(c.Header.ParentLabelRef)
	if err != nil {
		return nil, fmt.Errorf("failed to read cth_parlabel string: %v", err)
	}

	c.Header.ParentName, err = c.getString(c.Header.ParentNameRef)
	if err != nil {
		return nil, fmt.Errorf("failed to read cth_parname string: %v", err)
	}

	return &c, nil
}

func (c *CTF) getString(offset uint32) (string, error) {

	// if (CTF_NAME_STID(name) != CTF_STRTAB_0) {
	// 	return ("<< ??? - name in external strtab >>")
	// }

	// if (offset >= hp->cth_strlen) {
	// 	return ("<< ??? - name exceeds strlab len >>")
	// }

	// if (hp->cth_stroff + offset >= cd->cd_ctflen) {
	// 	return ("<< ??? - file truncated >>")
	// }

	offset = c.Header.StrOffset + (offset & CTF_MAX_NAME)

	// fmt.Println(hex.Dump(c.data[offset : offset+100]))

	c.sr.Seek(int64(offset), io.SeekStart)

	s, err := bufio.NewReader(c.sr).ReadString('\x00')
	if err != nil {
		return "", fmt.Errorf("failed to read string at offset %#x: %v", offset, err)
	}

	s = strings.Trim(s, "\x00")

	if len(s) == 0 {
		return "(anon)", nil
	}

	return s, nil
}

// GetFunctions returns all the CTF function definitions
func (c *CTF) GetFunctions() error {

	c.sr.Seek(int64(c.Header.FuncOffset), io.SeekStart)

	return nil
}

// GetTypes returns all the CTF type definitions
func (c *CTF) GetTypes() error {

	c.sr.Seek(int64(c.Header.TypeOffset), io.SeekStart)

	return nil
}
