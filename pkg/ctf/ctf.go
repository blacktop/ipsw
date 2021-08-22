package ctf

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/blacktop/go-macho"
)

// CTF is the Compact ANSI-C Type Format object
type CTF struct {
	Header header
	Types  map[int]Type

	data []byte
	m    *macho.File
	sr   *io.SectionReader
}

// Parse parses the CTF data and returns an CTF object pointer
func Parse(m *macho.File) (*CTF, error) {

	c := CTF{m: m}

	sec := m.Section("__CTF", "__ctf")
	if sec == nil {
		return nil, fmt.Errorf("failed to find __CTF.__ctf section")
	}

	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read __CTF.__ctf data: %v", err)
	}

	c.data = data
	c.sr = io.NewSectionReader(bytes.NewReader(data), 0, 1<<63-1)

	if err := binary.Read(c.sr, binary.LittleEndian, &c.Header.header_t); err != nil {
		return nil, fmt.Errorf("failed to read ctf_header_t: %v", err)
	}

	if (c.Header.Preamble.Flags & F_COMPRESS) != 0 {
		zr, err := zlib.NewReader(c.sr)
		if err != nil {
			return nil, fmt.Errorf("failed to create zlib reader: %v", err)
		}
		var out bytes.Buffer
		io.Copy(&out, zr)
		c.data = out.Bytes()
		c.sr = io.NewSectionReader(bytes.NewReader(out.Bytes()), 0, 1<<63-1)
	}

	c.Header.ParentLabel = c.getString(c.Header.ParentLabelRef)
	c.Header.ParentName = c.getString(c.Header.ParentNameRef)

	if err := c.GetDataTypes(); err != nil {
		return nil, err
	}

	// if err := c.GetFunctions(); err != nil {
	// 	return nil, err
	// }

	return &c, nil
}

func (c *CTF) getString(offset uint32) string {

	// if (CTF_NAME_STID(name) != CTF_STRTAB_0) {
	// 	return ("<< ??? - name in external strtab >>")
	// }

	// if (offset >= hp->cth_strlen) {
	// 	return ("<< ??? - name exceeds strlab len >>")
	// }

	// if (hp->cth_stroff + offset >= cd->cd_ctflen) {
	// 	return ("<< ??? - file truncated >>")
	// }

	offset = c.Header.StrOffset + (offset & MAX_NAME)

	// fmt.Println(hex.Dump(c.data[offset : offset+100]))

	c.sr.Seek(int64(offset), io.SeekStart)

	s, err := bufio.NewReader(c.sr).ReadString('\x00')
	if err != nil {
		return fmt.Sprintf("failed to read string at offset %#x: %v", offset, err)
	}

	s = strings.Trim(s, "\x00")

	if len(s) == 0 {
		return "(anon)"
	}

	return s
}

func (c *CTF) getGlobalSymbols() []macho.Symbol {
	var fsyms []macho.Symbol
	for _, sym := range c.m.Symtab.Syms {
		if sym.Type.IsExternalSym() {
			if sym.Type.IsDefinedInSection() {
				if c.m.Sections[sym.Sect-1].Name != "__text" {
					fsyms = append(fsyms, sym)
				}
			}
		}
	}
	return fsyms
}

func (c *CTF) getFunctionSymbols() []macho.Symbol {
	var fsyms []macho.Symbol
	for _, sym := range c.m.Symtab.Syms {
		if sym.Type.IsExternalSym() {
			if sym.Type.IsDefinedInSection() {
				if c.m.Sections[sym.Sect-1].Name == "__text" {
					fsyms = append(fsyms, sym)
				}
			}
		}
	}
	return fsyms
}

// GetDataObjects returns all the CTF data objects
func (c *CTF) GetDataObjects() error {

	c.sr.Seek(int64(c.Header.ObjOffset), io.SeekStart)

	dataSyms := c.getGlobalSymbols()

	dataObjects := make([]uint16, (c.Header.FuncOffset-c.Header.ObjOffset)/uint32(binary.Size(uint16(0))))
	if err := binary.Read(c.sr, binary.LittleEndian, &dataObjects); err != nil {
		return fmt.Errorf("failed to read data objects: %v", err)
	}

	if len(dataSyms) != len(dataObjects) {
		return fmt.Errorf("size of global symbols does NOT match that of the CTF data objects")
	}

	for idx, sym := range dataSyms {
		fmt.Printf("[%d] %d %s\n", idx, dataObjects[idx], strings.TrimPrefix(sym.Name, "_"))
	}

	return nil
}

// GetFunctions returns all the CTF function definitions
func (c *CTF) GetFunctions() error {

	c.sr.Seek(int64(c.Header.FuncOffset), io.SeekStart)

	for idx, fsym := range c.getFunctionSymbols() {

		var inf info
		var dat uint16
		if err := binary.Read(c.sr, binary.LittleEndian, &inf); err != nil {
			return fmt.Errorf("failed to read info: %v", err)
		}

		if inf.Kind() == UNKNOWN && inf.VarLen() == 0 {
			continue /* skip padding */
		}

		if inf.Kind() != FUNCTION {
			return fmt.Errorf("  [%d] unexpected kind -- %d", idx, inf.Kind())
		}

		fsym.Name = strings.TrimPrefix(fsym.Name, "_") // Lop off omnipresent underscore to match DWARF convention

		fmt.Printf("  [%d] FUNC ", idx)
		if len(fsym.Name) > 0 {
			fmt.Printf("(%s) ", fsym.Name)
		}
		if err := binary.Read(c.sr, binary.LittleEndian, &dat); err != nil {
			return fmt.Errorf("failed to read info: %v", err)
		}
		fmt.Printf("returns: %d args: (", dat)

		if inf.VarLen() != 0 {
			if err := binary.Read(c.sr, binary.LittleEndian, &dat); err != nil {
				return fmt.Errorf("failed to read info: %v", err)
			}
			fmt.Printf("%d", dat)
			for i := uint16(1); i < inf.VarLen(); i++ {
				if err := binary.Read(c.sr, binary.LittleEndian, &dat); err != nil {
					return fmt.Errorf("failed to read info: %v", err)
				}

				fmt.Printf(", %d", dat)
			}
		}
		fmt.Printf(")\n")
	}

	return nil
}

func (c *CTF) lookup(id int) Type {
	if t, ok := c.Types[id]; ok {
		return t
	}
	return nil
}

// GetDataTypes returns all the CTF data type definitions
func (c *CTF) GetDataTypes() error {

	c.Types = make(map[int]Type)

	r := bytes.NewReader(c.data[c.Header.TypeOffset:c.Header.StrOffset])

	id := 1

	for {
		var t ctftype
		if err := binary.Read(r, binary.LittleEndian, &t.stype); err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read data type: %v", err)
		}

		size := uint64(t.SizeOrType)
		if t.SizeOrType == LSIZE_SENT {
			if err := binary.Read(r, binary.LittleEndian, &t.LSizeHI); err != nil {
				return fmt.Errorf("failed to read ctf_type_t lsizehi : %v", err)
			}
			if err := binary.Read(r, binary.LittleEndian, &t.LSizeLO); err != nil {
				return fmt.Errorf("failed to read ctf_type_t lsizelo : %v", err)
			}
			size = t.LSize()
		}

		switch t.Info.Kind() {
		case INTEGER:
			var enc intEncoding
			if err := binary.Read(r, binary.LittleEndian, &enc); err != nil {
				return fmt.Errorf("failed to read int encoding: %v", err)
			}
			c.Types[id] = &Integer{
				id:       id,
				name:     c.getString(uint32(t.Name)),
				info:     t.Info,
				encoding: enc,
			}
		case FLOAT:
			var enc floatEncoding
			if err := binary.Read(r, binary.LittleEndian, &enc); err != nil {
				return fmt.Errorf("failed to read float encoding: %v", err)
			}
			c.Types[id] = &Float{
				id:       id,
				name:     c.getString(uint32(t.Name)),
				info:     t.Info,
				encoding: enc,
			}
		case ARRAY:
			var a array
			if err := binary.Read(r, binary.LittleEndian, &a); err != nil {
				return fmt.Errorf("failed to read array: %v", err)
			}
			c.Types[id] = &Array{
				id:       id,
				name:     c.getString(uint32(t.Name)),
				info:     t.Info,
				array:    a,
				lookupFn: c.lookup,
			}
		case FUNCTION:
			args := make([]uint16, t.Info.VarLen())
			if err := binary.Read(r, binary.LittleEndian, &args); err != nil {
				return fmt.Errorf("failed to read args: %v", err)
			}
			c.Types[id] = &Function{
				id:       id,
				name:     c.getString(uint32(t.Name)),
				info:     t.Info,
				ret:      t.SizeOrType,
				args:     args,
				lookupFn: c.lookup,
			}
			if (t.Info.VarLen() & 1) != 0 {
				r.Seek(int64(binary.Size(uint16(0))), io.SeekCurrent) // alignment
			}
		case STRUCT:
			s := &Struct{
				id:   id,
				name: c.getString(uint32(t.Name)),
				info: t.Info,
				size: size,
			}
			if size >= LSTRUCT_THRESH {
				lmps := make([]lmember, t.Info.VarLen())
				if err := binary.Read(r, binary.LittleEndian, &lmps); err != nil {
					return fmt.Errorf("failed to read lmembers: %v", err)
				}
				for _, lmp := range lmps {
					s.Fields = append(s.Fields, Member{
						parent:    id,
						name:      c.getString(uint32(lmp.Name)),
						offset:    lmp.Offset(),
						reference: lmp.Type,
						lookupFn:  c.lookup,
					})
				}
			} else {
				mps := make([]member, t.Info.VarLen())
				if err := binary.Read(r, binary.LittleEndian, &mps); err != nil {
					return fmt.Errorf("failed to read members: %v", err)
				}
				for _, mp := range mps {
					s.Fields = append(s.Fields, Member{
						parent:    id,
						name:      c.getString(uint32(mp.Name)),
						offset:    uint64(mp.Offset),
						reference: mp.Type,
						lookupFn:  c.lookup,
					})
				}
			}
			c.Types[id] = s
		case UNION:
			u := &Union{
				id:   id,
				name: c.getString(uint32(t.Name)),
				info: t.Info,
				size: size,
			}
			if size >= LSTRUCT_THRESH {
				lmps := make([]lmember, t.Info.VarLen())
				if err := binary.Read(r, binary.LittleEndian, &lmps); err != nil {
					return fmt.Errorf("failed to read lmembers: %v", err)
				}
				for _, lmp := range lmps {
					u.Fields = append(u.Fields, Member{
						parent:    id,
						name:      c.getString(uint32(lmp.Name)),
						offset:    lmp.Offset(),
						reference: lmp.Type,
						lookupFn:  c.lookup,
					})
				}
			} else {
				mps := make([]member, t.Info.VarLen())
				if err := binary.Read(r, binary.LittleEndian, &mps); err != nil {
					return fmt.Errorf("failed to read members: %v", err)
				}
				for _, mp := range mps {
					u.Fields = append(u.Fields, Member{
						parent:    id,
						name:      c.getString(uint32(mp.Name)),
						offset:    uint64(mp.Offset),
						reference: mp.Type,
						lookupFn:  c.lookup,
					})
				}
			}
			c.Types[id] = u
		case ENUM:
			en := &Enum{
				id:   id,
				name: c.getString(uint32(t.Name)),
				info: t.Info,
			}
			enums := make([]enum, t.Info.VarLen())
			if err := binary.Read(r, binary.LittleEndian, &enums); err != nil {
				return fmt.Errorf("failed to read enums: %v", err)
			}
			for _, e := range enums {
				en.Fields = append(en.Fields, enumField{
					Name:  c.getString(uint32(e.Name)),
					Value: e.Value,
				})
			}
			c.Types[id] = en
		case FORWARD:
			c.Types[id] = &Forward{
				id:   id,
				name: c.getString(uint32(t.Name)),
				info: t.Info,
			}
		case POINTER:
			c.Types[id] = &Pointer{
				id:        id,
				name:      c.getString(uint32(t.Name)),
				info:      t.Info,
				reference: t.SizeOrType,
				lookupFn:  c.lookup,
			}
		case TYPEDEF:
			c.Types[id] = &Typedef{
				id:        id,
				name:      c.getString(uint32(t.Name)),
				info:      t.Info,
				reference: t.SizeOrType,
				lookupFn:  c.lookup,
			}
		case VOLATILE:
			c.Types[id] = &Volatile{
				id:        id,
				name:      c.getString(uint32(t.Name)),
				info:      t.Info,
				reference: t.SizeOrType,
				lookupFn:  c.lookup,
			}
		case CONST:
			c.Types[id] = &Const{
				id:        id,
				name:      c.getString(uint32(t.Name)),
				info:      t.Info,
				reference: t.SizeOrType,
				lookupFn:  c.lookup,
			}
		case RESTRICT:
			c.Types[id] = &Restrict{
				id:        id,
				name:      c.getString(uint32(t.Name)),
				info:      t.Info,
				reference: t.SizeOrType,
				lookupFn:  c.lookup,
			}
		case PTRAUTH:
			var ptrauth ptrAuthData
			if err := binary.Read(r, binary.LittleEndian, &ptrauth); err != nil {
				return fmt.Errorf("failed to read ptr auth data: %v", err)
			}
			c.Types[id] = &PtrAuth{
				id:        id,
				name:      c.getString(uint32(t.Name)),
				info:      t.Info,
				data:      ptrauth,
				reference: t.SizeOrType,
				lookupFn:  c.lookup,
			}
		case UNKNOWN:
			break /* hole in type id space */
		default:
			return fmt.Errorf("unexpected kind %d", t.Info.Kind())
		}

		id++
	}

	return nil
}
