package ctf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
)

type Type interface {
	ID() int
	Name() string
	Info() Info
	ParentID() int
	Type() string
	String() string
	Dump() string
}

type Integer struct {
	id       int
	name     string
	info     Info
	encoding intEncoding
}

func (i *Integer) ID() int {
	return i.id
}
func (i *Integer) Name() string {
	return i.name
}
func (i *Integer) Info() Info {
	return i.info
}
func (i *Integer) Encoding() string {
	return i.encoding.Encoding().String()
}
func (i *Integer) Offset() uint32 {
	return i.encoding.Offset()
}
func (i *Integer) Bits() uint32 {
	return i.encoding.Bits()
}
func (i *Integer) ParentID() int {
	return 0
}
func (i *Integer) Type() string {
	return i.name
}
func (i *Integer) String() string {
	return i.name
}
func (i *Integer) Dump() string {
	return fmt.Sprintf("%s %s %s encoding=%s offset=%d bits=%d\n",
		isRootIDFmtStr(i.info.IsRoot(), i.id),
		i.info.Kind(),
		i.name,
		i.encoding.Encoding(),
		i.encoding.Offset(),
		i.encoding.Bits(),
	)
}
func (i *Integer) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID       int         `json:"id,omitempty"`
		Name     string      `json:"name,omitempty"`
		Info     Info        `json:"info,omitempty"`
		Encoding intEncoding `json:"encoding,omitempty"`
	}{
		ID:       i.id,
		Name:     i.name,
		Info:     i.info,
		Encoding: i.encoding,
	})
}

type Float struct {
	id       int
	name     string
	info     Info
	encoding floatEncoding
}

func (f *Float) ID() int {
	return f.id
}
func (f *Float) Name() string {
	return f.name
}
func (f *Float) Info() Info {
	return f.info
}
func (f *Float) Encoding() string {
	return f.encoding.Encoding().String()
}
func (f *Float) Offset() uint32 {
	return f.encoding.Offset()
}
func (f *Float) Bits() uint32 {
	return f.encoding.Bits()
}
func (f *Float) ParentID() int {
	return 0
}
func (f *Float) Type() string {
	return f.name
}
func (f *Float) String() string {
	return f.name
}
func (f *Float) Dump() string {
	return fmt.Sprintf("%s %s %s encoding=%s offset=%d bits=%d",
		isRootIDFmtStr(f.info.IsRoot(), f.id),
		f.info.Kind(),
		f.name,
		f.encoding.Encoding(),
		f.encoding.Offset(),
		f.encoding.Bits(),
	)
}
func (f *Float) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID       int           `json:"id,omitempty"`
		Name     string        `json:"name,omitempty"`
		Info     Info          `json:"info,omitempty"`
		Encoding floatEncoding `json:"encoding,omitempty"`
	}{
		ID:       f.id,
		Name:     f.name,
		Info:     f.info,
		Encoding: f.encoding,
	})
}

type Array struct {
	id   int
	name string
	info Info
	array
	lookupFn func(int) Type
}

func (a *Array) ID() int {
	return a.id
}
func (a *Array) Name() string {
	if a.name == "(anon)" {
		return ""
	}
	return " " + a.name
}
func (a *Array) Info() Info {
	return a.info
}
func (a *Array) Index() string {
	if t := a.lookupFn(int(a.array.Index)); t != nil {
		return t.Type()
	}
	return "<type not found>"
}
func (a *Array) Contents() string {
	if t := a.lookupFn(int(a.array.Contents)); t != nil {
		return t.Type()
	}
	return "<type not found>"
}
func (a *Array) ParentID() int {
	return 0
}
func (a *Array) Type() string {
	return strings.TrimSuffix(a.String(), ";")
}
func (a *Array) String() string {
	return fmt.Sprintf(
		"%s%s[%d];",
		a.Contents(),
		a.Name(),
		a.NumElements,
	)
}
func (a *Array) Dump() string {
	return fmt.Sprintf("%s %s %s content: %d index: %d nelems: %d",
		isRootIDFmtStr(a.info.IsRoot(), a.id),
		a.info.Kind(),
		a.name,
		a.array.Contents,
		a.array.Index,
		a.array.NumElements,
	)
}
func (a *Array) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID          int    `json:"id,omitempty"`
		Name        string `json:"name,omitempty"`
		Info        Info   `json:"info,omitempty"`
		ContentsID  uint   `json:"contents_id,omitempty"`  /* reference to type of array contents */
		Contents    string `json:"contents,omitempty"`     /* reference to type of array contents */
		IndexID     uint   `json:"index_id,omitempty"`     /* reference to type of array index */
		IndexType   string `json:"index_type,omitempty"`   /* reference to type of array index */
		NumElements uint32 `json:"num_elements,omitempty"` /* number of elements */
	}{
		ID:          a.id,
		Name:        a.name,
		Info:        a.info,
		ContentsID:  uint(a.array.Contents),
		Contents:    a.Contents(),
		IndexID:     uint(a.array.Index),
		IndexType:   a.Index(),
		NumElements: a.array.NumElements,
	})
}

type Function struct {
	id       int
	name     string
	info     Info
	ret      uint
	args     []uint32
	lookupFn func(int) Type
}

type funcArg struct {
	ID   int    `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}

func (f *Function) ID() int {
	return f.id
}
func (f *Function) Name() string {
	return f.name
}
func (f *Function) Info() Info {
	return f.info
}
func (f *Function) Return() string {
	if t := f.lookupFn(int(f.ret)); t != nil {
		return t.Type()
	}
	return "<return type not found>"
}
func (f *Function) Args() string {
	var argStrs []string
	for idx, arg := range f.args {
		if t := f.lookupFn(int(arg)); t != nil {
			argStrs = append(argStrs, t.Type())
		} else {
			return fmt.Sprintf("<arg%d type not found>", idx)
		}
	}
	return strings.Join(argStrs, ", ")
}
func (f *Function) ParentID() int {
	return 0
}
func (f *Function) Type() string {
	return strings.TrimSuffix(f.String(), ";")
}
func (f *Function) String() string {
	return fmt.Sprintf(
		"%s %s(%s);",
		f.Return(),
		f.name,
		f.Args(),
	)
}
func (f *Function) Dump() string {
	var fdump string
	fdump = fmt.Sprintf("%s %s %s returns: %d args: (",
		isRootIDFmtStr(f.info.IsRoot(), f.id),
		f.info.Kind(),
		f.name,
		f.ret,
	)
	var sargs []string
	for _, a := range f.args {
		sargs = append(sargs, strconv.Itoa(int(a)))
	}
	fdump += fmt.Sprintf("%s)", strings.Join(sargs, ","))
	return fdump
}
func (f *Function) MarshalJSON() ([]byte, error) {
	var args []funcArg
	for idx, arg := range f.args {
		if t := f.lookupFn(int(arg)); t != nil {
			args = append(args, funcArg{
				ID:   int(arg),
				Type: t.Type(),
			})
		} else {
			args = append(args, funcArg{
				ID:   int(arg),
				Type: fmt.Sprintf("<arg%d type ref %d not found>", idx, arg),
			})
		}
	}
	return json.Marshal(&struct {
		ID        int       `json:"id,omitempty"`
		Name      string    `json:"name,omitempty"`
		Info      Info      `json:"info,omitempty"`
		ReturnID  uint      `json:"return_id,omitempty"`
		Return    string    `json:"return,omitempty"`
		Arguments []funcArg `json:"arguments,omitempty"`
	}{
		ID:        f.id,
		Name:      f.name,
		Info:      f.info,
		ReturnID:  uint(f.ret),
		Return:    f.Return(),
		Arguments: args,
	})
}

type Member struct {
	parent    int
	name      string
	offset    uint64
	reference uint
	lookupFn  func(int) Type
}

func (m Member) ParentID() int {
	return m.parent
}
func (m Member) Name() string {
	return m.name
}
func (m Member) Type() string {
	if t := m.lookupFn(int(m.reference)); t != nil {
		return t.Type()
	}
	return "<member type not found>"
}
func (m Member) Offset() uint64 {
	return m.offset
}
func (m Member) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID     int    `json:"id,omitempty"`
		Name   string `json:"name,omitempty"`
		Type   string `json:"type,omitempty"`
		Offset uint64 `json:"offset"`
	}{
		ID:     int(m.reference),
		Name:   m.name,
		Type:   m.Type(),
		Offset: m.offset,
	})
}

type Struct struct {
	id       int
	name     string
	info     Info
	size     uint64
	Fields   []Member
	lookupFn func(int) Type
}

func (s *Struct) ID() int {
	return s.id
}
func (s *Struct) Name() string {
	if s.name == "(anon)" {
		return ""
	}
	return s.name
}
func (s *Struct) Info() Info {
	return s.info
}
func (s *Struct) ParentID() int {
	return 0
}
func (s *Struct) Size() uint64 {
	return s.size
}
func (s *Struct) Type() string {
	if s.name == "(anon)" {
		return strings.TrimSuffix(s.String(), ";")
	}
	return "struct " + s.Name()
}
func (s *Struct) String() string {
	buf := bytes.NewBufferString("")
	w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
	fmt.Fprintf(w,
		"struct %s {\t\t// (%d bytes)\n",
		s.Name(),
		s.size,
	)
	for _, f := range s.Fields {
		t := s.lookupFn(int(f.reference))
		if t != nil && t.Info().Kind() == ARRAY {
			fmt.Fprintf(w, "    %s\t%s[%d];\t// off=%#x\n",
				t.(*Array).Contents(),
				f.name,
				t.(*Array).NumElements,
				f.offset,
			)
		} else {
			fmt.Fprintf(w, "    %s\t%s;\t// off=%#x\n",
				f.Type(),
				f.name,
				f.offset,
			)
		}
	}
	fmt.Fprintf(w, "};")
	w.Flush()
	return buf.String()
}
func (s *Struct) Dump() string {
	buf := bytes.NewBufferString("")
	w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
	fmt.Fprintf(w, "%s %s %s (%d bytes)\n",
		isRootIDFmtStr(s.info.IsRoot(), s.id),
		s.info.Kind(),
		s.name,
		s.size,
	)
	for _, f := range s.Fields {
		fmt.Fprintf(w, "    %s\ttype=%d\toff=%#x\n",
			f.Name(),
			f.reference,
			f.offset,
		)
	}
	w.Flush()
	return buf.String()
}
func (s *Struct) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID     int      `json:"id,omitempty"`
		Name   string   `json:"name,omitempty"`
		Info   Info     `json:"info,omitempty"`
		Size   uint64   `json:"size,omitempty"`
		Fields []Member `json:"fields,omitempty"`
	}{
		ID:     s.id,
		Name:   s.name,
		Info:   s.info,
		Size:   s.size,
		Fields: s.Fields,
	})
}

type Union struct {
	id       int
	name     string
	info     Info
	size     uint64
	Fields   []Member
	lookupFn func(int) Type
}

func (s *Union) ID() int {
	return s.id
}
func (s *Union) Name() string {
	if s.name == "(anon)" {
		return ""
	}
	return s.name
}
func (s *Union) Info() Info {
	return s.info
}
func (s *Union) ParentID() int {
	return 0
}
func (s *Union) Size() uint64 {
	return s.size
}
func (s *Union) Type() string {
	return "union " + s.name
}
func (s *Union) String() string {
	buf := bytes.NewBufferString("")
	w := tabwriter.NewWriter(buf, 0, 0, 1, ' ', 0)
	fmt.Fprintf(w,
		"union %s {\t\t// (%d bytes)\n",
		s.Name(),
		s.size,
	)
	for _, f := range s.Fields {
		t := s.lookupFn(int(f.reference))
		if t != nil && t.Info().Kind() == ARRAY {
			fmt.Fprintf(w, "    %s\t%s[%d];\n",
				t.(*Array).Contents(),
				f.name,
				t.(*Array).NumElements,
			)
		} else {
			fmt.Fprintf(w, "    %s\t%s;\n",
				f.Type(),
				f.name,
			)
		}
	}
	fmt.Fprintf(w, "};")
	w.Flush()
	return buf.String()
}
func (s *Union) Dump() string {
	var sdump string
	sdump = fmt.Sprintf("%s %s %s (%d bytes)\n",
		isRootIDFmtStr(s.info.IsRoot(), s.id),
		s.info.Kind(),
		s.name,
		s.size,
	)
	for _, f := range s.Fields {
		sdump += fmt.Sprintf("\t%s type=%d off=%#x\n",
			f.Name(),
			f.reference,
			f.offset,
		)
	}
	return sdump
}
func (s *Union) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID     int      `json:"id,omitempty"`
		Name   string   `json:"name,omitempty"`
		Info   Info     `json:"info,omitempty"`
		Size   uint64   `json:"size,omitempty"`
		Fields []Member `json:"fields,omitempty"`
	}{
		ID:     s.id,
		Name:   s.name,
		Info:   s.info,
		Size:   s.size,
		Fields: s.Fields,
	})
}

type enumField struct {
	Name  string `json:"name,omitempty"`
	Value int32  `json:"value,omitempty"`
}

type Enum struct {
	id     int
	name   string
	info   Info
	Fields []enumField
}

func (e *Enum) ID() int {
	return e.id
}
func (e *Enum) Name() string {
	return e.name
}
func (e *Enum) Info() Info {
	return e.info
}
func (e *Enum) ParentID() int {
	return 0
}
func (e *Enum) Type() string { return "enum " + e.name }
func (e *Enum) String() string {
	eout := fmt.Sprintf("enum %s {\n", e.name)
	for _, f := range e.Fields {
		eout += fmt.Sprintf("\t%s = %d\n",
			f.Name,
			f.Value,
		)
	}
	eout += "};"
	return eout
}
func (e *Enum) Dump() string {
	var edump string
	edump = fmt.Sprintf("%s %s %s\n",
		isRootIDFmtStr(e.info.IsRoot(), e.id),
		e.info.Kind(),
		e.name,
	)
	for _, f := range e.Fields {
		edump += fmt.Sprintf("\t%s = %d\n",
			f.Name,
			f.Value,
		)
	}
	return edump
}
func (e *Enum) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID     int         `json:"id,omitempty"`
		Name   string      `json:"name,omitempty"`
		Info   Info        `json:"info,omitempty"`
		Fields []enumField `json:"fields,omitempty"`
	}{
		ID:     e.id,
		Name:   e.name,
		Info:   e.info,
		Fields: e.Fields,
	})
}

type Forward struct {
	id   int
	name string
	info Info
}

func (f *Forward) ID() int {
	return f.id
}
func (f *Forward) Name() string {
	return f.name
}
func (f *Forward) Info() Info {
	return f.info
}
func (f *Forward) ParentID() int {
	return 0
}
func (f *Forward) Type() string {
	return f.name
}
func (f *Forward) String() string {
	return f.name
}
func (f *Forward) Dump() string {
	return fmt.Sprintf("%s %s %s",
		isRootIDFmtStr(f.info.IsRoot(), f.id),
		f.info.Kind(),
		f.name,
	)
}
func (f *Forward) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID   int    `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
		Info Info   `json:"info,omitempty"`
	}{
		ID:   f.id,
		Name: f.name,
		Info: f.info,
	})
}

type Pointer struct {
	id        int
	name      string
	info      Info
	reference uint
	lookupFn  func(int) Type
}

func (p *Pointer) ID() int {
	return p.id
}
func (p *Pointer) Name() string {
	return p.name
}
func (p *Pointer) Info() Info {
	return p.info
}
func (p *Pointer) Reference() string {
	if t := p.lookupFn(int(p.reference)); t != nil {
		return t.Type()
	}
	return "<reference type not found>"
}
func (p *Pointer) ParentID() int {
	return int(p.reference)
}
func (p *Pointer) Type() string {
	return strings.TrimSuffix(p.String(), ";")
}
func (p *Pointer) String() string {
	return fmt.Sprintf("%s *;", p.Reference())
}
func (p *Pointer) Dump() string {
	return fmt.Sprintf("%s %s %s refers to %d",
		isRootIDFmtStr(p.info.IsRoot(), p.id),
		p.info.Kind(),
		p.name,
		p.reference,
	)
}
func (p *Pointer) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID          int    `json:"id,omitempty"`
		Name        string `json:"name,omitempty"`
		Info        Info   `json:"info,omitempty"`
		ReferenceID uint   `json:"reference_id,omitempty"`
		Reference   string `json:"reference,omitempty"`
	}{
		ID:          p.id,
		Name:        p.name,
		Info:        p.info,
		ReferenceID: uint(p.reference),
		Reference:   p.Reference(),
	})
}

type Typedef struct {
	id        int
	name      string
	info      Info
	reference uint
	lookupFn  func(int) Type
}

func (p *Typedef) ID() int {
	return p.id
}
func (p *Typedef) Name() string {
	return p.name
}
func (p *Typedef) Info() Info {
	return p.info
}
func (p *Typedef) Reference() string {
	if t := p.lookupFn(int(p.reference)); t != nil {
		return t.Type()
	}
	return "<reference type not found>"
}
func (p *Typedef) ParentID() int {
	return int(p.reference)
}
func (p *Typedef) Type() string {
	return p.Name()
}
func (p *Typedef) String() string {
	return fmt.Sprintf("typedef %s %s", p.name, p.Reference())
}
func (p *Typedef) Dump() string {
	return fmt.Sprintf("%s %s %s refers to %d",
		isRootIDFmtStr(p.info.IsRoot(), p.id),
		p.info.Kind(),
		p.name,
		p.reference,
	)
}
func (p *Typedef) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID          int    `json:"id,omitempty"`
		Name        string `json:"name,omitempty"`
		Info        Info   `json:"info,omitempty"`
		ReferenceID uint   `json:"reference_id,omitempty"`
		Reference   string `json:"reference,omitempty"`
	}{
		ID:          p.id,
		Name:        p.name,
		Info:        p.info,
		ReferenceID: uint(p.reference),
		Reference:   p.Reference(),
	})
}

type Volatile struct {
	id        int
	name      string
	info      Info
	reference uint
	lookupFn  func(int) Type
}

func (p *Volatile) ID() int {
	return p.id
}
func (p *Volatile) Name() string {
	return p.name
}
func (p *Volatile) Info() Info {
	return p.info
}
func (p *Volatile) Reference() string {
	if t := p.lookupFn(int(p.reference)); t != nil {
		return t.Type()
	}
	return "<reference type not found>"
}
func (p *Volatile) ParentID() int {
	return int(p.reference)
}
func (p *Volatile) Type() string {
	return fmt.Sprintf("volatile %s", p.Reference())
}
func (p *Volatile) String() string {
	return fmt.Sprintf("volatile %s", p.Reference())
}
func (p *Volatile) Dump() string {
	return fmt.Sprintf("%s %s %s refers to %d",
		isRootIDFmtStr(p.info.IsRoot(), p.id),
		p.info.Kind(),
		p.name,
		p.reference,
	)
}
func (p *Volatile) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID          int    `json:"id,omitempty"`
		Name        string `json:"name,omitempty"`
		Info        Info   `json:"info,omitempty"`
		ReferenceID uint   `json:"reference_id,omitempty"`
		Reference   string `json:"reference,omitempty"`
	}{
		ID:          p.id,
		Name:        p.name,
		Info:        p.info,
		ReferenceID: uint(p.reference),
		Reference:   p.Reference(),
	})
}

type Const struct {
	id        int
	name      string
	info      Info
	reference uint
	lookupFn  func(int) Type
}

func (p *Const) ID() int {
	return p.id
}
func (p *Const) Name() string {
	return p.name
}
func (p *Const) Info() Info {
	return p.info
}
func (p *Const) Reference() string {
	if t := p.lookupFn(int(p.reference)); t != nil {
		return t.Type()
	}
	return "<reference type not found>"
}
func (p *Const) ParentID() int {
	return int(p.reference)
}
func (p *Const) Type() string {
	return fmt.Sprintf("const %s", p.Reference())
}
func (p *Const) String() string {
	return fmt.Sprintf("const %s", p.Reference())
}
func (p *Const) Dump() string {
	return fmt.Sprintf("%s %s %s refers to %d",
		isRootIDFmtStr(p.info.IsRoot(), p.id),
		p.info.Kind(),
		p.name,
		p.reference,
	)
}
func (p *Const) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID          int    `json:"id,omitempty"`
		Name        string `json:"name,omitempty"`
		Info        Info   `json:"info,omitempty"`
		ReferenceID uint   `json:"reference_id,omitempty"`
		Reference   string `json:"reference,omitempty"`
	}{
		ID:          p.id,
		Name:        p.name,
		Info:        p.info,
		ReferenceID: uint(p.reference),
		Reference:   p.Reference(),
	})
}

type Restrict struct {
	id        int
	name      string
	info      Info
	reference uint
	lookupFn  func(int) Type
}

func (p *Restrict) ID() int {
	return p.id
}
func (p *Restrict) Name() string {
	return p.name
}
func (p *Restrict) Info() Info {
	return p.info
}
func (p *Restrict) Reference() string {
	if t := p.lookupFn(int(p.reference)); t != nil {
		return t.Type()
	}
	return "<reference type not found>"
}
func (p *Restrict) ParentID() int {
	return int(p.reference)
}
func (p *Restrict) Type() string {
	return fmt.Sprintf("restrict %s", p.Reference())
}
func (p *Restrict) String() string {
	return fmt.Sprintf("restrict %s", p.Reference())
}
func (p *Restrict) Dump() string {
	return fmt.Sprintf("%s %s %s refers to %d",
		isRootIDFmtStr(p.info.IsRoot(), p.id),
		p.info.Kind(),
		p.name,
		p.reference,
	)
}
func (p *Restrict) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID          int    `json:"id,omitempty"`
		Name        string `json:"name,omitempty"`
		Info        Info   `json:"info,omitempty"`
		ReferenceID uint   `json:"reference_id,omitempty"`
		Reference   string `json:"reference,omitempty"`
	}{
		ID:          p.id,
		Name:        p.name,
		Info:        p.info,
		ReferenceID: uint(p.reference),
		Reference:   p.Reference(),
	})
}

type PtrAuth struct {
	id        int
	name      string
	info      Info
	data      ptrAuthData
	reference uint
	lookupFn  func(int) Type
}

func (p *PtrAuth) ID() int {
	return p.id
}
func (p *PtrAuth) Name() string {
	return p.name
}
func (p *PtrAuth) Info() Info {
	return p.info
}
func (p *PtrAuth) Reference() string {
	if t := p.lookupFn(int(p.reference)); t != nil {
		return t.Type()
	}
	return "<reference type not found>"
}
func (p *PtrAuth) ParentID() int {
	return int(p.reference)
}
func (p *PtrAuth) Type() string { return p.String() }
func (p *PtrAuth) String() string {
	return fmt.Sprintf(
		"%s __ptrauth(%s, %t, %04x)",
		p.Reference(),
		p.data.Key(),
		p.data.Discriminated(),
		p.data.Discriminator(),
	)
}
func (p *PtrAuth) Dump() string {
	return fmt.Sprintf("%s %s %s refers to %d (key=%s, addr_div=%t, div=%04x)",
		isRootIDFmtStr(p.info.IsRoot(), p.id),
		p.info.Kind(),
		p.name,
		p.reference,
		p.data.Key(),
		p.data.Discriminated(),
		p.data.Discriminator(),
	)
}
func (p *PtrAuth) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		ID          int         `json:"id,omitempty"`
		Name        string      `json:"name,omitempty"`
		Info        Info        `json:"info,omitempty"`
		Data        ptrAuthData `json:"data,omitempty"`
		ReferenceID uint        `json:"reference_id,omitempty"`
		Reference   string      `json:"reference,omitempty"`
	}{
		ID:          p.id,
		Name:        p.name,
		Info:        p.info,
		Data:        p.data,
		ReferenceID: uint(p.reference),
		Reference:   p.Reference(),
	})
}

type global struct {
	Address   uint64 `json:"address,omitempty"`
	Name      string `json:"name,omitempty"`
	Reference int    `json:"reference,omitempty"`
	Type      Type   `json:"type,omitempty"`
}

func (g global) String() string {
	if g.Type != nil {
		return fmt.Sprintf("%#x: %s %s", g.Address, g.Type.Type(), g.Name)
	}
	if g.Reference == 0 {
		return fmt.Sprintf("%#x: <unknown> %s", g.Address, g.Name)
	}
	return fmt.Sprintf("%#x: %d %s", g.Address, g.Reference, g.Name)
}

type function struct {
	Address   uint64 `json:"address,omitempty"`
	Name      string `json:"name,omitempty"`
	Return    Type   `json:"return,omitempty"`
	Arguments []Type `json:"arguments,omitempty"`
}

func (f function) String() string {
	var args []string
	for _, arg := range f.Arguments {
		args = append(args, arg.Type())
	}
	return fmt.Sprintf("%#x: %s %s(%s);", f.Address, f.Return.Type(), f.Name, strings.Join(args, ", "))
}

func isRootIDFmtStr(isroot bool, id int) string {
	if isroot {
		return fmt.Sprintf("<%d>", id)
	}
	return fmt.Sprintf("[%d]", id)
}

func (h header) String() string {
	return fmt.Sprintf(
		"Magic        = %#x\n"+
			"Version      = %d\n"+
			"Flags        = %#x\n"+
			"Parent Label = %s\n"+
			"Parent Name  = %s\n"+
			"Label Offset = %d\n"+
			"Obj Offset   = %d\n"+
			"Func Offset  = %#x\n"+
			"Type Offset  = %#x\n"+
			"Str Offset   = %#x\n"+
			"Str Len      = %#x\n",
		h.Preamble.Magic,
		h.Preamble.Version,
		h.Preamble.Flags,
		h.ParentLabel,
		h.ParentName,
		h.LabelOffset,
		h.ObjOffset,
		h.FuncOffset,
		h.TypeOffset,
		h.StrOffset,
		h.StrLen,
	)
}
