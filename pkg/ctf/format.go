package ctf

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
)

type Type interface {
	ID() int
	Name() string
	Info() info
	ParentID() int
	Type() string
	String() string
	Dump() string
}

type Integer struct {
	id       int
	name     string
	info     info
	encoding intEncoding
}

func (i *Integer) ID() int {
	return i.id
}
func (i *Integer) Name() string {
	return i.name
}
func (i *Integer) Info() info {
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

type Float struct {
	id       int
	name     string
	info     info
	encoding floatEncoding
}

func (f *Float) ID() int {
	return f.id
}

func (f *Float) Name() string {
	return f.name
}

func (f *Float) Info() info {
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

type Array struct {
	id   int
	name string
	info info
	array
	lookupFn func(int) Type
}

func (a *Array) ID() int {
	return a.id
}

func (a *Array) Name() string {
	return a.name
}

func (a *Array) Info() info {
	return a.info
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

func (a *Array) Type() string { return a.String() }

func (a *Array) String() string {
	var n string
	if a.name != "(anon)" {
		n = a.name
	}
	return fmt.Sprintf(
		"%s %s[%d]",
		a.Contents(),
		n,
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

type Function struct {
	id       int
	name     string
	info     info
	ret      uint16
	args     []uint16
	lookupFn func(int) Type
}

func (f *Function) ID() int {
	return f.id
}

func (f *Function) Name() string {
	return f.name
}

func (f *Function) Info() info {
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
			argStrs = append(argStrs, t.String())
		}
		return fmt.Sprintf("<arg%d type not found>", idx)
	}

	return strings.Join(argStrs, ", ")
}

func (f *Function) ParentID() int {
	return 0
}

func (f *Function) Type() string {
	return f.String()
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
	fmt.Printf("%s)", strings.Join(sargs, ","))
	return fdump
}

type Member struct {
	parent    int
	name      string
	offset    uint64
	reference uint16
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

type Struct struct {
	id     int
	name   string
	info   info
	size   uint64
	Fields []Member
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

func (s *Struct) Info() info {
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
		return s.String()
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
		fmt.Fprintf(w, "    %s\t%s;\t// off=%d\n",
			f.Type(),
			f.name,
			f.offset,
		)
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
		fmt.Fprintf(w, "    %s\ttype=%d\toff=%d\n",
			f.Name(),
			f.reference,
			f.offset,
		)
	}
	w.Flush()
	return buf.String()
}

type Union struct {
	id     int
	name   string
	info   info
	size   uint64
	Fields []Member
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

func (s *Union) Info() info {
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
	var sout string
	sout = fmt.Sprintf(
		"union %s {\t\t// (%d bytes)\n",
		s.Name(),
		s.size,
	)
	for _, f := range s.Fields {
		sout += fmt.Sprintf("\t%s\t%s;\n",
			f.Type(),
			f.name,
		)
	}
	sout += "};"
	return sout
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
		sdump += fmt.Sprintf("\t%s type=%d off=%d\n",
			f.Name(),
			f.reference,
			f.offset,
		)
	}
	return sdump
}

type enumField struct {
	Name  string
	Value int32
}

type Enum struct {
	id     int
	name   string
	info   info
	Fields []enumField
}

func (e *Enum) ID() int {
	return e.id
}

func (e *Enum) Name() string {
	return e.name
}

func (e *Enum) Info() info {
	return e.info
}

func (e *Enum) ParentID() int {
	return 0
}

func (e *Enum) Type() string { return e.String() }
func (e *Enum) String() string {
	eout := "enum {\n"
	for _, f := range e.Fields {
		eout += fmt.Sprintf("\t%s = %d\n",
			f.Name,
			f.Value,
		)
	}
	eout += "}"
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

type Forward struct {
	id   int
	name string
	info info
}

func (f *Forward) ID() int {
	return f.id
}

func (f *Forward) Name() string {
	return f.name
}

func (f *Forward) Info() info {
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

type Pointer struct {
	id        int
	name      string
	info      info
	reference uint16
	lookupFn  func(int) Type
}

func (p *Pointer) ID() int {
	return p.id
}

func (p *Pointer) Name() string {
	return p.name
}

func (p *Pointer) Info() info {
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
	return fmt.Sprintf("%s *", p.Reference())
}

func (p *Pointer) String() string {
	return fmt.Sprintf("%s *", p.Reference())
}

func (p *Pointer) Dump() string {
	return fmt.Sprintf("%s %s %s refers to %d",
		isRootIDFmtStr(p.info.IsRoot(), p.id),
		p.info.Kind(),
		p.name,
		p.reference,
	)
}

type Typedef struct {
	id        int
	name      string
	info      info
	reference uint16
	lookupFn  func(int) Type
}

func (p *Typedef) ID() int {
	return p.id
}

func (p *Typedef) Name() string {
	return p.name
}

func (p *Typedef) Info() info {
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

type Volatile struct {
	id        int
	name      string
	info      info
	reference uint16
	lookupFn  func(int) Type
}

func (p *Volatile) ID() int {
	return p.id
}

func (p *Volatile) Name() string {
	return p.name
}

func (p *Volatile) Info() info {
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

type Const struct {
	id        int
	name      string
	info      info
	reference uint16
	lookupFn  func(int) Type
}

func (p *Const) ID() int {
	return p.id
}

func (p *Const) Name() string {
	return p.name
}

func (p *Const) Info() info {
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

type Restrict struct {
	id        int
	name      string
	info      info
	reference uint16
	lookupFn  func(int) Type
}

func (p *Restrict) ID() int {
	return p.id
}

func (p *Restrict) Name() string {
	return p.name
}

func (p *Restrict) Info() info {
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

type PtrAuth struct {
	id        int
	name      string
	info      info
	data      ptrAuthData
	reference uint16
	lookupFn  func(int) Type
}

func (p *PtrAuth) ID() int {
	return p.id
}

func (p *PtrAuth) Name() string {
	return p.name
}

func (p *PtrAuth) Info() info {
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
		"__ptrauth(%s, %t, %04x) %s",
		p.data.Key(),
		p.data.Discriminated(),
		p.data.Discriminator(),
		p.Reference(),
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

type global struct {
	Address   uint64
	Name      string
	Reference int
	Type      Type
}

type function struct {
	Address   uint64
	Name      string
	Return    Type
	Arguments []Type
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
