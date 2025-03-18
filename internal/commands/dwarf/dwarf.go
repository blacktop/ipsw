package dwarf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"

	"github.com/apex/log"
	dwf "github.com/blacktop/go-dwarf"
	"github.com/blacktop/go-macho"
	"github.com/blacktop/ipsw/internal/utils"
)

type Config struct {
	Markdown    bool
	Color       bool
	DiffTool    string
	ShowOffsets bool
}

func GetAllStructs(path string) (map[string]*dwf.StructType, error) {
	types := make(map[string]*dwf.StructType)

	m, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return nil, err
	}

	r := df.Reader()

	for {
		entry, err := r.Next()
		if err != nil {
			break
		}
		if entry == nil {
			break
		}

		var st *dwf.StructType
		if entry.Tag == dwf.TagStructType {
			typ, err := df.Type(entry.Offset)
			if err != nil {
				continue
			}
			st = typ.(*dwf.StructType)
			if st.Incomplete {
				continue
			}
			types[st.StructName] = st
		}
	}

	return types, nil
}

func GetAllEnums(path string) (map[string]*dwf.EnumType, error) {
	enums := make(map[string]*dwf.EnumType)

	m, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return nil, err
	}

	r := df.Reader()

	for {
		entry, err := r.Next()
		if err != nil {
			break
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwf.TagEnumerationType {
			typ, err := df.Type(entry.Offset)
			if err != nil {
				continue
			}
			enum := typ.(*dwf.EnumType)
			enums[enum.EnumName] = enum
		}
	}

	return enums, nil
}

func GetName(path, name string) (nameMap map[string]*dwf.FuncType, err error) {
	nameMap = make(map[string]*dwf.FuncType)

	m, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return nil, err
	}

	r := df.Reader()

	var nameOffs []dwf.Offset

	off, err := df.LookupName(name)
	if err != nil {
		if !errors.Is(err, dwf.ErrHashNotFound) {
			return nil, fmt.Errorf("failed to find name %s: %v", name, err)
		}
		offs, err := df.LookupDebugName(name)
		if err != nil {
			return nil, fmt.Errorf("failed to find debug name %s: %v", name, err)
		}
		if len(offs) > 1 {
			log.Warnf("found multiple debug names entries for %s", name)
		}
		for _, o := range offs {
			switch o.Tag {
			case dwf.TagStructType, dwf.TagEnumerationType, dwf.TagUnionType, dwf.TagTypedef, dwf.TagArrayType, dwf.TagPointerType:
			default: // NOT a type
				nameOffs = append(nameOffs, o.DIEOffset)
			}
		}
	} else {
		nameOffs = append(nameOffs, off)
	}

	for _, off := range nameOffs {
		filename := "<unknown>"

		r.Seek(off)

		entry, err := r.Next()
		if err != nil {
			return nil, err
		}

		fs, err := df.FilesForEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to get files for entry: %v", err)
		}
		if idx, ok := entry.Val(dwf.AttrDeclFile).(int64); ok {
			if idx < int64(len(fs)) {
				filename = fs[idx].Name
			}
		}
		if idx, ok := entry.Val(dwf.AttrCallFile).(int64); ok {
			if idx < int64(len(fs)) {
				filename = fs[idx].Name
			}
		}
		if line, ok := entry.Val(dwf.AttrDeclLine).(int64); ok {
			filename += fmt.Sprintf("#L%d", line)
		}
		if line, ok := entry.Val(dwf.AttrCallLine).(int64); ok {
			filename += fmt.Sprintf("#L%d", line)
		}

		if entry.Tag == dwf.TagSubprogram || entry.Tag == dwf.TagSubroutineType || entry.Tag == dwf.TagInlinedSubroutine {
			typ, err := df.Type(entry.Offset)
			if err != nil {
				return nil, err
			}
			nameMap[filename] = typ.(*dwf.FuncType)
		} else {
			typ, err := df.Type(entry.Offset)
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("did not find tag func type: found %s; %s", entry.Tag, typ.String())
		}
	}

	return nameMap, nil
}

func GetType(path, name string, showOffsets bool) (typeMap map[string]string, err error) {
	typeMap = make(map[string]string)

	m, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return nil, err
	}

	r := df.Reader()

	var typoffs []dwf.Offset

	off, err := df.LookupType(name)
	if err != nil {
		if !errors.Is(err, dwf.ErrHashNotFound) {
			return nil, fmt.Errorf("failed to find name %s: %v", name, err)
		}
		offs, err := df.LookupDebugName(name)
		if err != nil {
			return nil, fmt.Errorf("failed to find debug name %s: %v", name, err)
		}
		if len(offs) > 1 {
			log.Warnf("found multiple debug names entries for %s", name)
		}
		for _, o := range offs {
			switch o.Tag {
			case dwf.TagStructType, dwf.TagEnumerationType, dwf.TagUnionType, dwf.TagTypedef, dwf.TagArrayType, dwf.TagPointerType:
				typoffs = append(typoffs, o.DIEOffset)
			}
		}
	} else {
		typoffs = append(typoffs, off)
	}

	for _, off := range typoffs {
		filename := "<unknown>"

		r.Seek(off)

		entry, err := r.Next()
		if err != nil {
			return nil, err
		}

		fs, err := df.FilesForEntry(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to get files for entry: %v", err)
		}
		if idx, ok := entry.Val(dwf.AttrDeclFile).(int64); ok {
			if idx < int64(len(fs)) {
				filename = fs[idx].Name
			}
		}
		if line, ok := entry.Val(dwf.AttrDeclLine).(int64); ok {
			filename += fmt.Sprintf("#L%d", line)
		}

		typ, err := df.Type(entry.Offset)
		if err != nil {
			return nil, fmt.Errorf("failed to get type for entry: %v", err)
		}

		switch t := typ.(type) {
		case *dwf.StructType:
			if t.Incomplete {
				continue
			}
			typeMap[filename] = t.Defn(showOffsets)
		case *dwf.ArrayType, *dwf.PtrType, *dwf.EnumType:
			typeMap[filename] = t.String()
		case *dwf.TypedefType:
			if enum, ok := t.Type.(*dwf.EnumType); ok {
				typeMap[filename] = fmt.Sprintf("typedef %s %s;", enum.String(), t.Name)
			}
			typeMap[filename] = fmt.Sprintf("typedef %s %s;", t.Type.Common().Name, t.Name)
		default:
			return nil, fmt.Errorf("did not find supported type: found %s; %s", entry.Tag, typ.String())
		}
	}

	return typeMap, nil
}

func DiffStructures(prevMachO, currMachO string, conf *Config) (string, error) {
	var dat bytes.Buffer
	buf := bufio.NewWriter(&dat)

	types1, err := GetAllStructs(prevMachO)
	if err != nil {
		return "", err
	}

	types2, err := GetAllStructs(currMachO)
	if err != nil {
		return "", err
	}

	seen := make(map[string]bool)

	for name, struct2 := range types2 {
		if _, ok := seen[name]; !ok {
			seen[name] = true
			if struct2.Incomplete {
				continue
			}
			if struct1, found := types1[name]; found {
				if conf.Markdown {
					out, err := utils.GitDiff(struct1.Defn(conf.ShowOffsets), struct2.Defn(conf.ShowOffsets), &utils.GitDiffConfig{Color: false, Tool: "git"})
					if err != nil {
						return "", err
					}
					if len(out) > 0 {
						buf.WriteString(fmt.Sprintf("#### %s\n\n```diff\n%s\n```\n", name, out))
					}
				} else {
					out, err := utils.GitDiff(struct1.Defn(conf.ShowOffsets), struct2.Defn(conf.ShowOffsets), &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
					if err != nil {
						return "", err
					}
					if len(out) > 0 {
						buf.WriteString(fmt.Sprintf("DIFF: %s\n\n%s\n", name, out))
					}
				}
			} else { // NOT FOUND (NEW STRUCT)
				if conf.Markdown {
					buf.WriteString(fmt.Sprintf("#### %s\n\n```c\n%s\n```\n", struct2.StructName, utils.ClangFormat(struct2.Defn(conf.ShowOffsets), struct2.StructName+".h", false)))
				} else {
					buf.WriteString(fmt.Sprintf("NEW: %s\n\n%s\n", struct2.StructName, utils.ClangFormat(struct2.Defn(conf.ShowOffsets), struct2.StructName+".h", conf.Color)))
				}
			}
		}
	}

	buf.Flush()

	return dat.String(), nil
}

func DiffEnums(prevMachO, currMachO string, conf *Config) (string, error) {
	var dat bytes.Buffer
	buf := bufio.NewWriter(&dat)

	enums1, err := GetAllEnums(prevMachO)
	if err != nil {
		return "", err
	}

	enums2, err := GetAllEnums(currMachO)
	if err != nil {
		return "", err
	}

	seen := make(map[string]bool)

	for name, enum2 := range enums2 {
		if _, ok := seen[name]; !ok {
			seen[name] = true
			if enum1, found := enums1[name]; found {
				if conf.Markdown {
					out, err := utils.GitDiff(enum1.String(), enum2.String(), &utils.GitDiffConfig{Color: false, Tool: "git"})
					if err != nil {
						return "", err
					}
					if len(out) > 0 {
						buf.WriteString(fmt.Sprintf("#### %s\n\n```diff\n%s\n```\n", name, out))
					}
				} else {
					out, err := utils.GitDiff(enum1.String(), enum2.String(), &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
					if err != nil {
						return "", err
					}
					if len(out) > 0 {
						buf.WriteString(fmt.Sprintf("DIFF: %s\n\n%s\n", name, out))
					}
				}
			} else { // NOT FOUND (NEW STRUCT)
				if conf.Markdown {
					buf.WriteString(fmt.Sprintf("#### %s\n\n```c\n%s\n```\n", name, utils.ClangFormat(enum2.String(), name+".h", false)))
				} else {
					buf.WriteString(fmt.Sprintf("NEW: %s\n\n%s\n", name, utils.ClangFormat(enum2.String(), name+".h", conf.Color)))
				}
			}
		}
	}

	buf.Flush()

	return dat.String(), nil
}

func DumpAllStructs(path string, conf *Config) error {
	types, err := GetAllStructs(path)
	if err != nil {
		return err
	}

	for name, st := range types {
		fmt.Println(utils.ClangFormat(st.Defn(conf.ShowOffsets), name+".h", conf.Color))
		println()
	}

	return nil
}

func DumpAllEnums(path string, conf *Config) error {
	types, err := GetAllEnums(path)
	if err != nil {
		return err
	}

	for name, enum := range types {
		fmt.Println(utils.ClangFormat(enum.String(), name+".h", conf.Color))
		println()
	}

	return nil
}

func DumpAllTypes(path string, conf *Config) error {
	m, err := macho.Open(path)
	if err != nil {
		return err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return err
	}

	r := df.Reader()

	for {
		entry, err := r.Next()
		if err != nil {
			break
		}
		if entry == nil {
			break
		}

		typ, err := df.Type(entry.Offset)
		if err != nil {
			continue
		}

		fmt.Println(utils.ClangFormat(typ.String()+";", typ.Common().Name+".h", conf.Color))
		println()
	}

	return nil
}
