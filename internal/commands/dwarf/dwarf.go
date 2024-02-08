package dwarf

import (
	"bufio"
	"bytes"
	"fmt"

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

func GetAllStructs(path string) (<-chan *dwf.StructType, error) {
	out := make(chan *dwf.StructType)

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

	go func() {
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
				out <- st
			}
		}
		close(out)
	}()

	return out, nil
}

func GetAllEnums(path string) (<-chan *dwf.EnumType, error) {
	out := make(chan *dwf.EnumType)

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

	go func() {
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
				out <- typ.(*dwf.EnumType)
			}
		}
		close(out)
	}()

	return out, nil
}

func GetName(path, name string) (ft *dwf.FuncType, filename string, err error) {
	m, err := macho.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return nil, "", err
	}

	r := df.Reader()

	off, err := df.LookupName(name)
	if err != nil {
		return nil, "", fmt.Errorf("failed to find name %s: %v", name, err)
	}

	r.Seek(off)

	entry, err := r.Next()
	if err != nil {
		return nil, "", err
	}

	fs, err := df.FilesForEntry(entry)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get files for entry: %v", err)
	}
	if idx, ok := entry.Val(dwf.AttrDeclFile).(int64); ok {
		if idx < int64(len(fs)) {
			filename = fs[idx].Name
		}
	}

	if entry.Tag == dwf.TagSubprogram || entry.Tag == dwf.TagSubroutineType || entry.Tag == dwf.TagInlinedSubroutine {
		typ, err := df.Type(entry.Offset)
		if err != nil {
			return nil, "", err
		}
		ft = typ.(*dwf.FuncType)
	} else {
		typ, err := df.Type(entry.Offset)
		if err != nil {
			return nil, "", err
		}
		return nil, "", fmt.Errorf("did not find tag func type: found %s; %s", entry.Tag, typ.String())
	}

	return
}

func GetType(path, name string, showOffsets bool) (typeStr string, filename string, err error) {
	m, err := macho.Open(path)
	if err != nil {
		return "", "", err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return "", "", err
	}

	r := df.Reader()

	off, err := df.LookupType(name)
	if err != nil {
		return "", "", fmt.Errorf("failed to find type %s: %v", name, err)
	}

	r.Seek(off)

	entry, err := r.Next()
	if err != nil {
		return "", "", err
	}

	fs, err := df.FilesForEntry(entry)
	if err != nil {
		return "", "", fmt.Errorf("failed to get files for entry: %v", err)
	}
	if idx, ok := entry.Val(dwf.AttrDeclFile).(int64); ok {
		if idx < int64(len(fs)) {
			filename = fs[idx].Name
		}
	}

	typ, err := df.Type(entry.Offset)
	if err != nil {
		return "", "", fmt.Errorf("failed to get type for entry: %v", err)
	}

	switch t := typ.(type) {
	case *dwf.StructType:
		if t.Incomplete {
			return "", "", fmt.Errorf("type %s is incomplete", name)
		}
		return t.Defn(showOffsets), filename, nil
	case *dwf.ArrayType:
		return t.String(), filename, nil
	case *dwf.PtrType:
		return t.String(), filename, nil
	case *dwf.FuncType:
		return t.String(), filename, nil
	case *dwf.EnumType:
		return t.String(), filename, nil
	case *dwf.TypedefType:
		if enum, ok := t.Type.(*dwf.EnumType); ok {
			return fmt.Sprintf("typedef %s %s;", enum.String(), t.Name), filename, nil
		}
		return fmt.Sprintf("typedef %s %s;", t.Type.Common().Name, t.Name), filename, nil
	default:
		return "", "", fmt.Errorf("did not find supported type: found %s; %s", entry.Tag, typ.String())
	}
}

func DiffStructures(prevMachO, currMachO string, conf *Config) (string, error) {
	var dat bytes.Buffer
	buf := bufio.NewWriter(&dat)

	m, err := macho.Open(prevMachO)
	if err != nil {
		return "", err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return "", err
	}

	r := df.Reader()

	types, err := GetAllStructs(currMachO)
	if err != nil {
		return "", err
	}

	seen := make(map[string]bool)

	for t := range types {
		if len(t.StructName) > 0 {
			if _, ok := seen[t.StructName]; !ok {
				seen[t.StructName] = true
				off, err := df.LookupType(t.StructName)
				if err != nil {
					if conf.Markdown {
						buf.WriteString(fmt.Sprintf("#### %s\n\n```c\n%s\n```\n", t.StructName, utils.ClangFormat(t.Defn(conf.ShowOffsets), t.StructName+".h", false)))
					} else {
						buf.WriteString(fmt.Sprintf("NEW: %s\n\n%s\n", t.StructName, utils.ClangFormat(t.Defn(conf.ShowOffsets), t.StructName+".h", conf.Color)))
					}
					continue // not found in older version
				}

				r.Seek(off)

				entry, err := r.Next()
				if err != nil {
					return "", err
				}

				var st *dwf.StructType
				if entry.Tag == dwf.TagStructType {
					typ, err := df.Type(entry.Offset)
					if err != nil {
						return "", err
					}
					st = typ.(*dwf.StructType)
					if st.Incomplete {
						continue
					}
					if conf.Markdown {
						out, err := utils.GitDiff(st.Defn(conf.ShowOffsets), t.Defn(conf.ShowOffsets), &utils.GitDiffConfig{Color: false, Tool: "git"})
						if err != nil {
							return "", err
						}
						if len(out) > 0 {
							buf.WriteString(fmt.Sprintf("#### %s\n\n```diff\n%s\n```\n", t.StructName, out))
						}
					} else {
						out, err := utils.GitDiff(st.Defn(conf.ShowOffsets), t.Defn(conf.ShowOffsets), &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
						if err != nil {
							return "", err
						}
						if len(out) > 0 {
							buf.WriteString(fmt.Sprintf("DIFF: %s\n\n%s\n", t.StructName, out))
						}
					}

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

	m, err := macho.Open(prevMachO)
	if err != nil {
		return "", err
	}
	defer m.Close()

	df, err := m.DWARF()
	if err != nil {
		return "", err
	}

	r := df.Reader()

	types, err := GetAllEnums(currMachO)
	if err != nil {
		return "", err
	}

	seen := make(map[string]bool)

	for t := range types {
		if len(t.EnumName) > 0 {
			if _, ok := seen[t.EnumName]; !ok {
				seen[t.EnumName] = true
				off, err := df.LookupType(t.EnumName)
				if err != nil {
					if conf.Markdown {
						buf.WriteString(fmt.Sprintf("#### %s\n\n```c\n%s\n```\n", t.EnumName, utils.ClangFormat(t.String(), t.EnumName+".h", false)))
					} else {
						buf.WriteString(fmt.Sprintf("NEW: %s\n\n%s\n", t.EnumName, utils.ClangFormat(t.String(), t.EnumName+".h", conf.Color)))
					}
					continue // not found in older version
				}

				r.Seek(off)

				entry, err := r.Next()
				if err != nil {
					return "", err
				}

				var enum *dwf.EnumType
				if entry.Tag == dwf.TagStructType {
					typ, err := df.Type(entry.Offset)
					if err != nil {
						return "", err
					}
					enum = typ.(*dwf.EnumType)
					if conf.Markdown {
						out, err := utils.GitDiff(enum.String(), t.String(), &utils.GitDiffConfig{Color: false, Tool: "git"})
						if err != nil {
							return "", err
						}
						if len(out) > 0 {
							buf.WriteString(fmt.Sprintf("#### %s\n\n```diff\n%s\n```\n", t.EnumName, out))
						}
					} else {
						out, err := utils.GitDiff(enum.String(), t.String(), &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
						if err != nil {
							return "", err
						}
						if len(out) > 0 {
							buf.WriteString(fmt.Sprintf("DIFF: %s\n\n%s\n", t.EnumName, out))
						}
					}

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

	for t := range types {
		fmt.Println(utils.ClangFormat(t.Defn(conf.ShowOffsets), t.StructName+".h", conf.Color))
		println()
	}

	return nil
}

func DumpAllEnums(path string, conf *Config) error {
	types, err := GetAllEnums(path)
	if err != nil {
		return err
	}

	for t := range types {
		fmt.Println(utils.ClangFormat(t.String(), t.Name+".h", conf.Color))
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
