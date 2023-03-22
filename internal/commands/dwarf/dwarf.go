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
	Markdown bool
	Color    bool
	DiffTool string
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

func GetType(path, name string) (typeStr string, filename string, err error) {
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
		return t.Defn(), filename, nil
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
						buf.WriteString(fmt.Sprintf("#### %s\n\n```c\n%s\n```\n", t.StructName, utils.ClangFormat(t.Defn(), t.StructName+".h", false)))
					} else {
						buf.WriteString(fmt.Sprintf("NEW: %s\n\n%s\n", t.StructName, utils.ClangFormat(t.Defn(), t.StructName+".h", conf.Color)))
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
						out, err := utils.GitDiff(st.Defn(), t.Defn(), &utils.GitDiffConfig{Color: false, Tool: "git"})
						if err != nil {
							return "", err
						}
						if len(out) > 0 {
							buf.WriteString(fmt.Sprintf("#### %s\n\n```diff\n%s\n```\n", t.StructName, out))
						}
					} else {
						out, err := utils.GitDiff(st.Defn(), t.Defn(), &utils.GitDiffConfig{Color: conf.Color, Tool: conf.DiffTool})
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
