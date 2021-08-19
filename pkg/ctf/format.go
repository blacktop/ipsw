package ctf

import "fmt"

func (h header) String(verbose bool) string {
	title := ""
	if verbose {
		title = "- CTF Header -----------------------------------------------------------------\n\n"
	}
	return fmt.Sprintf(
		"%sMagic        = %#x\n"+
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
		title,
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
