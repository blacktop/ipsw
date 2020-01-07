package utils

import "strconv"

type IntName struct {
	I uint32
	S string
}

func StringName(i uint32, names []IntName, goSyntax bool) string {
	for _, n := range names {
		if n.I == i {
			if goSyntax {
				return "macho." + n.S
			}
			return n.S
		}
	}
	return strconv.FormatUint(uint64(i), 10)
}
