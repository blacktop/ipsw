package nsxpc

import "strings"

type methodTypeInfo struct {
	ParamClasses []string
	ReturnClass  string
}

func decodeMethodTypeClasses(types string) methodTypeInfo {
	var info methodTypeInfo
	typ, rest, ok := cutObjCType(types)
	if !ok {
		return info
	}
	info.ReturnClass = objectClassName(typ)

	args := make([]string, 0, 4)
	for rest != "" {
		rest = trimTypeOffset(rest)
		if rest == "" {
			break
		}
		typ, next, ok := cutObjCType(rest)
		if !ok {
			break
		}
		args = append(args, objectClassName(typ))
		rest = next
	}
	if len(args) > 2 {
		info.ParamClasses = args[2:]
	}
	return info
}

func trimTypeOffset(s string) string {
	return strings.TrimLeft(s, "0123456789")
}

func cutObjCType(s string) (string, string, bool) {
	s = trimTypeOffset(strings.TrimSpace(s))
	if s == "" {
		return "", "", false
	}
	start := 0
	for start < len(s) && strings.ContainsRune("rnNoORVj", rune(s[start])) {
		start++
	}
	if start >= len(s) {
		return "", "", false
	}
	typStart := start
	switch s[start] {
	case '@':
		if start+1 < len(s) && s[start+1] == '?' {
			return s[typStart : start+2], s[start+2:], true
		}
		if start+1 < len(s) && s[start+1] == '"' {
			end := start + 2
			for end < len(s) {
				if s[end] == '"' && s[end-1] != '\\' {
					return s[typStart : end+1], s[end+1:], true
				}
				end++
			}
			return s[typStart:], "", true
		}
		return s[typStart : start+1], s[start+1:], true
	case '^':
		_, rest, ok := cutObjCType(s[start+1:])
		if !ok {
			return s[typStart : start+1], s[start+1:], true
		}
		return s[typStart : len(s)-len(rest)], rest, true
	case '{':
		return cutBalancedType(s, typStart, '{', '}')
	case '(':
		return cutBalancedType(s, typStart, '(', ')')
	case '[':
		return cutBalancedType(s, typStart, '[', ']')
	default:
		return s[typStart : start+1], s[start+1:], true
	}
}

func cutBalancedType(s string, start int, open, close byte) (string, string, bool) {
	depth := 0
	for idx := start; idx < len(s); idx++ {
		switch s[idx] {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return s[start : idx+1], s[idx+1:], true
			}
		}
	}
	return s[start:], "", true
}

func objectClassName(enc string) string {
	enc = strings.TrimSpace(enc)
	for strings.HasPrefix(enc, "^") {
		enc = strings.TrimPrefix(enc, "^")
	}
	if !strings.HasPrefix(enc, "@\"") || !strings.HasSuffix(enc, "\"") {
		return ""
	}
	name := strings.TrimSuffix(strings.TrimPrefix(enc, "@\""), "\"")
	if name == "" || strings.HasPrefix(name, "<") {
		return ""
	}
	if idx := strings.Index(name, "<"); idx >= 0 {
		name = name[:idx]
	}
	if idx := strings.IndexAny(name, " \t\n"); idx >= 0 {
		name = name[:idx]
	}
	return name
}
