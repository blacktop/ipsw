// Code generated by "stringer -type=kind,floatEncoding -output types_string.go"; DO NOT EDIT.

package ctf

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[UNKNOWN-0]
	_ = x[INTEGER-1]
	_ = x[FLOAT-2]
	_ = x[POINTER-3]
	_ = x[ARRAY-4]
	_ = x[FUNCTION-5]
	_ = x[STRUCT-6]
	_ = x[UNION-7]
	_ = x[ENUM-8]
	_ = x[FORWARD-9]
	_ = x[TYPEDEF-10]
	_ = x[VOLATILE-11]
	_ = x[CONST-12]
	_ = x[RESTRICT-13]
	_ = x[PTRAUTH-14]
	_ = x[MAX-31]
}

const (
	_kind_name_0 = "UNKNOWNINTEGERFLOATPOINTERARRAYFUNCTIONSTRUCTUNIONENUMFORWARDTYPEDEFVOLATILECONSTRESTRICTPTRAUTH"
	_kind_name_1 = "MAX"
)

var (
	_kind_index_0 = [...]uint8{0, 7, 14, 19, 26, 31, 39, 45, 50, 54, 61, 68, 76, 81, 89, 96}
)

func (i kind) String() string {
	switch {
	case i <= 14:
		return _kind_name_0[_kind_index_0[i]:_kind_index_0[i+1]]
	case i == 31:
		return _kind_name_1
	default:
		return "kind(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[SINGLE-1]
	_ = x[DOUBLE-2]
	_ = x[CPLX-3]
	_ = x[DCPLX-4]
	_ = x[LDCPLX-5]
	_ = x[LDOUBLE-6]
	_ = x[INTRVL-7]
	_ = x[DINTRVL-8]
	_ = x[LDINTRVL-9]
	_ = x[IMAGRY-10]
	_ = x[DIMAGRY-11]
	_ = x[LDIMAGRY-12]
}

const _floatEncoding_name = "SINGLEDOUBLECPLXDCPLXLDCPLXLDOUBLEINTRVLDINTRVLLDINTRVLIMAGRYDIMAGRYLDIMAGRY"

var _floatEncoding_index = [...]uint8{0, 6, 12, 16, 21, 27, 34, 40, 47, 55, 61, 68, 76}

func (i floatEncoding) String() string {
	i -= 1
	if i >= floatEncoding(len(_floatEncoding_index)-1) {
		return "floatEncoding(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _floatEncoding_name[_floatEncoding_index[i]:_floatEncoding_index[i+1]]
}
