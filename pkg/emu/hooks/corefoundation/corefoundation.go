package corefoundation

type CFTypeID uint32

const (
	CFStringTypeID CFTypeID = iota
	CFDataTypeID
	CFNumberTypeID
	CFArrayTypeID
	CFDictionaryTypeID
	CFBooleanTypeID
	CFSetTypeID
)

type CFArray struct {
	values    []any
	count     uint32
	cf_values bool
}

type CFDictionary struct {
	keys      []any
	values    []any
	count     uint32
	cf_keys   bool
	cf_values bool
}
