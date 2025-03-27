package nskeyedarchiver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

// ObjectType is an enumeration of the possible types of objects in the NSKeyedArchiver data
type ObjectType int

// Possible values of the ObjectType enumeration
const (
	ObjectTypeInt ObjectType = iota
	ObjectTypeBool
	ObjectTypeReal
	ObjectTypeDate
	ObjectTypeASCIIString
	ObjectTypeData
	ObjectTypeUnicodeString
	ObjectTypeUID
	ObjectTypeArray
	ObjectTypeSet
	ObjectTypeDictionary
)

// ObjectInfo contains the information about an object in the NSKeyedArchiver data
type ObjectInfo struct {
	// The type of the object
	Type ObjectType

	// The reference count of the object
	Ref int
}

// NSKeyedArchiverParser is a parser for NSKeyedArchiver files
type NSKeyedArchiverParser struct {
	data  []byte
	index int
}

// NewNSKeyedArchiverParser creates a new NSKeyedArchiverParser
func NewNSKeyedArchiverParser(data []byte) (*NSKeyedArchiverParser, error) {
	// Verify that the data is a valid NSKeyedArchiver file
	if len(data) < 6 || !bytes.Equal(data[:6], []byte("bplist")) {
		return nil, errors.New("invalid NSKeyedArchiver data")
	}

	return &NSKeyedArchiverParser{data: data, index: 0}, nil
}

// NextObject parses the next object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) NextObject() (any, error) {
	// Parse the object info
	objectInfo, err := p.parseObjectHeader()
	if err != nil {
		return nil, err
	}

	// Parse the object based on its type
	var value any
	switch objectInfo.Type {
	case ObjectTypeInt:
		// Parse an integer value
		value, err = p.parseInt()
	case ObjectTypeBool:
		// Parse a boolean value
		value, err = p.parseBool()
	case ObjectTypeReal:
		// Parse a real (floating-point) value
		value, err = p.parseReal()
	case ObjectTypeDate:
		// Parse a date value
		value, err = p.parseDate()
	case ObjectTypeASCIIString:
		// Parse an ASCII string
		value, err = p.parseASCIIString()
	case ObjectTypeData:
		// Parse data
		value, err = p.parseData()
	case ObjectTypeUnicodeString:
		// Parse a Unicode string
		value, err = p.parseUnicodeString()
	case ObjectTypeUID:
		// Parse a unique identifier (UID)
		value, err = p.parseUID()
	case ObjectTypeArray:
		// Parse an array
		value, err = p.parseArray()
	case ObjectTypeSet:
		// Parse a set
		value, err = p.parseSet()
	case ObjectTypeDictionary:
		// Parse a dictionary
		value, err = p.parseDictionary()
	default:
		// Unrecognized object type
		err = errors.New("unrecognized object type")
	}

	// Return the parsed value
	return value, err
}

// parseObjectHeader parses the object info from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseObjectHeader() (*ObjectInfo, error) {
	// Verify that there is enough data to read the object info
	if p.index+1 > len(p.data) {
		return nil, errors.New("invalid object header")
	}

	// Parse the object info
	objectInfo := &ObjectInfo{
		Type: ObjectType(p.data[p.index] & 0x0f),
		Ref:  int(p.data[p.index] & 0xf0),
	}

	// Advance the index to the next object
	p.index++

	return objectInfo, nil
}

// parseObjectLength parses the length of an object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseObjectLength(objectInfo byte) (int64, error) {
	switch objectInfo & 0x0f {
	case 0x00: // 0-byte object
		return 0, nil
	case 0x01: // 1-byte object
		if p.index+1 > len(p.data) {
			return 0, errors.New("invalid object length")
		}
		return int64(p.data[p.index]), nil
	case 0x02: // 2-byte object
		if p.index+2 > len(p.data) {
			return 0, errors.New("invalid object length")
		}
		return int64(binary.BigEndian.Uint16(p.data[p.index:])), nil
	case 0x03: // 4-byte object
		if p.index+4 > len(p.data) {
			return 0, errors.New("invalid object length")
		}
		return int64(binary.BigEndian.Uint32(p.data[p.index:])), nil
	case 0x04: // 8-byte object
		if p.index+8 > len(p.data) {
			return 0, errors.New("invalid object length")
		}
		return int64(binary.BigEndian.Uint64(p.data[p.index:])), nil
	default:
		return 0, errors.New("invalid object length")
	}
}

// parseBool parses a boolean object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseBool() (bool, error) {
	// Verify that there is enough data to read the boolean value
	if p.index+1 > len(p.data) {
		return false, errors.New("invalid boolean value")
	}

	// Parse the boolean value
	value := p.data[p.index] != 0

	// Advance the index to the next object
	p.index++

	return value, nil
}

// parseInt parses an integer object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseInt() (int64, error) {
	// Verify that there is enough data to read the integer value
	if p.index+8 > len(p.data) {
		return 0, errors.New("invalid integer value")
	}

	// Parse the integer value
	value := int64(binary.BigEndian.Uint64(p.data[p.index:]))

	// Advance the index to the next object
	p.index += 8

	return value, nil
}

// parseReal parses a real (floating-point) object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseReal() (float64, error) {
	// Verify that there is enough data to read the real value
	if p.index+8 > len(p.data) {
		return 0, errors.New("invalid real value")
	}

	// Parse the real value
	value := math.Float64frombits(binary.BigEndian.Uint64(p.data[p.index:]))

	// Advance the index to the next object
	p.index += 8

	return value, nil
}

// parseDate parses a date object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseDate() (time.Time, error) {
	// Verify that there is enough data to read the date value
	if p.index+8 > len(p.data) {
		return time.Time{}, errors.New("invalid date value")
	}

	// Parse the date value
	timestamp := binary.BigEndian.Uint64(p.data[p.index:])
	value := time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(timestamp) * time.Second)

	// Advance the index to the next object
	p.index += 8

	return value, nil
}

// parseData parses a data object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseData() ([]byte, error) {
	// Parse the length of the data
	length, err := p.parseInt()
	if err != nil {
		return nil, err
	}

	// Verify that there is enough data to read the data
	if p.index+int(length) > len(p.data) {
		return nil, errors.New("invalid data")
	}

	// Parse the data
	value := p.data[p.index : p.index+int(length)]

	// Advance the index to the next object
	p.index += int(length)

	return value, nil
}

// parseASCIIString parses an ASCII string object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseASCIIString() (string, error) {
	// Parse the length of the string
	length, err := p.parseInt()
	if err != nil {
		return "", err
	}

	// Verify that there is enough data to read the string
	if p.index+int(length) > len(p.data) {
		return "", errors.New("invalid ASCII string")
	}

	// Parse the string
	value := string(p.data[p.index : p.index+int(length)])

	// Advance the index to the next object
	p.index += int(length)

	return value, nil
}

// parseUnicodeString parses a Unicode string object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseUnicodeString() (string, error) {
	// Parse the length of the string
	length, err := p.parseInt()
	if err != nil {
		return "", err
	}

	// Verify that there is enough data to read the string
	if p.index+int(length) > len(p.data) {
		return "", errors.New("invalid Unicode string")
	}

	// Parse the string
	value := string(p.data[p.index : p.index+int(length)])

	// Advance the index to the next object
	p.index += int(length)

	return value, nil
}

// parseUID parses a unique identifier (UID) object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseUID() (uint64, error) {
	// Parse the length of the UID
	length, err := p.parseInt()
	if err != nil {
		return 0, err
	}

	// Verify that there is enough data to read the UID
	if p.index+int(length) > len(p.data) {
		return 0, errors.New("invalid UID")
	}

	// Parse the UID
	value := binary.BigEndian.Uint64(p.data[p.index : p.index+int(length)])

	// Advance the index to the next object
	p.index += int(length)

	return value, nil
}

// parseArray parses an array object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseArray() ([]any, error) {
	// Parse the number of elements in the array
	numElements, err := p.parseInt()
	if err != nil {
		return nil, err
	}

	// Parse the elements in the array
	array := make([]any, numElements)
	for i := int64(0); i < numElements; i++ {
		// Parse the element
		element, err := p.NextObject()
		if err != nil {
			return nil, err
		}

		// Add the element to the array
		array[i] = element
	}

	return array, nil
}

// parseSet parses a set object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseSet() (map[any]struct{}, error) {
	// Parse the number of elements in the set
	numElements, err := p.parseInt()
	if err != nil {
		return nil, err
	}

	// Parse the elements in the set
	set := make(map[any]struct{}, numElements)
	for i := int64(0); i < numElements; i++ {
		// Parse the element
		element, err := p.NextObject()
		if err != nil {
			return nil, err
		}

		// Add the element to the set
		set[element] = struct{}{}
	}

	return set, nil
}

// parseDictionary parses a dictionary object from the NSKeyedArchiver data
func (p *NSKeyedArchiverParser) parseDictionary() (map[string]any, error) {
	// Parse the number of key-value pairs in the dictionary
	numPairs, err := p.parseInt()
	if err != nil {
		return nil, err
	}

	// Parse the key-value pairs in the dictionary
	dictionary := make(map[string]any, numPairs)
	for i := int64(0); i < numPairs; i++ {
		// Parse the key
		key, err := p.parseASCIIString()
		if err != nil {
			return nil, err
		}

		// Parse the value
		value, err := p.NextObject()
		if err != nil {
			return nil, err
		}

		// Add the key-value pair to the dictionary
		dictionary[key] = value
	}

	return dictionary, nil
}
