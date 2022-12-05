package nskeyedarchiver

// import (
// 	"bytes"
// 	"encoding/binary"
// 	"math"
// 	"reflect"
// )

// const nsNull = "$null"

// type KeyedArchiver struct {
// 	Archiver string        `plist:"$archiver"`
// 	Objects  []interface{} `plist:"$objects"`
// 	Top      ArchiverRoot  `plist:"$top"`
// 	Version  int           `plist:"$version"`
// }

// // Marshal marshals the specified value into NSKeyedArchiver data
// func (u *NSKeyedUnarchiver) Marshal(v interface{}) ([]byte, error) {
// 	// Create a new KeyedArchiver struct to hold the marshaled data
// 	k := KeyedArchiver{
// 	  Archiver: "NSKeyedArchiver",
// 	  Objects:  []interface{}{},
// 	  Top: ArchiverRoot{
// 		Root:   0,
// 		Object: v,
// 	  },
// 	  Version: 100000,
// 	}

// 	// Encode the object in the KeyedArchiver struct
// 	err := encodeObject(v, &k)
// 	if err != nil {
// 	  return nil, err
// 	}

// 	// Marshal the KeyedArchiver struct into plist data
// 	plistData, err := plist.MarshalIndent(k, plist.XMLFormat, "\t")
// 	if err != nil {
// 	  return nil, err
// 	}

// 	return plistData, nil
//   }

//   // encodeObject encodes the specified object and adds it to the specified KeyedArchiver struct
//   func encodeObject(v interface{}, k *KeyedArchiver) error {
// 	// Get the type and value of the specified value
// 	value := reflect.ValueOf(v)
// 	valueType := value.Type()

// 	// Check if the value has already been encoded
// 	index, ok := k.getObjectIndex(v)
// 	if ok {
// 	  // The value has already been encoded, so return its index
// 	  return index
// 	}

// 	// Encode the value based on its type
// 	switch valueType.Kind() {
// 	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
// 	  // Encode an integer value
// 	  k.Objects = append(k.Objects, NSNumber{
// 		Type: "NSNumber",
// 		Value: NSNumberValue{
// 		  Type:  "CFNumber",
// 		  Value: strconv.FormatInt(value.Int(), 10),
// 		},
// 	  })
// 	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
// 	  // Encode a unsigned integer value
// 	  k.Objects = append(k.Objects, NSNumber{
// 		Type: "NSNumber",
// 		Value: NSNumberValue{
// 		  Type:  "CFNumber",
// 		  Value: strconv.FormatUint(value.Uint(), 10),
// 		},
// 	  })
// 	case reflect.Bool:
// 	  // Encode a boolean value
// 	  var b string
// 	  if value.Bool() {
// 		b = "YES"
// 	  } else {
// 		b = "NO"
// 	  }
// 	  k.Objects = append(k.Objects, NSNumber{
// 		Type: "NSNumber",
// 		Value: NSNumberValue{
// 		  Type:  "CFBoolean",
// 		  Value: b,
// 		},
// 	  })
// 	// case reflect.Float32, reflect.Float64:
// 	//   // Encode a floating-point value
// 	//   k.Objects = append(k.Objects, NSNumber{
// 	// 	Type: "

// 	//   }
// 	}
// }
// // NSNumber represents an NSNumber value in NSKeyedArchiver data
// type NSNumber struct {
// 	Type  string        `plist:"$class"`
// 	Value NSNumberValue `plist:"NS.number"`
//   }

//   // NSNumberValue represents the value of an NSNumber in NSKeyedArchiver data
//   type NSNumberValue struct {
// 	Type  string `plist:"CF$UID"`
// 	Value string `plist:"_"`
//   }
