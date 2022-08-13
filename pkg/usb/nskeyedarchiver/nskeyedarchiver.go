package nskeyedarchiver

import (
	"io"

	"github.com/blacktop/go-plist"
)

type NSKeyedArchiver struct {

	// The version of the archiver.
	Version uint64 `plist:"version,omitempty"`

	// The root object of the archiver.
	Root *NSKeyedArchiverObject `plist:"root,omitempty"`

	// The objects that are referenced by the root object.
	ReferencedObjects []*NSKeyedArchiverObject `plist:"referencedObjects,omitempty"`

	// The objects that are encoded in the archiver.
	Objects []*NSKeyedArchiverObject `plist:"objects,omitempty"`

	// The classes that are encoded in the archiver.
	Classes []*NSKeyedArchiverClass `plist:"classes,omitempty"`

	// The classes that are encoded in the archiver.
	ClassesByName map[string]*NSKeyedArchiverClass `plist:"classesByName,omitempty"`

	// The classes that are encoded in the archiver.
	ClassesByNameForEncoding map[string]*NSKeyedArchiverClass `plist:"classesByNameForEncoding,omitempty"`

	// The classes that are encoded in the archiver.
	ClassesByNameForDecoding map[string]*NSKeyedArchiverClass `plist:"classesByNameForDecoding,omitempty"`

	// The classes that are encoded in the archiver.
	ClassesByNameForObjects map[string]*NSKeyedArchiverClass `plist:"classesByNameForObjects,omitempty"`

	// The classes that are encoded in the archiver.
	ClassesByNameForReferences map[string]*NSKeyedArchiverClass `plist:"classesByNameForReferences,omitempty"`

	// The classes that are encoded in the archiver.
	ClassesByNameForClasses map[string]*NSKeyedArchiverClass `plist:"classesByNameForClasses,omitempty"`

	// The classes that are encoded in the archiver.
	ClassesByNameForClassesByName map[string]*NSKeyedArchiverClass `plist:"classesByNameForClassesByName,omitempty"`
}

type NSKeyedArchiverObject struct {

	// The class of the object.
	Class *NSKeyedArchiverClass `plist:"class,omitempty"`

	// The class of the object.
	ClassName string `plist:"className,omitempty"`

	// The class of the object.
	ClassNameForEncoding string `plist:"classNameForEncoding,omitempty"`

	// The class of the object.
	ClassNameForDecoding string `plist:"classNameForDecoding,omitempty"`

	// The class of the object.
	ClassNameForObjects string `plist:"classNameForObjects,omitempty"`

	// The class of the object.
	ClassNameForReferences string `plist:"classNameForReferences,omitempty"`
}

type NSKeyedArchiverClass struct {

	// The class of the object.
	Class *NSKeyedArchiverClass `plist:"class,omitempty"`

	// The class of the object.
	ClassName string `plist:"className,omitempty"`

	// The class of the object.
	ClassNameForEncoding string `plist:"classNameForEncoding,omitempty"`

	// The class of the object.
	ClassNameForDecoding string `plist:"classNameForDecoding,omitempty"`

	// The class of the object.
	ClassNameForObjects string `plist:"classNameForObjects,omitempty"`

	// The class of the object.
	ClassNameForReferences string `plist:"classNameForReferences,omitempty"`

	// The class of the object.
	ClassNameForClasses string `plist:"classNameForClasses,omitempty"`

	// The class of the object.
	ClassNameForClassesByName string `plist:"classNameForClassesByName,omitempty"`

	// The class of the object.
	ClassNameForClassesByNameForEncoding string `plist:"classNameForClassesByNameForEncoding,omitempty"`

	// The class of the object.
	ClassNameForClassesByNameForDecoding string `plist:"classNameForClassesByNameForDecoding,omitempty"`

	// The class of the object.
	ClassNameForClassesByNameForObjects string `plist:"classNameForClassesByNameForObjects,omitempty"`

	// The class of the object.
	ClassNameForClassesByNameForReferences string `plist:"classNameForClassesByNameForReferences,omitempty"`

	// The class of the object.
	ClassNameForClassesByNameForClasses string `plist:"classNameForClassesByNameForClasses,omitempty"`

	// The class of the object.
	ClassNameForClassesByNameForClassesByName string `plist:"classNameForClassesByNameForClassesByName,omitempty"`

	// The class of the object.
	ClassNameForClassesByNameForClassesByNameForEncoding string `plist:"classNameForClassesByNameForClassesByNameForEncoding,omitempty"`

	// The class of the object.
	ClassNameForClassesByNameForClassesByNameForDecoding string `plist:"classNameForClassesByNameForClassesByNameForDecoding,omitempty"`

	// The class of the object.
}

func NewNSKeyedArchiver() *NSKeyedArchiver {
	return &NSKeyedArchiver{}
}

func (nska *NSKeyedArchiver) GetVersion() uint64 {
	return nska.Version
}

func (nska *NSKeyedArchiver) SetVersion(version uint64) {
	nska.Version = version
}

func (nska *NSKeyedArchiver) GetRoot() *NSKeyedArchiverObject {
	return nska.Root
}

func (nska *NSKeyedArchiver) SetRoot(root *NSKeyedArchiverObject) {
	nska.Root = root
}

func (nska *NSKeyedArchiver) GetReferencedObjects() []*NSKeyedArchiverObject {
	return nska.ReferencedObjects
}

func (nska *NSKeyedArchiver) SetReferencedObjects(referencedObjects []*NSKeyedArchiverObject) {
	nska.ReferencedObjects = referencedObjects
}

func (nska *NSKeyedArchiver) GetObjects() []*NSKeyedArchiverObject {
	return nska.Objects
}

func (nska *NSKeyedArchiver) SetObjects(objects []*NSKeyedArchiverObject) {
	nska.Objects = objects
}

func (nska *NSKeyedArchiver) GetClasses() []*NSKeyedArchiverClass {
	return nska.Classes
}

func (nska *NSKeyedArchiver) SetClasses(classes []*NSKeyedArchiverClass) {
	nska.Classes = classes
}

func (nska *NSKeyedArchiver) GetClassesByName() map[string]*NSKeyedArchiverClass {
	return nska.ClassesByName
}

// Unarchiaves the plist from the given reader.
func Unarchive(reader io.Reader) (*NSKeyedArchiver, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return UnarchiveFromData(data)
}

// Unarchiaves the plist from the given data.
func UnarchiveFromData(data []byte) (*NSKeyedArchiver, error) {
	nska := &NSKeyedArchiver{}
	if _, err := plist.Unmarshal(data, nska); err != nil {
		return nil, err
	}
	return nska, nil
}
