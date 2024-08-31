package dyld

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/blacktop/go-macho/types"
)

/*
 * objc_stringhash_t - Precomputed perfect hash table of strings <dyld/include/objc-shared-cache.h>
 *
 * Base class for precomputed selector table and class table.
 */

type strHashType uint8

const (
	selopt strHashType = iota
	clsopt
)

type stringHash struct {
	Capacity uint32
	Occupied uint32
	Shift    uint32
	Mask     uint32
	_        uint32 // was zero
	_        uint32 // alignment pad
	Salt     uint64
	Scramble [256]uint32
}

type stringHashV16 struct {
	Version  uint32
	Capacity uint32
	Occupied uint32
	Shift    uint32
	Mask     uint32
	_        uint32 // was zero
	Salt     uint64
	Scramble [256]uint32
}

// StringHash struct
type StringHash struct {
	Type             strHashType
	FileOffset       int64
	shash            any
	Tab              []byte       /* tab[mask+1] (always power-of-2) */
	CheckBytes       []byte       /* check byte for each string */
	Offsets          []int32      /* offsets from &capacity to cstrings */
	ObjectOffsets    []ObjectData /* offsets from &capacity to cstrings */
	DuplicateCount   uint32
	DuplicateOffsets []ObjectData

	hdrRO    *objc_headeropt_ro_t
	hdrRW    *objc_headeropt_rw_t
	opt      Optimization
	dylibMap map[uint16]string
}

// Capacity returns the Capacity
func (s *StringHash) Capacity() uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Capacity
	case stringHashV16:
		return h.Capacity
	}
	return 0
}

// Occupied returns the Occupied
func (s *StringHash) Occupied() uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Occupied
	case stringHashV16:
		return h.Occupied
	}
	return 0
}

// Shift returns the Shift
func (s *StringHash) Shift() uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Shift
	case stringHashV16:
		return h.Shift
	}
	return 0
}

// Mask returns the Mask
func (s *StringHash) Mask() uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Mask
	case stringHashV16:
		return h.Mask
	}
	return 0
}

// Salt returns the Salt
func (s *StringHash) Salt() uint64 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Salt
	case stringHashV16:
		return h.Salt
	}
	return 0
}

// Scramble returns the Scramble
func (s *StringHash) Scramble() [256]uint32 {
	switch h := s.shash.(type) {
	case stringHash:
		return h.Scramble
	case stringHashV16:
		return h.Scramble
	}
	return [256]uint32{0}
}

func (s *StringHash) Read(r io.ReadSeeker) error {
	if s.opt.GetVersion() >= 16 {
		var sh stringHashV16
		if err := binary.Read(r, binary.LittleEndian, &sh); err != nil {
			return fmt.Errorf("failed to read %T: %v", sh, err)
		}
		s.shash = sh
	} else {
		var sh stringHash
		if err := binary.Read(r, binary.LittleEndian, &sh); err != nil {
			return fmt.Errorf("failed to read %T: %v", sh, err)
		}
		s.shash = sh
	}

	s.Tab = make([]byte, s.Mask()+1)
	if err := binary.Read(r, binary.LittleEndian, &s.Tab); err != nil {
		return err
	}

	s.CheckBytes = make([]byte, s.Capacity())
	if err := binary.Read(r, binary.LittleEndian, &s.CheckBytes); err != nil {
		return err
	}

	s.Offsets = make([]int32, s.Capacity())
	if err := binary.Read(r, binary.LittleEndian, &s.Offsets); err != nil {
		return err
	}

	if s.Type == clsopt {
		s.ObjectOffsets = make([]ObjectData, s.Capacity())
		if err := binary.Read(r, binary.LittleEndian, &s.ObjectOffsets); err != nil {
			if err == io.ErrUnexpectedEOF { // FIXME: gross hack (selectors don't use these fields)
				s.ObjectOffsets = nil
				return nil
			}
			return err
		}

		if err := binary.Read(r, binary.LittleEndian, &s.DuplicateCount); err != nil {
			return err
		}

		s.DuplicateOffsets = make([]ObjectData, s.DuplicateCount)
		if err := binary.Read(r, binary.LittleEndian, &s.DuplicateOffsets); err != nil {
			return err
		}
	}

	return nil
}

func (s StringHash) String() string {
	return fmt.Sprintf(
		"FileOffset = %X\n"+
			"Capacity   = %X\n"+
			"Occupied   = %X\n"+
			"Shift      = %X\n"+
			"Mask       = %X\n"+
			"Salt       = %016X\n",
		s.FileOffset,
		s.Capacity(),
		s.Occupied(),
		s.Shift(),
		s.Mask(),
		s.Salt())
}

type ObjectData uint64

func (o ObjectData) IsDuplicate() bool {
	return types.ExtractBits(uint64(o), 0, 1) != 0
}
func (o ObjectData) DuplicateIndex() uint64 {
	return types.ExtractBits(uint64(o), 1, 47)
}
func (o ObjectData) DuplicateCount() uint16 {
	return uint16(types.ExtractBits(uint64(o), 48, 16))
}
func (o ObjectData) ObjectCacheOffset() uint64 {
	return types.ExtractBits(uint64(o), 1, 47)
}
func (o ObjectData) DylibObjCIndex() uint16 {
	return uint16(types.ExtractBits(uint64(o), 48, 16))
}
func (o ObjectData) String() string {
	if o.IsDuplicate() {
		return fmt.Sprintf("Duplicate: count=%#x, index=%d", o.DuplicateCount(), o.DuplicateIndex())
	}
	return fmt.Sprintf("cache_offset=%#x, dylib_index=%d", o.ObjectCacheOffset(), o.DylibObjCIndex())
}

/*
--------------------------------------------------------------------
mix -- mix 3 64-bit values reversibly.
mix() takes 48 machine instructions, but only 24 cycles on a superscalar

	machine (like Intel's new MMX architecture).  It requires 4 64-bit
	registers for 4::2 parallelism.

All 1-bit deltas, all 2-bit deltas, all deltas composed of top bits of

	(a,b,c), and all deltas of bottom bits were tested.  All deltas were
	tested both on random keys and on keys that were nearly all zero.
	These deltas all cause every bit of c to change between 1/3 and 2/3
	of the time (well, only 113/400 to 287/400 of the time for some
	2-bit delta).  These deltas all cause at least 80 bits to change
	among (a,b,c) when the mix is run either forward or backward (yes it
	is reversible).

This implies that a hash using mix64 has no funnels.  There may be

	characteristics with 3-bit deltas or bigger, I didn't test for
	those.

--------------------------------------------------------------------
*/
func mix64(a, b, c *uint64) {
	*a = (*a - *b - *c) ^ (*c >> 43)
	*b = (*b - *c - *a) ^ (*a << 9)
	*c = (*c - *a - *b) ^ (*b >> 8)
	*a = (*a - *b - *c) ^ (*c >> 38)
	*b = (*b - *c - *a) ^ (*a << 23)
	*c = (*c - *a - *b) ^ (*b >> 5)
	*a = (*a - *b - *c) ^ (*c >> 35)
	*b = (*b - *c - *a) ^ (*a << 49)
	*c = (*c - *a - *b) ^ (*b >> 11)
	*a = (*a - *b - *c) ^ (*c >> 12)
	*b = (*b - *c - *a) ^ (*a << 18)
	*c = (*c - *a - *b) ^ (*b >> 22)
}

/*
--------------------------------------------------------------------
hash() -- hash a variable-length key into a 64-bit value
  k     : the key (the unaligned variable-length array of bytes)
  len   : the length of the key, counting by bytes
  level : can be any 8-byte value
Returns a 64-bit value.  Every bit of the key affects every bit of
the return value.  No funnels.  Every 1-bit and 2-bit delta achieves
avalanche.  About 41+5len instructions.

The best hash table sizes are powers of 2.  There is no need to do
mod a prime (mod is sooo slow!).  If you need less than 64 bits,
use a bitmask.  For example, if you need only 10 bits, do
  h = (h & hashmask(10));
In which case, the hash table should have hashsize(10) elements.

If you are hashing n strings (uint8_t **)k, do it like this:
  for (i=0, h=0; i<n; ++i) h = hash( k[i], len[i], h);

By Bob Jenkins, Jan 4 1997.  bob_jenkins@burtleburtle.net.  You may
use this code any way you wish, private, educational, or commercial,
but I would appreciate if you give me credit.

See http://burtleburtle.net/bob/hash/evahash.html
Use for hash table lookup, or anything where one collision in 2^^64
is acceptable.  Do NOT use for cryptographic purposes.
--------------------------------------------------------------------
*/

func lookup8(k []byte, level uint64) uint64 {
	// uint8_t *k;        /* the key */
	// uint64_t  length;   /* the length of the key */
	// uint64_t  level;    /* the previous hash, or an arbitrary value */
	var a, b, c uint64
	var length int

	/* Set up the internal state */
	length = len(k)
	a = level
	b = level              /* the previous hash value */
	c = 0x9e3779b97f4a7c13 /* the golden ratio; an arbitrary value */
	p := 0
	/*---------------------------------------- handle most of the key */
	for length >= 24 {
		a += uint64(k[p+0]) + (uint64(k[p+1]) << 8) + (uint64(k[p+2]) << 16) + (uint64(k[p+3]) << 24) + (uint64(k[p+4]) << 32) + (uint64(k[p+5]) << 40) + (uint64(k[p+6]) << 48) + (uint64(k[p+7]) << 56)
		b += uint64(k[p+8]) + (uint64(k[p+9]) << 8) + (uint64(k[p+10]) << 16) + (uint64(k[p+11]) << 24) + (uint64(k[p+12]) << 32) + (uint64(k[p+13]) << 40) + (uint64(k[p+14]) << 48) + (uint64(k[p+15]) << 56)
		c += uint64(k[p+16]) + (uint64(k[p+17]) << 8) + (uint64(k[p+18]) << 16) + (uint64(k[p+19]) << 24) + (uint64(k[p+20]) << 32) + (uint64(k[p+21]) << 40) + (uint64(k[p+22]) << 48) + (uint64(k[p+23]) << 56)
		mix64(&a, &b, &c)
		p += 24
		length -= 24
	}

	/*------------------------------------- handle the last 23 bytes */
	c += uint64(len(k))
	switch length { /* all the case statements fall through */
	case 23:
		c += (uint64(k[p+22]) << 56)
		fallthrough
	case 22:
		c += (uint64(k[p+21]) << 48)
		fallthrough
	case 21:
		c += (uint64(k[p+20]) << 40)
		fallthrough
	case 20:
		c += (uint64(k[p+19]) << 32)
		fallthrough
	case 19:
		c += (uint64(k[p+18]) << 24)
		fallthrough
	case 18:
		c += (uint64(k[p+17]) << 16)
		fallthrough
	case 17:
		c += (uint64(k[p+16]) << 8)
		fallthrough
	/* the first byte of c is reserved for the length */
	case 16:
		b += (uint64(k[p+15]) << 56)
		fallthrough
	case 15:
		b += (uint64(k[p+14]) << 48)
		fallthrough
	case 14:
		b += (uint64(k[p+13]) << 40)
		fallthrough
	case 13:
		b += (uint64(k[p+12]) << 32)
		fallthrough
	case 12:
		b += (uint64(k[p+11]) << 24)
		fallthrough
	case 11:
		b += (uint64(k[p+10]) << 16)
		fallthrough
	case 10:
		b += (uint64(k[p+9]) << 8)
		fallthrough
	case 9:
		b += (uint64(k[p+8]))
		fallthrough
	case 8:
		a += (uint64(k[p+7]) << 56)
		fallthrough
	case 7:
		a += (uint64(k[p+6]) << 48)
		fallthrough
	case 6:
		a += (uint64(k[p+5]) << 40)
		fallthrough
	case 5:
		a += (uint64(k[p+4]) << 32)
		fallthrough
	case 4:
		a += (uint64(k[p+3]) << 24)
		fallthrough
	case 3:
		a += (uint64(k[p+2]) << 16)
		fallthrough
	case 2:
		a += (uint64(k[p+1]) << 8)
		fallthrough
	case 1:
		a += uint64(k[p+0])
		/* case 0: nothing left to add */
	}
	mix64(&a, &b, &c)
	/*-------------------------------------------- report the result */
	return c
}

// The check bytes are used to reject strings that aren't in the table
// without paging in the table's cstring data. This checkbyte calculation
// catches 4785/4815 rejects when launching Safari; a perfect checkbyte
// would catch 4796/4815.
func checkbyte(key []byte) uint8 {
	return ((key[0] & 0x7) << 5) | (uint8(len(key)) & 0x1f)
}

func (s StringHash) hash(key []byte) uint32 {
	val := lookup8(key, s.Salt())
	if s.Shift() == 64 {
		return uint32(0)
	}
	index := (val >> uint64(s.Shift())) ^ uint64(s.Scramble()[s.Tab[(val&uint64(s.Mask()))]])
	return uint32(index)
}

func (s StringHash) getIndex(keyStr string) (uint32, error) {
	key := []byte(keyStr)

	h := s.hash(key)

	// Use check byte to reject without paging in the table's cstrings
	hCheck := s.CheckBytes[h]
	keyCheck := checkbyte(key)
	if hCheck != keyCheck {
		return 0, fmt.Errorf("INDEX_NOT_FOUND")
	}

	offset := s.Offsets[h]
	if offset == 0 {
		return 0, fmt.Errorf("INDEX_NOT_FOUND")
	}
	// result = (const char *)this + offset
	// TODO: fix me
	// result := "FIX ME"
	// if result != string(key) {
	// 	return 0, fmt.Errorf("INDEX_NOT_FOUND")
	// }

	return h, nil
}
