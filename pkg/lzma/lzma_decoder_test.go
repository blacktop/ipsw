// Copyright (c) 2010, Andrei Vieru. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

import (
	"bytes"
	"io"
	"log"
	"testing"
)

func TestDecoder(t *testing.T) {
	b := new(bytes.Buffer)
	for _, tt := range lzmaTests {
		in := bytes.NewBuffer(tt.lzma)
		r := NewReader(in)
		defer r.Close()
		b.Reset()
		n, err := io.Copy(b, r)
		if err != tt.err {
			t.Errorf("%s: io.Copy: %v, want %v", tt.descr, err, tt.err)
		}
		if err == nil { // if err != nil, there is little chance that data is decoded correctly, if at all
			s := b.String()
			if s != tt.raw {
				t.Errorf("%s: got %d-byte %q, want %d-byte %q", tt.descr, n, s, len(tt.raw), tt.raw)
			}
		}
	}
}

func BenchmarkDecoder(b *testing.B) {
	b.StopTimer()
	buf := new(bytes.Buffer)
	for i := 0; i < b.N; i++ {
		buf.Reset()
		in := bytes.NewBuffer(bench.lzma)
		b.StartTimer()
		// timer starts before this contructor because variable "in" already
		// contains data, so the decoding start rigth away
		r := NewReader(in)
		n, err := io.Copy(buf, r)
		b.StopTimer()
		if err != nil {
			log.Fatalf("%v", err)
		}
		b.SetBytes(n)
		r.Close()
	}
	if bytes.Equal(buf.Bytes(), bench.raw) == false { // check only after last iteration
		log.Fatalf("%s: got %d-byte %q, want %d-byte %q", bench.descr, len(buf.Bytes()), buf.String(), len(bench.raw), bench.raw)
	}
}
