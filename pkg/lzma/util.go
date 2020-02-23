// Copyright (c) 2010, Andrei Vieru. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package lzma

func minInt32(left int32, right int32) int32 {
	if left < right {
		return left
	}
	return right
}

func minUInt32(left uint32, right uint32) uint32 {
	if left < right {
		return left
	}
	return right
}

func maxInt32(left int32, right int32) int32 {
	if left > right {
		return left
	}
	return right
}

func maxUInt32(left uint32, right uint32) uint32 {
	if left > right {
		return left
	}
	return right
}
