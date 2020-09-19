// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build 386 arm

package libc // import "modernc.org/libc"

type (
	RawMem [1<<31 - 1]byte
)

type bitset []int

func newBitseett(n int) (r bitset) { return make(bitset, (n+31)>>5) }
func (b bitset) has(n int) bool    { return b != nil && b[n>>5]&(1<<uint(n&31)) != 0 }
func (b bitset) set(n int)         { b[n>>5] |= 1 << uint(n&31) }
