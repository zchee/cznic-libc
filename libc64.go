// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64 arm64

package libc // import "modernc.org/libc"

type (
	RawMem [1<<50 - 1]byte
)

type bitset []int

func newBitset(n int) (r bitset) { return make(bitset, (n+63)>>6) }
func (b bitset) has(n int) bool  { return b != nil && b[n>>6]&(1<<uint(n&63)) != 0 }
func (b bitset) set(n int)       { b[n>>6] |= 1 << uint(n&63) }
