// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"testing"
	"unsafe"
)

func TestXfmod(t *testing.T) {
	x := 1.3518643030646695
	y := 6.283185307179586
	if g, e := Xfmod(nil, x, y), 1.3518643030646695; g != e {
		t.Fatal(g, e)
	}
}

func TestSwap(t *testing.T) {
	if g, e := X__builtin_bswap16(nil, 0x1234), uint16(0x3412); g != e {
		t.Errorf("%#04x %#04x", g, e)
	}
	if g, e := X__builtin_bswap32(nil, 0x12345678), uint32(0x78563412); g != e {
		t.Errorf("%#04x %#04x", g, e)
	}
	if g, e := X__builtin_bswap64(nil, 0x123456789abcdef0), uint64(0xf0debc9a78563412); g != e {
		t.Errorf("%#04x %#04x", g, e)
	}
}

var (
	valist       [256]byte
	formatString [256]byte
)

func TestPrintf(t *testing.T) {
	isWindows = true
	i := uint64(0x123456787abcdef8)
	for itest, test := range []struct {
		fmt    string
		args   []interface{}
		result string
	}{
		{
			"%I64x %I32x %I64x %I32x",
			[]interface{}{int64(i), int32(i), int64(i), int32(i)},
			"123456787abcdef8 7abcdef8 123456787abcdef8 7abcdef8",
		},
	} {
		copy(formatString[:], test.fmt+"\x00")
		b := printf(uintptr(unsafe.Pointer(&formatString[0])), VaList(uintptr(unsafe.Pointer(&valist[0])), test.args...))
		if g, e := string(b), test.result; g != e {
			t.Errorf("%v: %q %q", itest, g, e)
		}
	}
}
