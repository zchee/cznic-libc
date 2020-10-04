// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"testing"
)

func TestXfmod(t *testing.T) {
	x := 1.3518643030646695
	y := 6.283185307179586
	if g, e := Xfmod(nil, x, y), 1.3518643030646695; g != e {
		t.Fatal(g, e)
	}
}

func TestBswap(t *testing.T) {
	if g, e := X__builtin_bswap16(nil, 0x0123), uint16(0x2301); g != e {
		t.Errorf("%#06x %#06x", g, e)
	}
	if g, e := X__builtin_bswap32(nil, 0x01234567), uint32(0x67452301); g != e {
		t.Errorf("%#10x %#10x", g, e)
	}
	if g, e := X__builtin_bswap64(nil, 0x0123456789abcdef), uint64(0xefcdab8967452301); g != e {
		t.Errorf("%#18x %#18x", g, e)
	}
}
