// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"runtime"
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
	srcString    [256]byte
	testPrintfS1 = [...]byte{'X', 'Y', 0}
)

func TestPrintf(t *testing.T) {
	isWindows = true
	i := uint64(0x123456789abcdef)
	j := uint64(0xf123456789abcde)
	k := uint64(0x23456789abcdef1)
	l := uint64(0xef123456789abcd)
	for itest, test := range []struct {
		fmt    string
		args   []interface{}
		result string
	}{
		{
			"%I64x %I32x %I64x %I32x",
			[]interface{}{int64(i), int32(j), int64(k), int32(l)},
			"123456789abcdef 789abcde 23456789abcdef1 6789abcd",
		},
		{
			"%llx %x %llx %x",
			[]interface{}{int64(i), int32(j), int64(k), int32(l)},
			"123456789abcdef 789abcde 23456789abcdef1 6789abcd",
		},
		{
			"%.1s\n",
			[]interface{}{uintptr(unsafe.Pointer(&testPrintfS1[0]))},
			"X\n",
		},
		{
			"%.2s\n",
			[]interface{}{uintptr(unsafe.Pointer(&testPrintfS1[0]))},
			"XY\n",
		},
	} {
		copy(formatString[:], test.fmt+"\x00")
		b := printf(uintptr(unsafe.Pointer(&formatString[0])), VaList(uintptr(unsafe.Pointer(&valist[0])), test.args...))
		if g, e := string(b), test.result; g != e {
			t.Errorf("%v: %q %q", itest, g, e)
		}
	}
}

func TestStrtod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("TODO")
	}

	tls := NewTLS()
	defer tls.Close()

	for itest, test := range []struct {
		s      string
		result float64
	}{
		{"+0", 0},
		{"+1", 1},
		{"+2", 2},
		{"-0", 0},
		{"-1", -1},
		{"-2", -2},
		{".5", .5},
		{"0", 0},
		{"1", 1},
		{"1.", 1},
		{"1.024e3", 1024},
		{"16", 16},
		{"2", 2},
		{"32", 32},
	} {
		copy(srcString[:], test.s+"\x00")
		if g, e := Xstrtod(tls, uintptr(unsafe.Pointer(&srcString[0])), 0), test.result; g != e {
			t.Errorf("%v: %q: %v %v", itest, test.s, g, e)
		}
	}
}

func TestParseZone(t *testing.T) {
	for itest, test := range []struct {
		in, out string
		off     int
	}{
		{"America/Los_Angeles", "America/Los_Angeles", 0},
		{"America/Los_Angeles+12", "America/Los_Angeles", 43200},
		{"America/Los_Angeles-12", "America/Los_Angeles", -43200},
		{"UTC", "UTC", 0},
		{"UTC+1", "UTC", 3600},
		{"UTC+10", "UTC", 36000},
		{"UTC-1", "UTC", -3600},
		{"UTC-10", "UTC", -36000},
	} {
		out, off := parseZone(test.in)
		if g, e := out, test.out; g != e {
			t.Errorf("%d: %+v %v %v", itest, test, g, e)
		}
		if g, e := off, test.off; g != e {
			t.Errorf("%d: %+v %v %v", itest, test, g, e)
		}
	}
}
