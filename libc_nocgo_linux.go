// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !cgo

package libc // import "modernc.org/libc"

import (
	"unsafe"
)

// int * __errno_location(void);
func X__errno_location(t *TLS) uintptr {
	return t.errnop
}

func Environ() uintptr {
	return Xenviron
}

func EnvironP() uintptr {
	return uintptr(unsafe.Pointer(&Xenviron))
}
