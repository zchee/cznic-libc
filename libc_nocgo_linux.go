// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !cgo

package libc // import "modernc.org/libc"

import (
	"unsafe"

	"modernc.org/libc/sys/socket"
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

// struct hostent *gethostbyname(const char *name);
func Xgethostbyname(t *TLS, name uintptr) uintptr {
	panic(todo(""))
}

// struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
func Xgethostbyaddr(t *TLS, addr uintptr, len socket.Socklen_t, type1 int32) uintptr {
	panic(todo(""))
}
