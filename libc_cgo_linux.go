// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo

package libc // import "modernc.org/libc"

import (
	"os"
	"runtime"
	"unsafe"

	"modernc.org/libc/sys/types"
)

/*

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

extern char **environ;

FILE *__ccgo_stdout, *__ccgo_stderr, *__ccgo_stdin;

void __ccgo_init() {
	__ccgo_stdout = stdout;
	__ccgo_stderr = stderr;
	__ccgo_stderr = stderr;
}

*/
import "C"

func init() {
	C.__ccgo_init()
	Xstderr = uintptr(unsafe.Pointer(C.__ccgo_stderr))
	Xstdin = uintptr(unsafe.Pointer(C.__ccgo_stdin))
	Xstdout = uintptr(unsafe.Pointer(C.__ccgo_stdout))
}

// void *realloc(void *ptr, size_t size);
func Xrealloc(t *TLS, ptr uintptr, size types.Size_t) uintptr {
	return uintptr(C.realloc(unsafe.Pointer(ptr), C.size_t(size)))
}

// void *calloc(size_t nmemb, size_t size);
func Xcalloc(t *TLS, n, size types.Size_t) uintptr {
	return uintptr(C.calloc(C.size_t(n), C.size_t(size)))
}

// void free(void *ptr);
func Xfree(t *TLS, p uintptr) { C.free(unsafe.Pointer(p)) }

// void *malloc(size_t size);
func Xmalloc(t *TLS, n types.Size_t) uintptr { return uintptr(C.malloc(C.size_t(n))) }

func Start(main func(*TLS, int32, uintptr) int32) {
	runtime.LockOSThread()
	t := NewTLS()
	argv := mustCalloc(t, types.Size_t((len(os.Args)+1)*int(uintptrSize)))
	p := argv
	for _, v := range os.Args {
		s := mustCalloc(t, types.Size_t(len(v)+1))
		copy((*RawMem)(unsafe.Pointer(s))[:len(v):len(v)], v)
		*(*uintptr)(unsafe.Pointer(p)) = s
		p += uintptrSize
	}
	Xexit(t, main(t, int32(len(os.Args)), argv))
}

// int * __errno_location(void);
func X__errno_location(t *TLS) uintptr {
	return uintptr(unsafe.Pointer(C.__errno_location()))
}

func Environ() uintptr {
	return uintptr(unsafe.Pointer(C.environ))
}

func EnvironP() uintptr {
	return uintptr(unsafe.Pointer(&C.environ))
}
