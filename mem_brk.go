// Copyright 2021 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build libc.membrk

// This is a debug-only version of the memory handling functions. When a
// program is built with -tags=libc.membrk a simple but safe version of malloc
// and friends is used that works like sbrk(2). Additionally free becomes a
// nop.

package libc // import "modernc.org/libc"

import (
	"unsafe"

	"modernc.org/libc/errno"
	"modernc.org/libc/sys/types"
)

const (
	heapSize  = 20 << 30 // Adjust for your debugging session requirements and system RAM size.
	heapAlign = 16
)

var (
	heap     = make([]byte, heapSize)
	heapP    = uintptr(unsafe.Pointer(&heap[heapAlign]))
	heapLast = uintptr(unsafe.Pointer(&heap[heapSize-1]))
)

// void *malloc(size_t size);
func Xmalloc(t *TLS, n types.Size_t) uintptr {
	if n == 0 {
		return 0
	}

	allocMu.Lock()

	defer allocMu.Unlock()

	n2 := uintptr(n) + uintptrSize // reserve space for recording block size
	p := roundup(heapP, 16)
	if p+uintptr(n2) >= heapLast {
		t.setErrno(errno.ENOMEM)
		return 0
	}

	heapP = p + uintptr(n2)
	*(*uintptr)(unsafe.Pointer(p - uintptrSize)) = uintptr(n)
	return p
}

// void *calloc(size_t nmemb, size_t size);
func Xcalloc(t *TLS, n, size types.Size_t) uintptr {
	return Xmalloc(t, n*size)
}

// void *realloc(void *ptr, size_t size);
func Xrealloc(t *TLS, ptr uintptr, size types.Size_t) uintptr {
	switch {
	case ptr != 0 && size != 0:
		p := Xmalloc(t, size)
		sz0 := UsableSize(ptr)
		if p != 0 {
			copy((*RawMem)(unsafe.Pointer(p))[:size:size], (*RawMem)(unsafe.Pointer(ptr))[:sz0:sz0])
		}
		return p
	case ptr == 0 && size != 0:
		return Xmalloc(t, size)
	}
	return 0
}

// void free(void *ptr);
func Xfree(t *TLS, p uintptr) {}

func UsableSize(p uintptr) types.Size_t {
	return types.Size_t(*(*uintptr)(unsafe.Pointer(p - uintptrSize)))
}
