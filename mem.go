// Copyright 2021 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !libc.membrk

package libc // import "modernc.org/libc"

import (
	"modernc.org/libc/errno"
	"modernc.org/libc/sys/types"
	"modernc.org/memory"
)

var (
	allocator memory.Allocator
)

// void *malloc(size_t size);
func Xmalloc(t *TLS, n types.Size_t) uintptr {
	if n == 0 {
		return 0
	}

	allocMu.Lock()

	defer allocMu.Unlock()

	p, err := allocator.UintptrMalloc(int(n))
	if err != nil {
		t.setErrno(errno.ENOMEM)
		return 0
	}

	return p
}

// void *calloc(size_t nmemb, size_t size);
func Xcalloc(t *TLS, n, size types.Size_t) uintptr {
	rq := int(n * size)
	if rq == 0 {
		return 0
	}

	allocMu.Lock()

	defer allocMu.Unlock()

	p, err := allocator.UintptrCalloc(int(n * size))
	if err != nil {
		t.setErrno(errno.ENOMEM)
		return 0
	}

	return p
}

// void *realloc(void *ptr, size_t size);
func Xrealloc(t *TLS, ptr uintptr, size types.Size_t) uintptr {
	allocMu.Lock()

	defer allocMu.Unlock()

	p, err := allocator.UintptrRealloc(ptr, int(size))
	if err != nil {
		t.setErrno(errno.ENOMEM)
		return 0
	}

	return p
}

// void free(void *ptr);
func Xfree(t *TLS, p uintptr) {
	if p == 0 {
		return
	}

	allocMu.Lock()

	defer allocMu.Unlock()

	allocator.UintptrFree(p)
}

func UsableSize(p uintptr) types.Size_t {
	return types.Size_t(memory.UintptrUsableSize(p))
}
