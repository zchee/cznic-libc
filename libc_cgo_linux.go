// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo

package libc // import "modernc.org/libc"

import (
	"os"
	"runtime"
	"unsafe"

	"modernc.org/libc/sys/socket"
	"modernc.org/libc/sys/types"
)

/*

#include <dirent.h>
#include <errno.h>
#include <netdb.h>
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

// int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
func Xgetaddrinfo(t *TLS, node, service, hints, res uintptr) int32 {
	return int32(C.getaddrinfo((*C.char)(unsafe.Pointer(node)), (*C.char)(unsafe.Pointer(service)), (*C.struct_addrinfo)(unsafe.Pointer(hints)), (**C.struct_addrinfo)(unsafe.Pointer(res))))
}

// void freeaddrinfo(struct addrinfo *res);
func Xfreeaddrinfo(t *TLS, res uintptr) {
	C.freeaddrinfo((*C.struct_addrinfo)(unsafe.Pointer(res)))
}

// int getnameinfo(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);
func Xgetnameinfo(t *TLS, addr uintptr, addrlen socket.Socklen_t, host uintptr, hostlen socket.Socklen_t, serv uintptr, servlen socket.Socklen_t, flags int32) int32 {
	return int32(C.getnameinfo(
		(*C.struct_sockaddr)(unsafe.Pointer(addr)),
		C.socklen_t(addrlen),
		(*C.char)(unsafe.Pointer(host)),
		C.socklen_t(hostlen),
		(*C.char)(unsafe.Pointer(serv)),
		C.socklen_t(servlen),
		C.int(flags),
	))
}

// struct hostent *gethostbyname(const char *name);
func Xgethostbyname(t *TLS, name uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.gethostbyname((*C.char)(unsafe.Pointer(name)))))
}

// struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
func Xgethostbyaddr(t *TLS, addr uintptr, len socket.Socklen_t, type1 int32) uintptr {
	return uintptr(unsafe.Pointer(C.gethostbyaddr(unsafe.Pointer(addr), C.socklen_t(len), C.int(type1))))
}

func Environ() uintptr {
	return uintptr(unsafe.Pointer(C.environ))
}

func EnvironP() uintptr {
	return uintptr(unsafe.Pointer(&C.environ))
}

// DIR *opendir(const char *name);
func Xopendir(t *TLS, name uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.opendir((*C.char)(unsafe.Pointer(name)))))
}

// struct dirent *readdir(DIR *dirp);
func Xreaddir64(t *TLS, dirp uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.readdir((*C.DIR)(unsafe.Pointer(dirp)))))
}

// int closedir(DIR *dirp);
func Xclosedir(t *TLS, dir uintptr) int32 {
	return int32(C.closedir((*C.DIR)(unsafe.Pointer(dir))))
}
