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

// struct servent *getservbyname(const char *name, const char *proto);
func Xgetservbyname(t *TLS, name, proto uintptr) uintptr {
	panic(todo(""))
}

// int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
func Xgetaddrinfo(t *TLS, node, service, hints, res uintptr) int32 { //TODO not needed by sqlite
	panic(todo(""))
}

// void freeaddrinfo(struct addrinfo *res);
func Xfreeaddrinfo(t *TLS, res uintptr) {
	panic(todo(""))
}

// int getnameinfo(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);
func Xgetnameinfo(t *TLS, addr uintptr, addrlen socket.Socklen_t, host uintptr, hostlen socket.Socklen_t, serv uintptr, servlen socket.Socklen_t, flags int32) int32 {
	panic(todo(""))
}

// struct hostent *gethostbyname(const char *name);
func Xgethostbyname(t *TLS, name uintptr) uintptr {
	panic(todo(""))
}

// struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
func Xgethostbyaddr(t *TLS, addr uintptr, len socket.Socklen_t, type1 int32) uintptr {
	panic(todo(""))
}
