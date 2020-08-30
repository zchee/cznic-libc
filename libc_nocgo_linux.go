// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !cgo

package libc // import "modernc.org/libc"

import (
	"bufio"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc/errno"
	"modernc.org/libc/stdio"
	"modernc.org/libc/sys/socket"
	"modernc.org/libc/sys/types"
)

type file uintptr

func (f file) fd() int      { return int((*stdio.FILE)(unsafe.Pointer(f)).F_fileno) }
func (f file) setFd(fd int) { (*stdio.FILE)(unsafe.Pointer(f)).F_fileno = int32(fd) }

func (f file) close(t *TLS) int32 {
	r := Xclose(t, int32(f.fd()))
	Xfree(t, uintptr(f))
	return r
}

func newFile(t *TLS, fd int) uintptr {
	p := Xcalloc(t, 1, types.Size_t(unsafe.Sizeof(stdio.FILE{})))
	if p == 0 {
		return 0
	}

	file(p).setFd(fd)
	return p
}

// int * __errno_location(void);
func X__errno_location(t *TLS) uintptr {
	return t.errnop
}

func (t *TLS) setErrno(err interface{}) { //TODO -> etc.go
again:
	switch x := err.(type) {
	case int:
		*(*int32)(unsafe.Pointer(X__errno_location(t))) = int32(x)
	case int32:
		*(*int32)(unsafe.Pointer(X__errno_location(t))) = x
	case *os.PathError:
		err = x.Err
		goto again
	case unix.Errno:
		*(*int32)(unsafe.Pointer(X__errno_location(t))) = int32(x)
	case *os.SyscallError:
		err = x.Err
		goto again
	default:
		panic(todo("%T", x))
	}
}

func Environ() uintptr {
	return Xenviron
}

func EnvironP() uintptr {
	return uintptr(unsafe.Pointer(&Xenviron))
}

func Xabort(t *TLS) {
	panic(todo(""))
}

func Xexit(t *TLS, status int32) {
	if len(Covered) != 0 { //TODO -> etc.go
		buf := bufio.NewWriter(os.Stdout)
		CoverReport(buf)
		buf.Flush()
	}
	for _, v := range atExit {
		v()
	}
	os.Exit(int(status))
}

// FILE *fdopen(int fd, const char *mode);
func Xfdopen(t *TLS, fd int32, mode uintptr) uintptr {
	panic(todo(""))
}

// int fseek(FILE *stream, long offset, int whence);
func Xfseek(t *TLS, stream uintptr, offset long, whence int32) int32 {
	n := Xlseek(t, int32(file(stream).fd()), offset, whence)
	if n < 0 {
		return -1
	}

	return int32(n)
}

// int fputc(int c, FILE *stream);
func Xfputc(t *TLS, c int32, stream uintptr) int32 {
	panic(todo(""))
}

// int fflush(FILE *stream);
func Xfflush(t *TLS, stream uintptr) int32 {
	return 0 //TODO
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

func X__ccgo_in6addr_anyp(t *TLS) uintptr {
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

// uint32_t htonl(uint32_t hostlong);
func Xhtonl(t *TLS, hostlong uint32) uint32 {
	panic(todo(""))
}

// int fclose(FILE *stream);
func Xfclose(t *TLS, stream uintptr) int32 {
	return file(stream).close(t)
}

// long ftell(FILE *stream);
func Xftell(t *TLS, stream uintptr) long {
	n := Xlseek(t, int32(file(stream).fd()), 0, stdio.SEEK_CUR)
	if n < 0 {
		return -1
	}

	return long(n)
}

// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
func Xfread(t *TLS, ptr uintptr, size, nmemb types.Size_t, stream uintptr) types.Size_t {
	fd := file(stream).fd()
	m := Xread(t, int32(fd), ptr, size*nmemb)
	if m < 0 {
		return 0
	}

	return types.Size_t(m) / size
}

// size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
func Xfwrite(t *TLS, ptr uintptr, size, nmemb types.Size_t, stream uintptr) types.Size_t {
	panic(todo(""))
}

// FILE *fopen64(const char *pathname, const char *mode);
func Xfopen64(t *TLS, pathname, mode uintptr) uintptr {
	s := GoString(pathname)
	m := strings.ReplaceAll(GoString(mode), "b", "")
	var fd int
	var err error
	switch m {
	case "r":
		if fd, err = unix.Open(s, os.O_RDONLY, 0666); err != nil {
			t.setErrno(err)
			return 0
		}
	case "r+":
		if fd, err = unix.Open(s, os.O_RDWR, 0666); err != nil {
			t.setErrno(err)
			return 0
		}
	case "w":
		if fd, err = unix.Open(s, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666); err != nil {
			t.setErrno(err)
			return 0
		}
	case "w+":
		if fd, err = unix.Open(s, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666); err != nil {
			t.setErrno(err)
			return 0
		}
	case "a":
		if fd, err = unix.Open(s, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666); err != nil {
			t.setErrno(err)
			return 0
		}
	case "a+":
		if fd, err = unix.Open(s, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil {
			t.setErrno(err)
			return 0
		}
	default:
		panic(m)
	}
	if p := newFile(t, fd); p != 0 {
		return p
	}

	t.setErrno(errno.ENOMEM)
	return 0
}

// int fgetc(FILE *stream);
func Xfgetc(t *TLS, stream uintptr) int32 {
	panic(todo(""))
}

// int ferror(FILE *stream);
func Xferror(t *TLS, stream uintptr) int32 {
	panic(todo(""))
}
