// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"modernc.org/libc/errno"
	"modernc.org/libc/stdio"
	"modernc.org/libc/sys/types"
	"modernc.org/libc/unistd"
)

type (
	long     = int32
	longlong = int64
	ulong    = uint32
)

type file uintptr

func (f file) fd() int32      { return (*stdio.FILE)(unsafe.Pointer(f)).F_file }
func (f file) setFd(fd int32) { (*stdio.FILE)(unsafe.Pointer(f)).F_file = fd }

func newFile(t *TLS, fd int32) uintptr {
	p := Xcalloc(t, 1, types.Size_t(unsafe.Sizeof(stdio.FILE{})))
	if p == 0 {
		return 0
	}
	file(p).setFd(fd)
	return p
}

func (f file) close(t *TLS) int32 {
	r := Xclose(t, f.fd())
	Xfree(t, uintptr(f))
	if r < 0 {
		return stdio.EOF
	}

	return 0
}

func fwrite(fd int32, b []byte) (int, error) {
	if fd == unistd.STDOUT_FILENO {
		return write(b)
	}

	if dmesgs {
		dmesg("%v: fd %v: %s", origin(1), fd, b)
	}
	return windows.Write(windows.Handle(fd), b)
}

// int fseek(FILE *stream, long offset, int whence);
func Xfseek(t *TLS, stream uintptr, offset long, whence int32) int32 {
	panic(todo(""))
}

// int vfscanf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__ms_vfscanf(t *TLS, stream, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfscanf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__mingw_vfscanf(t *TLS, stream, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsscanf(const char *str, const char *format, va_list ap);
func X__ms_vsscanf(t *TLS, str, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsscanf(const char *str, const char *format, va_list ap);
func X__mingw_vsscanf(t *TLS, str, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vscanf(const char *format, va_list ap);
func X__ms_vscanf(t *TLS, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsnprintf(char *str, size_t size, const char *format, va_list ap);
func X__ms_vsnprintf(t *TLS, str uintptr, size types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsnprintf(char *str, size_t size, const char *format, va_list ap);
func X__mingw_vsnprintf(t *TLS, str uintptr, size types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfwscanf(FILE *stream, const wchar_t *format, va_list argptr;);
func X__ms_vfwscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfwscanf(FILE *stream, const wchar_t *format, va_list argptr;);
func X__mingw_vfwscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vswscanf(const wchar_t *buffer, const wchar_t *format, va_list arglist);
func X__ms_vswscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vswscanf(const wchar_t *buffer, const wchar_t *format, va_list arglist);
func X__mingw_vswscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vwscanf(const wchar_t * restrict format, va_list arg);
func X__ms_vwscanf(t *TLS, format, ap uintptr) int32 {
	panic(todo(""))
}

// int _vsnwprintf(wchar_t *buffer, size_t count, const wchar_t *format, va_list argptr);
func X_vsnwprintf(t *TLS, buffer uintptr, count types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// int _vsnwprintf(wchar_t *buffer, size_t count, const wchar_t *format, va_list argptr);
func X__mingw_vsnwprintf(t *TLS, buffer uintptr, count types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

func X__acrt_iob_func(t *TLS, fd uint32) uintptr {
	switch fd {
	case unistd.STDIN_FILENO:
		return Xstdin
	case unistd.STDOUT_FILENO:
		return Xstdout
	case unistd.STDERR_FILENO:
		return Xstderr
	default:
		panic(todo(""))
	}
}

// int vfprintf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__mingw_vfprintf(t *TLS, stream, format, ap uintptr) int32 {
	return Xvfprintf(t, stream, format, ap)
}

// int vsprintf(char * restrict s, const char * restrict format, va_list arg);
func X__mingw_vsprintf(t *TLS, s, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfwprintf(FILE * restrict stream, const wchar_t * restrict format, va_list arg);
func X__mingw_vfwprintf(t *TLS, stream, format, ap uintptr) int32 {
	panic(todo(""))
}

func Xabort(t *TLS) {
	panic(todo(""))
}

// int fputs(const char *s, FILE *stream);
func Xfputs(t *TLS, s, stream uintptr) int32 {
	if _, err := fwrite(file(stream).fd(), GoBytes(s, int(Xstrlen(t, s)))); err != nil {
		return -1
	}

	return 0
}

// char *fgets(char *s, int size, FILE *stream);
func Xfgets(t *TLS, s uintptr, size int32, stream uintptr) uintptr {
	fd := windows.Handle(file(stream).fd())
	var b []byte
	buf := [1]byte{}
	for ; size > 0; size-- {
		n, err := windows.Read(fd, buf[:])
		if n != 0 {
			b = append(b, buf[0])
			if buf[0] == '\n' {
				b = append(b, 0)
				copy((*RawMem)(unsafe.Pointer(s))[:len(b):len(b)], b)
				return s
			}

			continue
		}

		switch {
		case n == 0 && err == nil && len(b) == 0:
			return 0
		default:
			panic(todo(""))
		}

		// if err == nil {
		// 	panic("internal error")
		// }

		// if len(b) != 0 {
		// 		b = append(b, 0)
		// 		copy((*RawMem)(unsafe.Pointer(s)[:len(b)]), b)
		// 		return s
		// }

		// t.setErrno(err)
	}
	panic(todo(""))
}

// int close(int fd);
func Xclose(t *TLS, fd int32) int32 {
	if err := windows.Close(windows.Handle(fd)); err != nil {
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %d: ok", origin(1), fd)
	}
	return 0
}

// FILE *fopen64(const char *pathname, const char *mode);
func Xfopen64(t *TLS, pathname, mode uintptr) uintptr {
	m := strings.ReplaceAll(GoString(mode), "b", "")
	var flags int
	switch m {
	case "r":
		flags = os.O_RDONLY
	case "r+":
		flags = os.O_RDWR
	case "w":
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	case "w+":
		flags = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	case "a":
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	case "a+":
		flags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	default:
		panic(m)
	}
	fd, err := windows.Open(GoString(pathname), flags, 0666)
	if err != nil {
		t.setErrno(err)
		return 0
	}

	if p := newFile(t, int32(fd)); p != 0 {
		return p
	}

	Xclose(t, int32(fd))
	t.setErrno(errno.ENOMEM)
	return 0
}

// int __isoc99_sscanf(const char *str, const char *format, ...);
func Xgnu_sscanf(t *TLS, str, format, va uintptr) int32 {
	return scanf(strings.NewReader(GoString(str)), format, va)
}

func __debugbreak(t *TLS) {
	panic(todo(""))
}
