// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

/*

#include <aclapi.h>
#include <fcntl.h>
#include <locale.h>
#include <process.h>
#include <stdio.h>
#include <time.h>
#include <windows.h>

extern char ***__imp_environ;
extern unsigned __ccgo_getLastError();
extern void *__ccgo_environ();
extern void *__ccgo_errno_location();
extern int __ccgo_errno();

extern HANDLE __ccgo_CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  SIZE_T                  dwStackSize,
  unsigned long long      obj,
  DWORD                   dwCreationFlags,
  LPDWORD                 lpThreadId
);

*/
import "C"

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"modernc.org/libc/sys/types"
)

type (
	long     = int32
	longlong = int64
	ulong    = uint32
)

// Keep these outside of the var block otherwise go generate will miss them.
// var X__imp__environ = uintptr(C.__ccgo_environ_location())
var X__imp__environ = uintptr(unsafe.Pointer(C.__imp__environ))

var (
	// msvcrt.dll
	printfAddr uintptr
	sprintf    uintptr
	fprintf    uintptr
	sscanf     uintptr

	// kernel32.dll
	formatMessageW      uintptr
	cancelSynchronousIo uintptr

	// ntdll.dll
	rtlGetVersion uintptr

	// user32.dll
	wsprintfA uintptr

	// netapi32.lib
	netUserGetInfo uintptr
	netGetDCName   uintptr
)

func init() {
	mustLinkDll("msvcrt.dll", []linkFunc{
		{"printf", &printfAddr},
		{"sprintf", &sprintf},
		{"fprintf", &fprintf},
		{"sscanf", &sscanf},
	})
	mustLinkDll("kernel32.dll", []linkFunc{
		{"FormatMessageW", &formatMessageW},
		{"CancelSynchronousIo", &cancelSynchronousIo},
	})
	mustLinkDll("ntdll.dll", []linkFunc{
		{"RtlGetVersion", &rtlGetVersion},
	})
	mustLinkDll("user32.dll", []linkFunc{
		{"wsprintfA", &wsprintfA},
	})
	mustLinkDll("netapi32.dll", []linkFunc{
		{"NetUserGetInfo", &netUserGetInfo},
		{"NetGetDCName", &netGetDCName},
	})
}

type linkFunc struct {
	name string
	p    *uintptr
}

func mustLinkDll(lib string, a []linkFunc) {
	dll, err := syscall.LoadLibrary(lib)
	if err != nil {
		panic(fmt.Errorf("cannot load %s: %v", lib, err))
	}

	for _, v := range a {
		p, err := syscall.GetProcAddress(dll, v.name)
		if p == 0 || err != nil {
			panic(fmt.Errorf("cannot find %s in %s: %v", v.name, lib, err))
		}

		*v.p = p
	}
}

type TLS struct {
	ID int32
	//TODO errnop    uintptr
	lastError syscall.Errno
	stack     stackHeader

	locked bool
}

func NewTLS() *TLS {
	id := atomic.AddInt32(&tid, 1)
	t := &TLS{ID: id}
	//TODO t.errnop = mustCalloc(t, types.Size_t(unsafe.Sizeof(int32(0))))
	return t
}

func (t *TLS) Close() {
	//TODO Xfree(t, t.errnop)
}

// void free(void *ptr);
func Xfree(t *TLS, p uintptr) {
	C.free(unsafe.Pointer(p))
}

// void *malloc(size_t size);
func Xmalloc(t *TLS, n types.Size_t) uintptr {
	return uintptr(C.malloc(C.ulonglong(n)))
}

// void *calloc(size_t nmemb, size_t size);
func Xcalloc(t *TLS, n, size types.Size_t) uintptr {
	return uintptr(C.calloc(C.ulonglong(n), C.ulonglong(size)))
}

func Environ() uintptr {
	return uintptr(C.__ccgo_environ())
}

func X___errno_location(t *TLS) uintptr {
	return uintptr(C.__ccgo_errno_location())
}

func X__builtin_abort(t *TLS) {
	C.abort()
}

// int vfscanf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__ms_vfscanf(t *TLS, stream, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsscanf(const char *str, const char *format, va_list ap);
func X__ms_vsscanf(t *TLS, str, format, ap uintptr) int32 {
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

// int vfwscanf(FILE *stream, const wchar_t *format, va_list argptr;);
func X__ms_vfwscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vswscanf(const wchar_t *buffer, const wchar_t *format, va_list arglist);
func X__ms_vswscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
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

func Start(main func(*TLS, int32, uintptr) int32) {
	t := NewTLS()
	t.lockOSThread()
	argv := mustCalloc(t, types.Size_t((len(os.Args)+1)*int(uintptrSize)))
	p := argv
	for _, v := range os.Args {
		s := mustCalloc(t, types.Size_t(len(v)+1))
		copy((*RawMem)(unsafe.Pointer(s))[:len(v):len(v)], v)
		*(*uintptr)(unsafe.Pointer(p)) = s
		p += uintptrSize
	}
	SetEnviron(t, os.Environ())
	Xexit(t, main(t, int32(len(os.Args)), argv))
}

func Xexit(t *TLS, status int32) {
	if len(Covered) != 0 {
		buf := bufio.NewWriter(os.Stdout)
		CoverReport(buf)
		buf.Flush()
	}
	if len(CoveredC) != 0 {
		buf := bufio.NewWriter(os.Stdout)
		CoverCReport(buf)
		buf.Flush()
	}
	for _, v := range atExit {
		v()
	}
	X_exit(t, status)
}

// void _exit(int status);
func X_exit(t *TLS, status int32) {
	os.Exit(int(status))
}

func SetEnviron(t *TLS, env []string) {
	p := mustCalloc(t, types.Size_t((len(env)+1)*(int(uintptrSize))))
	*(*uintptr)(unsafe.Pointer(EnvironP())) = p
	for _, v := range env {
		s := mustCalloc(t, types.Size_t(len(v)+1))
		copy((*(*RawMem)(unsafe.Pointer(s)))[:len(v):len(v)], v)
		*(*uintptr)(unsafe.Pointer(p)) = s
		p += uintptrSize
	}
}

func EnvironP() uintptr {
	return uintptr(unsafe.Pointer(C.__imp__environ))
}

// int printf(const char *format, ...);
func Xprintf(t *TLS, format, args uintptr) int32 {
	return int32(sysv(t, printfAddr, format, args))
}

func sysv(t *TLS, proc uintptr, args ...interface{}) uintptr {
	va := args[len(args)-1].(uintptr)
	if va != 0 {
		args = args[:len(args)-1]
		va -= 8
		n := int(VaInt32(&va))
		for i := 0; i < n; i++ {
			args = append(args, VaInt64(&va))
		}
	}
	return sys(t, proc, args...)
}

func sys(t *TLS, proc uintptr, args ...interface{}) uintptr {
	n, _ := sys2(t, proc, args...)
	return n
}

func sys2(t *TLS, proc uintptr, args ...interface{}) (r uintptr, err error) {
	na0 := uintptr(len(args))
	na := na0
	if n := na % 3; n != 0 {
		na += 3 - n
	}
	if na == 0 {
		na = 3
	}
	a := make([]uintptr, na)
	for i, v := range args {
		switch x := v.(type) {
		case uintptr:
			a[i] = x
		case int16:
			a[i] = uintptr(x)
		case int32:
			a[i] = uintptr(x)
		case int64:
			a[i] = uintptr(x)
		case uint16:
			a[i] = uintptr(x)
		case uint32:
			a[i] = uintptr(x)
		case uint64:
			a[i] = uintptr(x)
		case float32:
			a[i] = uintptr(x)
		case float64:
			a[i] = uintptr(x)
		default:
			panic(todo("%T", x))
		}
	}
	switch na {
	case 3:
		r, _, t.lastError = syscall.Syscall(proc, na0, a[0], a[1], a[2])
	case 6:
		r, _, t.lastError = syscall.Syscall6(proc, na0, a[0], a[1], a[2], a[3], a[4], a[5])
	case 9:
		r, _, t.lastError = syscall.Syscall9(proc, na0, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
	case 12:
		r, _, t.lastError = syscall.Syscall12(proc, na0, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11])
	case 15:
		r, _, t.lastError = syscall.Syscall15(proc, na0, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14])
	case 18:
		r, _, t.lastError = syscall.Syscall18(proc, na0, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15], a[16], a[17])
	default:
		panic(todo("", na))
	}
	return r, t.lastError
}

// VaList fills a varargs list at p with number of args and args and returns
// uintptr(p)+8.  The list must have been allocated by caller and it must not
// be in Go managed memory, ie. it must be pinned. Caller is responsible for
// freeing the list.
//
// Individual arguments must be one of int, uint, int32, uint32, int64, uint64,
// float64, uintptr or Intptr. Other types will panic.
//
// Note: The C translated to Go varargs ABI alignment for all types is 8 at all
// architectures.
func VaList(p uintptr, args ...interface{}) (r uintptr) {
	if p&7 != 0 {
		panic("internal error")
	}

	*(*int64)(unsafe.Pointer(p)) = int64(len(args))
	p += 8
	r = p
	for _, v := range args {
		switch x := v.(type) {
		case int:
			*(*int64)(unsafe.Pointer(p)) = int64(x)
		case int32:
			*(*int64)(unsafe.Pointer(p)) = int64(x)
		case int64:
			*(*int64)(unsafe.Pointer(p)) = x
		case uint:
			*(*uint64)(unsafe.Pointer(p)) = uint64(x)
		case uint32:
			*(*uint64)(unsafe.Pointer(p)) = uint64(x)
		case uint64:
			*(*uint64)(unsafe.Pointer(p)) = x
		case float64:
			*(*float64)(unsafe.Pointer(p)) = x
		case uintptr:
			*(*uint64)(unsafe.Pointer(p)) = uint64(x)
		default:
			panic(todo("invalid VaList argument type: %T", x))
		}
		p += 8
	}
	return r
}

// char *strcpy(char *dest, const char *src)
func Xstrcpy(t *TLS, dest, src uintptr) (r uintptr) {
	return uintptr(unsafe.Pointer(C.strcpy((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)))))
}

// char *strncpy(char *dest, const char *src, size_t n)
func Xstrncpy(t *TLS, dest, src uintptr, n types.Size_t) (r uintptr) {
	return uintptr(unsafe.Pointer(C.strncpy((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)), C.size_t(n))))
}

// int strcmp(const char *s1, const char *s2)
func Xstrcmp(t *TLS, s1, s2 uintptr) int32 {
	return int32(C.strcmp((*C.char)(unsafe.Pointer(s1)), (*C.char)(unsafe.Pointer(s2))))
}

// size_t strlen(const char *s)
func Xstrlen(t *TLS, s uintptr) (r types.Size_t) {
	return types.Size_t(C.strlen((*C.char)(unsafe.Pointer(s))))
}

// char *strcat(char *dest, const char *src)
func Xstrcat(t *TLS, dest, src uintptr) (r uintptr) {
	return uintptr(unsafe.Pointer(C.strcat((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)))))
}

// int strncmp(const char *s1, const char *s2, size_t n)
func Xstrncmp(t *TLS, s1, s2 uintptr, n types.Size_t) int32 {
	return int32(C.strncmp((*C.char)(unsafe.Pointer(s1)), (*C.char)(unsafe.Pointer(s2)), C.size_t(n)))
}

// char *strchr(const char *s, int c)
func Xstrchr(t *TLS, s uintptr, c int32) uintptr {
	return uintptr(unsafe.Pointer(C.strchr((*C.char)(unsafe.Pointer(s)), C.int(c))))
}

// char *strrchr(const char *s, int c)
func Xstrrchr(t *TLS, s uintptr, c int32) (r uintptr) {
	return uintptr(unsafe.Pointer(C.strrchr((*C.char)(unsafe.Pointer(s)), C.int(c))))
}

// void *memset(void *s, int c, size_t n)
func Xmemset(t *TLS, s uintptr, c int32, n types.Size_t) uintptr {
	return uintptr(unsafe.Pointer(C.memset(unsafe.Pointer(s), C.int(c), C.size_t(n))))
}

// void *memcpy(void *dest, const void *src, size_t n);
func Xmemcpy(t *TLS, dest, src uintptr, n types.Size_t) (r uintptr) {
	return uintptr(unsafe.Pointer(C.memcpy(unsafe.Pointer(dest), unsafe.Pointer(src), C.size_t(n))))
}

// int memcmp(const void *s1, const void *s2, size_t n);
func Xmemcmp(t *TLS, s1, s2 uintptr, n types.Size_t) int32 {
	return int32(C.memcmp(unsafe.Pointer(s1), unsafe.Pointer(s2), C.size_t(n)))
}

// int sprintf(char *str, const char *format, ...);
func Xsprintf(t *TLS, str, format, args uintptr) (r int32) {
	r = int32(sysv(t, sprintf, str, format, args))
	// if dmesgs {
	// 	dmesg("%v: %q %v: %q %v", origin(1), GoString(format), varargs(args), GoString(str), r)
	// }
	return r
}

func varargs(va uintptr) (r []uint64) {
	if va != 0 {
		va -= 8
		n := int(VaInt32(&va))
		for i := 0; i < n; i++ {
			r = append(r, VaUint64(&va))
		}
	}
	return r
}

// int vfscanf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__mingw_vfscanf(t *TLS, stream, format, ap uintptr) int32 {
	panic(todo(""))
}

// __acrt_iob_func
func X__acrt_iob_func(t *TLS, fd uint32) uintptr {
	return uintptr(unsafe.Pointer(C.__acrt_iob_func(C.uint(fd))))
}

// int vsscanf(const char *str, const char *format, va_list ap);
func X__mingw_vsscanf(t *TLS, str, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfprintf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__mingw_vfprintf(t *TLS, stream, format, ap uintptr) int32 {
	return int32(sysv(t, fprintf, stream, format, ap))
}

// int vsprintf(char * restrict s, const char * restrict format, va_list arg);
func X__mingw_vsprintf(t *TLS, s, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsnprintf(char *str, size_t size, const char *format, va_list ap);
func X__mingw_vsnprintf(t *TLS, str uintptr, size types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfwscanf(FILE *stream, const wchar_t *format, va_list argptr;);
func X__mingw_vfwscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vswscanf(const wchar_t *buffer, const wchar_t *format, va_list arglist);
func X__mingw_vswscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfwprintf(FILE * restrict stream, const wchar_t * restrict format, va_list arg);
func X__mingw_vfwprintf(t *TLS, stream, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsnwprintf(wchar_t *buffer, size_t count, const wchar_t *format, va_list argptr);
func X__mingw_vsnwprintf(t *TLS, buffer uintptr, count types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// long atol(const char *nptr);
func Xatol(t *TLS, nptr uintptr) long {
	panic(todo(""))
}

// int putchar(int c);
func Xputchar(t *TLS, c int32) int32 {
	panic(todo(""))
}

// int atoi(const char *nptr);
func Xatoi(t *TLS, nptr uintptr) int32 {
	return int32(C.atoi((*C.char)(unsafe.Pointer(nptr))))
}

// int putc(int c, FILE *stream);
func Xputc(t *TLS, c int32, fp uintptr) int32 {
	return int32(C.putc(C.int(c), (*C.FILE)(unsafe.Pointer(fp))))
}

// int fputs(const char *s, FILE *stream);
func Xfputs(t *TLS, s, stream uintptr) int32 {
	panic(todo(""))
}

// int fprintf(FILE *stream, const char *format, ...);
func Xfprintf(t *TLS, stream, format, args uintptr) int32 {
	return int32(sysv(t, fprintf, stream, format, args))
}

// char *fgets(char *s, int size, FILE *stream);
func Xfgets(t *TLS, s uintptr, size int32, stream uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.fgets((*C.char)(unsafe.Pointer(s)), C.int(size), (*C.FILE)(unsafe.Pointer(stream)))))
}

// void perror(const char *s);
func Xperror(t *TLS, s uintptr) {
	panic(todo(""))
}

// FILE *fopen(const char *pathname, const char *mode);
func Xfopen(t *TLS, pathname, mode uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.fopen((*C.char)(unsafe.Pointer(pathname)), (*C.char)(unsafe.Pointer(mode)))))
}

// void *realloc(void *ptr, size_t size);
func Xrealloc(t *TLS, ptr uintptr, size types.Size_t) uintptr {
	return uintptr(C.realloc(unsafe.Pointer(ptr), C.size_t(size)))
}

// int toupper(int c);
func Xtoupper(t *TLS, c int32) int32 {
	return int32(C.toupper(C.int(c)))
}

// int fclose(FILE *stream);
func Xfclose(t *TLS, stream uintptr) int32 {
	return int32(C.fclose((*C.FILE)(unsafe.Pointer(stream))))
}

// void _assert(
//    char const* message,
//    char const* filename,
//    unsigned line
// );
func X_assert(t *TLS, message, filename uintptr, line uint32) {
	panic(todo(""))
}

// long _InterlockedCompareExchange(
//    long volatile * Destination,
//    long Exchange,
//    long Comparand
// );
func X_InterlockedCompareExchange(t *TLS, Destination uintptr, Exchange, Comparand long) long {
	return long(C._InterlockedCompareExchange((*C.long)(unsafe.Pointer(Destination)), C.long(Exchange), C.long(Comparand)))
}

// struct tm *localtime( const time_t *sourceTime );
func Xlocaltime(t *TLS, sourceTime uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.localtime((*C.longlong)(unsafe.Pointer(sourceTime)))))
}

// char *strdup(const char *s);
func X_strdup(t *TLS, s uintptr) uintptr {
	panic(todo(""))
	// return Xstrdup(t, s)
}

// int _access(
//    const char *path,
//    int mode
// );
func X_access(t *TLS, pathname uintptr, mode int32) int32 {
	return int32(C._access((*C.char)(unsafe.Pointer(pathname)), C.int(mode)))
}

// BOOL WINAPI SetConsoleCtrlHandler(
//   _In_opt_ PHANDLER_ROUTINE HandlerRoutine,
//   _In_     BOOL             Add
// );
func XSetConsoleCtrlHandler(t *TLS, HandlerRoutine uintptr, Add int32) int32 {
	return 1 //TODO
}

// DebugBreak
func XDebugBreak(t *TLS) {
	panic(todo(""))
}

// int _getpid( void );
func Xgetpid(t *TLS) int32 {
	return int32(C._getpid())
}

// int _isatty( int fd );
func X_isatty(t *TLS, fd int32) int32 {
	return int32(C._isatty(C.int(fd)))
}

// int setvbuf(
//    FILE *stream,
//    char *buffer,
//    int mode,
//    size_t size
// );
func Xsetvbuf(t *TLS, stream, buffer uintptr, mode int32, size types.Size_t) int32 {
	return int32(C.setvbuf((*C.FILE)(unsafe.Pointer(stream)), (*C.char)(unsafe.Pointer(buffer)), C.int(mode), C.size_t(size)))
}

// BOOL WINAPI SetConsoleTextAttribute(
//   _In_ HANDLE hConsoleOutput,
//   _In_ WORD   wAttributes
// );
func XSetConsoleTextAttribute(t *TLS, hConsoleOutput uintptr, wAttributes uint16) int32 {
	panic(todo(""))
}

// BOOL WINAPI GetConsoleScreenBufferInfo(
//   _In_  HANDLE                      hConsoleOutput,
//   _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo
// );
func XGetConsoleScreenBufferInfo(t *TLS, hConsoleOutput, lpConsoleScreenBufferInfo uintptr) int32 {
	panic(todo(""))
}

// HANDLE WINAPI GetStdHandle(
//   _In_ DWORD nStdHandle
// );
func XGetStdHandle(t *TLS, nStdHandle uint32) uintptr {
	return uintptr(C.GetStdHandle(C.ulong(nStdHandle)))
}

// int system(
//    const char *command
// );
func Xsystem(t *TLS, command uintptr) int32 {
	panic(todo(""))
}

// FILE *_popen(
//     const char *command,
//     const char *mode
// );
func X_popen(t *TLS, command, mode uintptr) uintptr {
	panic(todo(""))
}

// BOOL SetCurrentDirectoryW(
//   LPCTSTR lpPathName
// );
func XSetCurrentDirectoryW(t *TLS, lpPathName uintptr) int32 {
	return int32(C.SetCurrentDirectoryW((*C.ushort)(unsafe.Pointer(lpPathName))))
}

// int _wunlink(
//    const wchar_t *filename
// );
func X_wunlink(t *TLS, filename uintptr) int32 {
	panic(todo(""))
}

// BOOL SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime);
func XSystemTimeToFileTime(t *TLS, lpSystemTime, lpFileTime uintptr) int32 {
	panic(todo(""))
}

// HANDLE CreateFileW(
//   LPCWSTR               lpFileName,
//   DWORD                 dwDesiredAccess,
//   DWORD                 dwShareMode,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//   DWORD                 dwCreationDisposition,
//   DWORD                 dwFlagsAndAttributes,
//   HANDLE                hTemplateFile
// );
func XCreateFileW(t *TLS, lpFileName uintptr, dwDesiredAccess, dwShareMode uint32, lpSecurityAttributes uintptr, dwCreationDisposition, dwFlagsAndAttributes uint32, hTemplateFile uintptr) uintptr {
	return uintptr(C.CreateFileW((*C.ushort)(unsafe.Pointer(lpFileName)), C.ulong(dwDesiredAccess), C.ulong(dwShareMode), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpSecurityAttributes)), C.ulong(dwCreationDisposition), C.ulong(dwFlagsAndAttributes), C.HANDLE(hTemplateFile)))
}

// BOOL SetFileTime(
//   HANDLE         hFile,
//   const FILETIME *lpCreationTime,
//   const FILETIME *lpLastAccessTime,
//   const FILETIME *lpLastWriteTime
// );
func XSetFileTime(t *TLS, hFile uintptr, lpCreationTime, lpLastAccessTime, lpLastWriteTime uintptr) int32 {
	return int32(C.SetFileTime(C.HANDLE(hFile), (*C.struct__FILETIME)(unsafe.Pointer(lpCreationTime)), (*C.struct__FILETIME)(unsafe.Pointer(lpLastAccessTime)), (*C.struct__FILETIME)(unsafe.Pointer(lpLastWriteTime))))
}

// BOOL CloseHandle(
//   HANDLE hObject
// );
func XCloseHandle(t *TLS, hObject uintptr) int32 {
	return int32(C.CloseHandle(C.HANDLE(hObject)))
}

// _CRTIMP extern int *__cdecl _errno(void); // /usr/share/mingw-w64/include/errno.h:17:
func X_errno(t *TLS) uintptr {
	return uintptr(C.__ccgo_errno_location())
}

func Xclosedir(tls *TLS, dir uintptr) int32 {
	panic(todo(""))
}

func Xopendir(tls *TLS, name uintptr) uintptr {
	panic(todo(""))
}

func Xreaddir(tls *TLS, dir uintptr) uintptr {
	panic(todo(""))
}

func fwrite(fd int32, b []byte) (int, error) {
	panic(todo(""))
}

// int fseek(FILE *stream, long offset, int whence);
func Xfseek(t *TLS, stream uintptr, offset long, whence int32) int32 {
	return int32(C.fseek((*C.struct__iobuf)(unsafe.Pointer(stream)), C.long(offset), C.int(whence)))
}

// long ftell(FILE *stream);
func Xftell(t *TLS, stream uintptr) long {
	return long(C.ftell((*C.struct__iobuf)(unsafe.Pointer(stream))))
}

// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
func Xfread(t *TLS, ptr uintptr, size, nmemb types.Size_t, stream uintptr) types.Size_t {
	return types.Size_t(C.fread(unsafe.Pointer(ptr), C.size_t(size), C.size_t(nmemb), (*C.FILE)(unsafe.Pointer(stream))))
}

// int _unlink(
//    const char *filename
// );
func X_unlink(t *TLS, filename uintptr) int32 {
	panic(todo(""))
}

// int pclose(FILE *stream);
func X_pclose(t *TLS, stream uintptr) int32 {
	panic(todo(""))
}

// void GetSystemTimeAsFileTime(
//   LPFILETIME lpSystemTimeAsFileTime
// );
func XGetSystemTimeAsFileTime(t *TLS, lpSystemTimeAsFileTime uintptr) {
	C.GetSystemTimeAsFileTime((*C.struct__FILETIME)(unsafe.Pointer(lpSystemTimeAsFileTime)))
}

// void GetSystemInfo(
//   LPSYSTEM_INFO lpSystemInfo
// );
func XGetSystemInfo(t *TLS, lpSystemInfo uintptr) {
	C.GetSystemInfo((*C.struct__SYSTEM_INFO)(unsafe.Pointer(lpSystemInfo)))
}

// DWORD GetTickCount();
func XGetTickCount(t *TLS) uint32 {
	return uint32(C.GetTickCount())
}

// BOOL GetVersionExA(
//   LPOSVERSIONINFOA lpVersionInformation
// );
func XGetVersionExA(t *TLS, lpVersionInformation uintptr) int32 {
	return int32(C.GetVersionExA((*C.OSVERSIONINFOA)(unsafe.Pointer(lpVersionInformation))))
}

// BOOL GetVersionExW(
//   LPOSVERSIONINFOW lpVersionInformation
// );
func XGetVersionExW(t *TLS, lpVersionInformation uintptr) int32 {
	return int32(C.GetVersionExW((*C.struct__OSVERSIONINFOW)(unsafe.Pointer(lpVersionInformation))))
}

// HLOCAL LocalFree(
//   HLOCAL hMem
// );
func XLocalFree(t *TLS, hMem uintptr) uintptr {
	return uintptr(C.LocalFree(C.HANDLE(hMem)))
}

// DWORD FormatMessageA(
//   DWORD   dwFlags,
//   LPCVOID lpSource,
//   DWORD   dwMessageId,
//   DWORD   dwLanguageId,
//   LPSTR   lpBuffer,
//   DWORD   nSize,
//   va_list *Arguments
// );
func XFormatMessageA(t *TLS, dwFlagsAndAttributes uint32, lpSource uintptr, dwMessageId, dwLanguageId uint32, lpBuffer uintptr, nSize uint32, Arguments uintptr) uint32 {
	panic(todo(""))
}

// DWORD FormatMessageW(
//   DWORD   dwFlags,
//   LPCVOID lpSource,
//   DWORD   dwMessageId,
//   DWORD   dwLanguageId,
//   LPWSTR  lpBuffer,
//   DWORD   nSize,
//   va_list *Arguments
// );
func XFormatMessageW(t *TLS, dwFlags uint32, lpSource uintptr, dwMessageId, dwLanguageId uint32, lpBuffer uintptr, nSize uint32, Arguments uintptr) uint32 {
	return uint32(sysv(t, formatMessageW, dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments))
}

// HMODULE LoadLibraryA(LPCSTR lpLibFileName);
func XLoadLibraryA(t *TLS, lpLibFileName uintptr) uintptr {
	panic(todo(""))
}

// HMODULE LoadLibraryW(
//   LPCWSTR lpLibFileName
// );
func XLoadLibraryW(t *TLS, lpLibFileName uintptr) uintptr {
	panic(todo(""))
}

// HANDLE CreateFileMappingA(
//   HANDLE                hFile,
//   LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
//   DWORD                 flProtect,
//   DWORD                 dwMaximumSizeHigh,
//   DWORD                 dwMaximumSizeLow,
//   LPCSTR                lpName
// );
func XCreateFileMappingA(t *TLS, hFile, lpFileMappingAttributes uintptr, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow uint32, lpName uintptr) uintptr {
	panic(todo(""))
}

// DWORD GetTempPathA(
//   DWORD nBufferLength,
//   LPSTR lpBuffer
// );
func XGetTempPathA(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	panic(todo(""))
}

// BOOL AreFileApisANSI();
func XAreFileApisANSI(t *TLS) int32 {
	panic(todo(""))
}

// int _setmode (int fd, int mode);
func X_setmode(t *TLS, fd, mode int32) int32 {
	return int32(C._setmode(C.int(fd), C.int(mode)))
}

// HANDLE GetCurrentProcess();
func XGetCurrentProcess(t *TLS) uintptr {
	return uintptr(C.GetCurrentProcess())
}

// FARPROC GetProcAddress(HMODULE hModule, LPCSTR  lpProcName);
func XGetProcAddress(t *TLS, hModule, lpProcName uintptr) uintptr {
	s := GoString(lpProcName)
	switch s {
	case "CancelSynchronousIo":
		return *(*uintptr)(unsafe.Pointer(&struct {
			f func(*TLS, uintptr) int32
		}{XCancelSynchronousIo}))
	case "RtlGetVersion":
		return *(*uintptr)(unsafe.Pointer(&struct {
			f func(*TLS, uintptr) uintptr
		}{XRtlGetVersion}))
	default:
		panic(todo("%q", s))
	}

}

// BOOL FreeLibrary(HMODULE hLibModule);
func XFreeLibrary(t *TLS, hLibModule uintptr) int32 {
	panic(todo(""))
}

// HANDLE FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
func XFindFirstFileW(t *TLS, lpFileName, lpFindFileData uintptr) uintptr {
	return uintptr(C.FindFirstFileW((*C.ushort)(unsafe.Pointer(lpFileName)), (*C.struct__WIN32_FIND_DATAW)(unsafe.Pointer(lpFindFileData))))
}

// BOOL FindClose(HANDLE hFindFile);
func XFindClose(t *TLS, hFindFile uintptr) int32 {
	return int32(C.FindClose(C.HANDLE(hFindFile)))
}

// int _stat64(const char *path, struct __stat64 *buffer);
func X_stat64(t *TLS, path, buffer uintptr) int32 {
	panic(todo(""))
}

// int _mkdir(const char *dirname);
func X_mkdir(t *TLS, dirname uintptr) int32 {
	panic(todo(""))
}

// size_t fwrite(const void *buffer, size_t size, size_t count, FILE *stream);
func Xfwrite(t *TLS, buffer uintptr, size, count types.Size_t, stream uintptr) types.Size_t {
	return types.Size_t(C.fwrite(unsafe.Pointer(buffer), C.ulonglong(size), C.ulonglong(count), (*C.struct__iobuf)(unsafe.Pointer(stream))))
}

// int _chmod( const char *filename, int pmode );
func X_chmod(t *TLS, filename uintptr, pmode int32) int32 {
	panic(todo(""))
}

// void GetSystemTime(LPSYSTEMTIME lpSystemTime);
func XGetSystemTime(t *TLS, lpSystemTime uintptr) {
	C.GetSystemTime((*C.struct__SYSTEMTIME)(unsafe.Pointer(lpSystemTime)))
}

// DWORD GetFileAttributesW(
//   LPCWSTR lpFileName
// );
func XGetFileAttributesW(t *TLS, lpFileName uintptr) uint32 {
	return uint32(C.GetFileAttributesW((*C.ushort)(unsafe.Pointer(lpFileName))))
}

// DWORD GetFileSize(
//   HANDLE  hFile,
//   LPDWORD lpFileSizeHigh
// );
func XGetFileSize(t *TLS, hFile, lpFileSizeHigh uintptr) uint32 {
	return uint32(C.GetFileSize(C.HANDLE(hFile), (*C.ulong)(unsafe.Pointer(lpFileSizeHigh))))
}

// DWORD SetFilePointer(
//   HANDLE hFile,
//   LONG   lDistanceToMove,
//   PLONG  lpDistanceToMoveHigh,
//   DWORD  dwMoveMethod
// );
func XSetFilePointer(t *TLS, hFile uintptr, lDistanceToMove long, lpDistanceToMoveHigh uintptr, dwMoveMethod uint32) uint32 {
	return uint32(C.SetFilePointer(C.HANDLE(hFile), C.long(lDistanceToMove), (*C.long)(unsafe.Pointer(lpDistanceToMoveHigh)), C.ulong(dwMoveMethod)))
}

// HANDLE CreateFileA(
//   LPCSTR                lpFileName,
//   DWORD                 dwDesiredAccess,
//   DWORD                 dwShareMode,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//   DWORD                 dwCreationDisposition,
//   DWORD                 dwFlagsAndAttributes,
//   HANDLE                hTemplateFile
// );
func XCreateFileA(t *TLS, lpFileName uintptr, dwDesiredAccess, dwShareMode uint32, lpSecurityAttributes uintptr, dwCreationDisposition, dwFlagsAndAttributes uint32, hTemplateFile uintptr) uintptr {
	panic(todo(""))
}

// BOOL GetDiskFreeSpaceA(
//   LPCSTR  lpRootPathName,
//   LPDWORD lpSectorsPerCluster,
//   LPDWORD lpBytesPerSector,
//   LPDWORD lpNumberOfFreeClusters,
//   LPDWORD lpTotalNumberOfClusters
// );
func XGetDiskFreeSpaceA(t *TLS, lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters uintptr) int32 {
	panic(todo(""))
}

// BOOL GetDiskFreeSpaceW(
//   LPCWSTR lpRootPathName,
//   LPDWORD lpSectorsPerCluster,
//   LPDWORD lpBytesPerSector,
//   LPDWORD lpNumberOfFreeClusters,
//   LPDWORD lpTotalNumberOfClusters
// );
func XGetDiskFreeSpaceW(t *TLS, lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters uintptr) int32 {
	panic(todo(""))
}

// DWORD GetFileAttributesA(
//   LPCSTR lpFileName
// );
func XGetFileAttributesA(t *TLS, lpFileName uintptr) uint32 {
	return uint32(C.GetFileAttributesA((*C.char)(unsafe.Pointer(lpFileName))))
}

// DWORD GetFullPathNameA(
//   LPCSTR lpFileName,
//   DWORD  nBufferLength,
//   LPSTR  lpBuffer,
//   LPSTR  *lpFilePart
// );
func XGetFullPathNameA(t *TLS, lpFileName uintptr, nBufferLength uint32, lpBuffer, lpFilePart uintptr) uint32 {
	panic(todo(""))
}

// DWORD GetFullPathNameW(
//   LPCWSTR lpFileName,
//   DWORD   nBufferLength,
//   LPWSTR  lpBuffer,
//   LPWSTR  *lpFilePart
// );
func XGetFullPathNameW(t *TLS, lpFileName uintptr, nBufferLength uint32, lpBuffer, lpFilePart uintptr) uint32 {
	return uint32(C.GetFullPathNameW((*C.ushort)(unsafe.Pointer(lpFileName)), C.ulong(nBufferLength), (*C.ushort)(unsafe.Pointer(lpBuffer)), (*C.LPWSTR)(unsafe.Pointer(lpFilePart))))
}

// BOOL LockFile(
//   HANDLE hFile,
//   DWORD  dwFileOffsetLow,
//   DWORD  dwFileOffsetHigh,
//   DWORD  nNumberOfBytesToLockLow,
//   DWORD  nNumberOfBytesToLockHigh
// );
func XLockFile(t *TLS, hFile uintptr, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh uint32) int32 {
	panic(todo(""))
}

// BOOL UnlockFile(
//   HANDLE hFile,
//   DWORD  dwFileOffsetLow,
//   DWORD  dwFileOffsetHigh,
//   DWORD  nNumberOfBytesToUnlockLow,
//   DWORD  nNumberOfBytesToUnlockHigh
// );
func XUnlockFile(t *TLS, hFile uintptr, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh uint32) int32 {
	panic(todo(""))
}

// BOOL ReadFile(
//   HANDLE       hFile,
//   LPVOID       lpBuffer,
//   DWORD        nNumberOfBytesToRead,
//   LPDWORD      lpNumberOfBytesRead,
//   LPOVERLAPPED lpOverlapped
// );
func XReadFile(t *TLS, hFile, lpBuffer uintptr, nNumberOfBytesToRead uint32, lpNumberOfBytesRead, lpOverlapped uintptr) int32 {
	return int32(C.ReadFile(C.HANDLE(hFile), C.LPVOID(lpBuffer), C.ulong(nNumberOfBytesToRead), (*C.ulong)(unsafe.Pointer(lpNumberOfBytesRead)), (*C.struct__OVERLAPPED)(unsafe.Pointer(lpOverlapped))))
}

// BOOL SetEndOfFile(
//   HANDLE hFile
// );
func XSetEndOfFile(t *TLS, hFile uintptr) int32 {
	return int32(C.SetEndOfFile(C.HANDLE(hFile)))
}

// BOOL UnlockFileEx(
//   HANDLE       hFile,
//   DWORD        dwReserved,
//   DWORD        nNumberOfBytesToUnlockLow,
//   DWORD        nNumberOfBytesToUnlockHigh,
//   LPOVERLAPPED lpOverlapped
// );
func XUnlockFileEx(t *TLS, hFile uintptr, dwReserved, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh uint32, lpOverlapped uintptr) int32 {
	return int32(C.UnlockFileEx(C.HANDLE(hFile), C.ulong(dwReserved), C.ulong(nNumberOfBytesToUnlockLow), C.ulong(nNumberOfBytesToUnlockHigh), (*C.struct__OVERLAPPED)(unsafe.Pointer(lpOverlapped))))
}

// BOOL WriteFile(
//   HANDLE       hFile,
//   LPCVOID      lpBuffer,
//   DWORD        nNumberOfBytesToWrite,
//   LPDWORD      lpNumberOfBytesWritten,
//   LPOVERLAPPED lpOverlapped
// );
func XWriteFile(t *TLS, hFile, lpBuffer uintptr, nNumberOfBytesToWrite uint32, lpNumberOfBytesWritten, lpOverlapped uintptr) int32 {
	return int32(C.WriteFile(C.HANDLE(hFile), C.LPCVOID(lpBuffer), C.ulong(nNumberOfBytesToWrite), (*C.ulong)(unsafe.Pointer(lpNumberOfBytesWritten)), (*C.struct__OVERLAPPED)(unsafe.Pointer(lpOverlapped))))
}

// LPVOID HeapAlloc(
//   HANDLE hHeap,
//   DWORD  dwFlags,
//   SIZE_T dwBytes
// );
func XHeapAlloc(t *TLS, hHeap uintptr, dwFlags uint32, dwBytes types.Size_t) uintptr {
	return uintptr(C.HeapAlloc(C.HANDLE(hHeap), C.ulong(dwFlags), C.ulonglong(dwBytes)))
}

// SIZE_T HeapCompact(
//   HANDLE hHeap,
//   DWORD  dwFlags
// );
func XHeapCompact(t *TLS, hHeap uintptr, dwFlags uint32) types.Size_t {
	panic(todo(""))
}

// HANDLE HeapCreate(
//   DWORD  flOptions,
//   SIZE_T dwInitialSize,
//   SIZE_T dwMaximumSize
// );
func XHeapCreate(t *TLS, flOptions uint32, dwInitialSize, dwMaximumSize types.Size_t) uintptr {
	panic(todo(""))
}

// BOOL HeapDestroy(
//   HANDLE hHeap
// );
func XHeapDestroy(t *TLS, hHeap uintptr) int32 {
	panic(todo(""))
}

// BOOL HeapFree(
//   HANDLE                 hHeap,
//   DWORD                  dwFlags,
//   _Frees_ptr_opt_ LPVOID lpMem
// );
func XHeapFree(t *TLS, hHeap uintptr, dwFlags uint32, lpMem uintptr) int32 {
	return int32(C.HeapFree(C.HANDLE(hHeap), C.ulong(dwFlags), C.LPVOID(lpMem)))
}

// LPVOID HeapReAlloc(
//   HANDLE                 hHeap,
//   DWORD                  dwFlags,
//   _Frees_ptr_opt_ LPVOID lpMem,
//   SIZE_T                 dwBytes
// );
func XHeapReAlloc(t *TLS, hHeap uintptr, dwFlags uint32, lpMem uintptr, dwBytes types.Size_t) uintptr {
	panic(todo(""))
}

// SIZE_T HeapSize(
//   HANDLE  hHeap,
//   DWORD   dwFlags,
//   LPCVOID lpMem
// );
func XHeapSize(t *TLS, hHeap uintptr, dwFlags uint32, lpMem uintptr) types.Size_t {
	panic(todo(""))
}

// BOOL HeapValidate(
//   HANDLE  hHeap,
//   DWORD   dwFlags,
//   LPCVOID lpMem
// );
func XHeapValidate(t *TLS, hHeap uintptr, dwFlags uint32, lpMem uintptr) int32 {
	panic(todo(""))
}

// HANDLE GetProcessHeap();
func XGetProcessHeap(t *TLS) uintptr {
	return uintptr(C.GetProcessHeap())
}

// BOOL FlushViewOfFile(
//   LPCVOID lpBaseAddress,
//   SIZE_T  dwNumberOfBytesToFlush
// );
func XFlushViewOfFile(t *TLS, lpBaseAddress uintptr, dwNumberOfBytesToFlush types.Size_t) int32 {
	panic(todo(""))
}

// BOOL UnmapViewOfFile(
//   LPCVOID lpBaseAddress
// );
func XUnmapViewOfFile(t *TLS, lpBaseAddress uintptr) int32 {
	return int32(C.UnmapViewOfFile(C.LPCVOID(lpBaseAddress)))
}

// HANDLE CreateFileMappingW(
//   HANDLE                hFile,
//   LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
//   DWORD                 flProtect,
//   DWORD                 dwMaximumSizeHigh,
//   DWORD                 dwMaximumSizeLow,
//   LPCWSTR               lpName
// );
func XCreateFileMappingW(t *TLS, hFile, lpFileMappingAttributes uintptr, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow uint32, lpName uintptr) uintptr {
	return uintptr(C.CreateFileMappingW(C.HANDLE(hFile), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpFileMappingAttributes)), C.ulong(flProtect), C.ulong(dwMaximumSizeHigh), C.ulong(dwMaximumSizeLow), (*C.ushort)(unsafe.Pointer(lpName))))
}

// LPVOID MapViewOfFile(
//   HANDLE hFileMappingObject,
//   DWORD  dwDesiredAccess,
//   DWORD  dwFileOffsetHigh,
//   DWORD  dwFileOffsetLow,
//   SIZE_T dwNumberOfBytesToMap
// );
func XMapViewOfFile(t *TLS, hFileMappingObject uintptr, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow uint32, dwNumberOfBytesToMap types.Size_t) uintptr {
	return uintptr(C.MapViewOfFile(C.HANDLE(hFileMappingObject), C.ulong(dwDesiredAccess), C.ulong(dwFileOffsetHigh), C.ulong(dwFileOffsetLow), C.ulonglong(dwNumberOfBytesToMap)))
}

// DWORD GetCurrentProcessId();
func XGetCurrentProcessId(t *TLS) uint32 {
	return uint32(C.GetCurrentProcessId())
}

// BOOL QueryPerformanceCounter(
//   LARGE_INTEGER *lpPerformanceCount
// );
func XQueryPerformanceCounter(t *TLS, lpPerformanceCount uintptr) int32 {
	return int32(C.QueryPerformanceCounter((*C.LARGE_INTEGER)(unsafe.Pointer(lpPerformanceCount))))
}

// int MultiByteToWideChar(
//   UINT                              CodePage,
//   DWORD                             dwFlags,
//   _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
//   int                               cbMultiByte,
//   LPWSTR                            lpWideCharStr,
//   int                               cchWideChar
// );
func XMultiByteToWideChar(t *TLS, CodePage uint32, dwFlags uint32, lpMultiByteStr uintptr, cbMultiByte int32, lpWideCharStr uintptr, cchWideChar int32) int32 {
	return int32(C.MultiByteToWideChar(C.uint(CodePage), C.ulong(dwFlags), (*C.char)(unsafe.Pointer(lpMultiByteStr)), C.int(cbMultiByte), (*C.ushort)(unsafe.Pointer(lpWideCharStr)), C.int(cchWideChar)))
}

// int WideCharToMultiByte(
//   UINT                               CodePage,
//   DWORD                              dwFlags,
//   _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
//   int                                cchWideChar,
//   LPSTR                              lpMultiByteStr,
//   int                                cbMultiByte,
//   LPCCH                              lpDefaultChar,
//   LPBOOL                             lpUsedDefaultChar
// );
func XWideCharToMultiByte(t *TLS, CodePage uint32, dwFlags uint32, lpWideCharStr uintptr, cchWideChar int32, lpMultiByteStr uintptr, cbMultiByte int32, lpDefaultChar, lpUsedDefaultChar uintptr) int32 {
	return int32(C.WideCharToMultiByte(C.uint(CodePage), C.ulong(dwFlags), (*C.ushort)(unsafe.Pointer(lpWideCharStr)), C.int(cchWideChar), (*C.char)(unsafe.Pointer(lpMultiByteStr)), C.int(cbMultiByte), (*C.char)(unsafe.Pointer(lpDefaultChar)), (*C.int)(unsafe.Pointer(lpUsedDefaultChar))))
}

// DWORD WaitForSingleObjectEx(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds,
//   BOOL   bAlertable
// );
func XWaitForSingleObjectEx(t *TLS, hHandle uintptr, dwMilliseconds uint32, bAlertable int32) uint32 {
	return uint32(C.WaitForSingleObjectEx(C.HANDLE(hHandle), C.ulong(dwMilliseconds), C.int(bAlertable)))
}

// HANDLE CreateMutexW(
//   LPSECURITY_ATTRIBUTES lpMutexAttributes,
//   BOOL                  bInitialOwner,
//   LPCWSTR               lpName
// );
func XCreateMutexW(t *TLS, lpMutexAttributes uintptr, bInitialOwner int32, lpName uintptr) uintptr {
	panic(todo(""))
}

// void Sleep(
//   DWORD dwMilliseconds
// );
func XSleep(t *TLS, dwMilliseconds uint32) {
	C.Sleep(C.ulong(dwMilliseconds))
}

// int _fileno(FILE *stream);
func X_fileno(t *TLS, stream uintptr) int32 {
	return int32(C._fileno((*C.FILE)(unsafe.Pointer(stream))))
}

// void OutputDebugStringA(
//   LPCSTR lpOutputString
// )
func XOutputDebugStringA(t *TLS, lpOutputString uintptr) {
	panic(todo(""))
}

// DWORD GetLastError();
func XGetLastError(t *TLS) uint32 {
	return uint32(C.__ccgo_getLastError())
}

// BOOL DeleteFileA(
//   LPCSTR lpFileName
// );
func XDeleteFileA(t *TLS, lpFileName uintptr) int32 {
	panic(todo(""))
}

// BOOL DeleteFileW(
//   LPCWSTR lpFileName
// );
func XDeleteFileW(t *TLS, lpFileName uintptr) int32 {
	return int32(C.DeleteFileW((*C.ushort)(unsafe.Pointer(lpFileName))))
}

// BOOL FlushFileBuffers(
//   HANDLE hFile
// );
func XFlushFileBuffers(t *TLS, hFile uintptr) int32 {
	return int32(C.FlushFileBuffers(C.HANDLE(hFile)))
}

// BOOL GetFileAttributesExW(
//   LPCWSTR                lpFileName,
//   GET_FILEEX_INFO_LEVELS fInfoLevelId,
//   LPVOID                 lpFileInformation
// );
func XGetFileAttributesExW(t *TLS, lpFileName uintptr, fInfoLevelId uint32, lpFileInformation uintptr) int32 {
	return int32(C.GetFileAttributesExW((*C.ushort)(unsafe.Pointer(lpFileName)), C.GET_FILEEX_INFO_LEVELS(fInfoLevelId), C.LPVOID(unsafe.Pointer(lpFileInformation))))
}

// DWORD GetTempPathW(
//   DWORD  nBufferLength,
//   LPWSTR lpBuffer
// );
func XGetTempPathW(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	return uint32(C.GetTempPathW(C.ulong(nBufferLength), (*C.ushort)(unsafe.Pointer(lpBuffer))))
}

// BOOL LockFileEx(
//   HANDLE       hFile,
//   DWORD        dwFlags,
//   DWORD        dwReserved,
//   DWORD        nNumberOfBytesToLockLow,
//   DWORD        nNumberOfBytesToLockHigh,
//   LPOVERLAPPED lpOverlapped
// );
func XLockFileEx(t *TLS, hFile uintptr, dwFlags, dwReserved, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh uint32, lpOverlapped uintptr) int32 {
	return int32(C.LockFileEx(C.HANDLE(hFile), C.ulong(dwFlags), C.ulong(dwReserved), C.ulong(nNumberOfBytesToLockLow), C.ulong(nNumberOfBytesToLockHigh), (*C.struct__OVERLAPPED)(unsafe.Pointer(lpOverlapped))))
}

// DWORD WaitForSingleObject(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds
// );
func XWaitForSingleObject(t *TLS, hHandle uintptr, dwMilliseconds uint32) uint32 {
	return uint32(C.WaitForSingleObject(C.HANDLE(hHandle), C.ulong(dwMilliseconds)))
}

// void OutputDebugStringW(
//   LPCWSTR lpOutputString
// );
func XOutputDebugStringW(t *TLS, lpOutputString uintptr) {
	panic(todo(""))
}

// int fflush(FILE *stream);
func Xfflush(t *TLS, stream uintptr) int32 {
	return int32(C.fflush((*C.FILE)(unsafe.Pointer(stream))))
}

func Xvfprintf(t *TLS, stream, format, ap uintptr) int32 {
	return int32(sysv(t, fprintf, stream, format, ap))
}

// void rewind(FILE *stream);
func Xrewind(t *TLS, stream uintptr) {
	C.rewind((*C.struct__iobuf)(unsafe.Pointer(stream)))
}

// void *memmove(void *dest, const void *src, size_t n);
func Xmemmove(t *TLS, dest, src uintptr, n types.Size_t) uintptr {
	return uintptr(C.memmove(unsafe.Pointer(dest), unsafe.Pointer(src), C.size_t(n)))
}

// char *getenv(const char *name);
func Xgetenv(t *TLS, name uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.getenv((*C.char)(unsafe.Pointer(name)))))
}

// char *strstr(const char *haystack, const char *needle);
func Xstrstr(t *TLS, haystack, needle uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.strstr((*C.char)(unsafe.Pointer(haystack)), (*C.char)(unsafe.Pointer(needle)))))
}

// int fputc(int c, FILE *stream);
func Xfputc(t *TLS, c int32, stream uintptr) int32 {
	panic(todo(""))
}

// int fgetc(FILE *stream);
func Xfgetc(t *TLS, stream uintptr) int32 {
	panic(todo(""))
}

// int tolower(int c);
func Xtolower(t *TLS, c int32) int32 {
	return int32(C.tolower(C.int(c)))
}

// size_t strcspn(const char *s, const char *reject);
func Xstrcspn(t *TLS, s, reject uintptr) (r types.Size_t) {
	return types.Size_t(C.strcspn((*C.char)(unsafe.Pointer(s)), (*C.char)(unsafe.Pointer(reject))))
}

// void abort(void);
func Xabort(t *TLS) {
	C.abort()
}

// int snprintf(char *str, size_t size, const char *format, ...);
func Xsnprintf(t *TLS, str uintptr, size types.Size_t, format, args uintptr) (r int32) {
	panic(todo(""))
}

// time_t mktime(struct tm *tm);
func Xmktime(t *TLS, ptm uintptr) types.Time_t {
	return types.Time_t(C.mktime((*C.struct_tm)(unsafe.Pointer(ptm))))
}

// void tzset (void);
func Xtzset(t *TLS) {
	C.tzset()
}

// BOOL SetEvent(
//   HANDLE hEvent
// );
func XSetEvent(t *TLS, hEvent uintptr) int32 {
	return int32(C.SetEvent(C.HANDLE(hEvent)))
}

// char *strpbrk(const char *s, const char *accept);
func Xstrpbrk(t *TLS, s, accept uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.strpbrk((*C.char)(unsafe.Pointer(s)), (*C.char)(unsafe.Pointer(accept)))))
}

// int _stricmp(
//    const char *string1,
//    const char *string2
// );
func X_stricmp(t *TLS, string1, string2 uintptr) int32 {
	return int32(C._stricmp((*C.char)(unsafe.Pointer(string1)), (*C.char)(unsafe.Pointer(string2))))
}

// int putenv(
//    const char *envstring
// );
func Xputenv(t *TLS, envstring uintptr) int32 {
	return int32(C.putenv((*C.char)(unsafe.Pointer(envstring))))
}

// void *memchr(const void *s, int c, size_t n);
func Xmemchr(t *TLS, s uintptr, c int32, n types.Size_t) uintptr {
	return uintptr(C.memchr(unsafe.Pointer(s), C.int(c), C.size_t(n)))
}

// WCHAR * gai_strerrorW(
//   int ecode
// );
func Xgai_strerrorW(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

// servent * getservbyname(
//   const char *name,
//   const char *proto
// );
func Xgetservbyname(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func Xntohs(t *TLS, netshort uint16) uint16 {
	panic(todo(""))
}

// uint16_t htons(uint16_t hostshort);
func Xhtons(t *TLS, hostshort uint16) uint16 {
	panic(todo(""))
}

func Xgetsockopt(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xsetsockopt(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// INT WSAAPI getaddrinfo(
//   PCSTR           pNodeName,
//   PCSTR           pServiceName,
//   const ADDRINFOA *pHints,
//   PADDRINFOA      *ppResult
// );
func XWspiapiGetAddrInfo(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// int wcscmp(
//    const wchar_t *string1,
//    const wchar_t *string2
// );
func Xwcscmp(t *TLS, string1, string2 uintptr) int32 {
	return int32(C.wcscmp((*C.ushort)(unsafe.Pointer(string1)), (*C.ushort)(unsafe.Pointer(string2))))
}

// int isatty(int fd);
func Xisatty(t *TLS, fd int32) int32 {
	return int32(C.isatty(C.int(fd)))
}

// BOOL IsDebuggerPresent();
func XIsDebuggerPresent(t *TLS) int32 {
	return int32(C.IsDebuggerPresent())
}

func XExitProcess(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// char *strerror(int errnum);
func Xstrerror(t *TLS, errnum int32) uintptr {
	return uintptr(unsafe.Pointer(C.strerror(C.int(errnum))))
}

// BOOL GetVolumeNameForVolumeMountPointW(
//   LPCWSTR lpszVolumeMountPoint,
//   LPWSTR  lpszVolumeName,
//   DWORD   cchBufferLength
// );
func XGetVolumeNameForVolumeMountPointW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// size_t wcslen(
//    const wchar_t *str
// );
func Xwcslen(t *TLS, str uintptr) types.Size_t {
	return types.Size_t(C.wcslen((*C.ushort)(unsafe.Pointer(str))))
}

// BOOL DuplicateHandle(
//   HANDLE   hSourceProcessHandle,
//   HANDLE   hSourceHandle,
//   HANDLE   hTargetProcessHandle,
//   LPHANDLE lpTargetHandle,
//   DWORD    dwDesiredAccess,
//   BOOL     bInheritHandle,
//   DWORD    dwOptions
// );
func XDuplicateHandle(t *TLS, hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle uintptr, dwDesiredAccess uint32, bInheritHandle int32, dwOptions uint32) int32 {
	return int32(C.DuplicateHandle(C.HANDLE(hSourceProcessHandle), C.HANDLE(hSourceHandle), C.HANDLE(hTargetProcessHandle), (*C.HANDLE)(unsafe.Pointer(lpTargetHandle)), C.ulong(dwDesiredAccess), C.int(bInheritHandle), C.ulong(dwOptions)))
}

// DWORD GetFileType(
//   HANDLE hFile
// );
func XGetFileType(t *TLS, hFile uintptr) uint32 {
	return uint32(C.GetFileType(C.HANDLE(hFile)))
}

// BOOL WINAPI GetConsoleMode(
//   _In_  HANDLE  hConsoleHandle,
//   _Out_ LPDWORD lpMode
// );
func XGetConsoleMode(t *TLS, hConsoleHandle, lpMode uintptr) int32 {
	return int32(C.GetConsoleMode(C.HANDLE(hConsoleHandle), (*C.ulong)(unsafe.Pointer((lpMode)))))
}

// BOOL GetCommState(
//   HANDLE hFile,
//   LPDCB  lpDCB
// );
func XGetCommState(t *TLS, hFile, lpDCB uintptr) int32 {
	return int32(C.GetCommState(C.HANDLE(hFile), (*C.struct__DCB)(unsafe.Pointer(lpDCB))))
}

// int _wcsnicmp(
//    const wchar_t *string1,
//    const wchar_t *string2,
//    size_t count
// );
func X_wcsnicmp(t *TLS, string1, string2 uintptr, count types.Size_t) int32 {
	return int32(C._wcsnicmp((*C.ushort)(unsafe.Pointer(string1)), (*C.ushort)(unsafe.Pointer(string2)), C.size_t(count)))
}

// BOOL AccessCheck(
//   PSECURITY_DESCRIPTOR pSecurityDescriptor,
//   HANDLE               ClientToken,
//   DWORD                DesiredAccess,
//   PGENERIC_MAPPING     GenericMapping,
//   PPRIVILEGE_SET       PrivilegeSet,
//   LPDWORD              PrivilegeSetLength,
//   LPDWORD              GrantedAccess,
//   LPBOOL               AccessStatus
// );
func XAccessCheck(t *TLS, pSecurityDescriptor, ClientToken uintptr, DesiredAccess uint32, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus uintptr) int32 {
	return int32(C.AccessCheck(C.PVOID(pSecurityDescriptor), C.HANDLE(ClientToken), C.ulong(DesiredAccess), (*C.struct__GENERIC_MAPPING)(unsafe.Pointer(GenericMapping)), (*C.struct__PRIVILEGE_SET)(unsafe.Pointer(PrivilegeSet)), (*C.ulong)(unsafe.Pointer(PrivilegeSetLength)), (*C.ulong)(unsafe.Pointer(GrantedAccess)), (*C.int)(unsafe.Pointer(AccessStatus))))
}

func XBuildCommDCBW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// LPWSTR CharLowerW(
//   LPWSTR lpsz
// );
func XCharLowerW(t *TLS, lpsz uintptr) uintptr {
	return uintptr(unsafe.Pointer((C.CharLowerW((*C.ushort)(unsafe.Pointer(lpsz))))))
}

func XClearCommError(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// NTSYSAPI NTSTATUS RtlGetVersion( // ntdll.dll
//   PRTL_OSVERSIONINFOW lpVersionInformation
// );
func XRtlGetVersion(t *TLS, lpVersionInformation uintptr) uintptr {
	r := sys(t, rtlGetVersion, lpVersionInformation)
	return r
}

// BOOL WINAPI CancelSynchronousIo(
//   _In_ HANDLE hThread
// );
func XCancelSynchronousIo(t *TLS, hThread uintptr) int32 {
	return int32(sys(t, cancelSynchronousIo, hThread))
}

// __atomic_load_n
func X__atomic_load_n(t *TLS) {
	panic(todo(""))
}

// __atomic_store_n
func X__atomic_store_n(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// __builtin_add_overflow
func X__builtin_add_overflow(t *TLS) {
	panic(todo(""))
}

// __builtin_mul_overflow
func X__builtin_mul_overflow(t *TLS) {
	panic(todo(""))
}

// __builtin_sub_overflow
func X__builtin_sub_overflow(t *TLS) {
	panic(todo(""))
}

// char *setlocale(int category, const char *locale);
func Xsetlocale(t *TLS, category int32, locale uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.setlocale(C.int(category), (*C.char)(unsafe.Pointer(locale)))))
}

func goWideString(p uintptr) string {
	if p == 0 {
		return ""
	}

	var a []uint16
	for {
		c := *(*uint16)(unsafe.Pointer(p))
		if c == 0 {
			return string(utf16.Decode(a))
		}

		a = append(a, c)
		p += unsafe.Sizeof(uint16(0))
	}
}

// BOOL CopyFileW(
//   LPCWSTR lpExistingFileName,
//   LPCWSTR lpNewFileName,
//   BOOL    bFailIfExists
// );
func XCopyFileW(t *TLS, lpExistingFileName, lpNewFileName uintptr, bFailIfExists int32) int32 {
	return int32(C.CopyFileW((*C.ushort)(unsafe.Pointer(lpExistingFileName)), (*C.ushort)(unsafe.Pointer(lpNewFileName)), C.int(bFailIfExists)))
}

// BOOL CreateDirectoryW(
//   LPCWSTR                lpPathName,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes
// );
func XCreateDirectoryW(t *TLS, lpPathName, lpSecurityAttributes uintptr) int32 {
	return int32(C.CreateDirectoryW((*C.ushort)(unsafe.Pointer(lpPathName)), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpSecurityAttributes))))
}

// HANDLE CreateEventA(
//   LPSECURITY_ATTRIBUTES lpEventAttributes,
//   BOOL                  bManualReset,
//   BOOL                  bInitialState,
//   LPCSTR                lpName
// );
func XCreateEventA(t *TLS, lpEventAttributes uintptr, bManualReset, bInitialState int32, lpName uintptr) uintptr {
	panic(todo(""))
}

// HANDLE CreateEventW(
//   LPSECURITY_ATTRIBUTES lpEventAttributes,
//   BOOL                  bManualReset,
//   BOOL                  bInitialState,
//   LPCWSTR               lpName
// );
func XCreateEventW(t *TLS, lpEventAttributes uintptr, bManualReset, bInitialState int32, lpName uintptr) uintptr {
	return uintptr(C.CreateEventW((*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpEventAttributes)), C.int(bManualReset), C.int(bInitialState), (*C.ushort)(unsafe.Pointer(lpName))))
}

// BOOL CreateHardLinkW(
//   LPCWSTR               lpFileName,
//   LPCWSTR               lpExistingFileName,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes
// );
func XCreateHardLinkW(t *TLS, lpFileName, lpExistingFileName, lpSecurityAttributes uintptr) int32 {
	return int32(C.CreateHardLinkW((*C.ushort)(unsafe.Pointer(lpFileName)), (*C.ushort)(unsafe.Pointer(lpExistingFileName)), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpSecurityAttributes))))
}

// BOOL CreatePipe(
//   PHANDLE               hReadPipe,
//   PHANDLE               hWritePipe,
//   LPSECURITY_ATTRIBUTES lpPipeAttributes,
//   DWORD                 nSize
// );
func XCreatePipe(t *TLS, hReadPipe, hWritePipe, lpPipeAttributes uintptr, nSize uint32) int32 {
	return int32(C.CreatePipe((*C.HANDLE)(unsafe.Pointer(hReadPipe)), (*C.HANDLE)(unsafe.Pointer(hWritePipe)), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpPipeAttributes)), C.ulong(nSize)))
}

type createThreadObj struct {
	threadProc func(tls *TLS, arg uintptr) uint32
	param      uintptr
}

//export __ccgo_thread_proc_cb
func __ccgo_thread_proc_cb(p C.ulonglong) C.ulong {
	runtime.LockOSThread()
	t := NewTLS()
	t.locked = true

	defer t.Close()

	o := getObject(uintptr(p)).(*createThreadObj)
	return C.ulong(o.threadProc(t, o.param))
}

// HANDLE CreateThread(
//   LPSECURITY_ATTRIBUTES   lpThreadAttributes,
//   SIZE_T                  dwStackSize,
//   LPTHREAD_START_ROUTINE  lpStartAddress,
//   __drv_aliasesMem LPVOID lpParameter,
//   DWORD                   dwCreationFlags,
//   LPDWORD                 lpThreadId
// );
func XCreateThread(t *TLS, lpThreadAttributes uintptr, dwStackSize types.Size_t, lpStartAddress, lpParameter uintptr, dwCreationFlags uint32, lpThreadId uintptr) (r uintptr) {
	o := addObject(&createThreadObj{
		*(*func(*TLS, uintptr) uint32)(unsafe.Pointer(&lpStartAddress)),
		lpParameter,
	})
	return uintptr(C.__ccgo_CreateThread((*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpThreadAttributes)), C.ulonglong(dwStackSize), C.ulonglong(o), C.ulong(dwCreationFlags), (*C.ulong)(unsafe.Pointer(lpThreadId))))
}

// HWND CreateWindowExW(
//   DWORD     dwExStyle,
//   LPCWSTR   lpClassName,
//   LPCWSTR   lpWindowName,
//   DWORD     dwStyle,
//   int       X,
//   int       Y,
//   int       nWidth,
//   int       nHeight,
//   HWND      hWndParent,
//   HMENU     hMenu,
//   HINSTANCE hInstance,
//   LPVOID    lpParam
// );
func XCreateWindowExW(t *TLS, dwExStyle uint32, lpClassName, lpWindowName uintptr, dwStyle uint32, x, y, nWidth, nHeight int32, hWndParent, hMenu, hInstance, lpParam uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.CreateWindowExW(C.ulong(dwExStyle), (*C.ushort)(unsafe.Pointer(lpClassName)), (*C.ushort)(unsafe.Pointer(lpWindowName)), C.ulong(dwStyle), C.int(x), C.int(y), C.int(nWidth), C.int(nHeight), (*C.struct_HWND__)(unsafe.Pointer(hWndParent)), (*C.struct_HMENU__)(unsafe.Pointer(hMenu)), (*C.struct_HINSTANCE__)(unsafe.Pointer(hInstance)), C.LPVOID(lpParam))))
}

func XDdeAbandonTransaction(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeAccessData(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeClientTransaction(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeConnect(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeCreateDataHandle(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeCreateStringHandleW(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeDisconnect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeFreeDataHandle(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeFreeStringHandle(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeGetData(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeGetLastError(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

func XDdeInitializeW(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

func XDdeNameService(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeQueryStringW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeUnaccessData(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeUninitialize(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// LRESULT LRESULT DefWindowProcW(
//   HWND   hWnd,
//   UINT   Msg,
//   WPARAM wParam,
//   LPARAM lParam
// );
func XDefWindowProcW(t *TLS, _ ...interface{}) int64 {
	panic(todo(""))
}

// void DeleteCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XDeleteCriticalSection(t *TLS, lpCriticalSection uintptr) {
	C.DeleteCriticalSection((*C.struct__RTL_CRITICAL_SECTION)(unsafe.Pointer(lpCriticalSection)))
}

func XDestroyWindow(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL DeviceIoControl(
//   HANDLE       hDevice,
//   DWORD        dwIoControlCode,
//   LPVOID       lpInBuffer,
//   DWORD        nInBufferSize,
//   LPVOID       lpOutBuffer,
//   DWORD        nOutBufferSize,
//   LPDWORD      lpBytesReturned,
//   LPOVERLAPPED lpOverlapped
// );
func XDeviceIoControl(t *TLS, hDevice uintptr, dwIoControlCode uint32, lpInBuffer uintptr, nInBufferSize uint32, lpOutBuffer uintptr, nOutBufferSize uint32, lpBytesReturned, lpOverlapped uintptr) int32 {
	return int32(C.DeviceIoControl(C.HANDLE(hDevice), C.ulong(dwIoControlCode), C.LPVOID(lpInBuffer), C.ulong(nInBufferSize), C.LPVOID(lpOutBuffer), C.ulong(nOutBufferSize), (*C.ulong)(unsafe.Pointer(lpBytesReturned)), (*C.struct__OVERLAPPED)(unsafe.Pointer(lpOverlapped))))
}

func XDispatchMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// void EnterCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XEnterCriticalSection(t *TLS, lpCriticalSection uintptr) {
	C.EnterCriticalSection((*C.struct__RTL_CRITICAL_SECTION)(unsafe.Pointer(lpCriticalSection)))
}

func XEnumWindows(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL EqualSid(
//   PSID pSid1,
//   PSID pSid2
// );
func XEqualSid(t *TLS, pSid1, pSid2 uintptr) int32 {
	return int32(C.EqualSid(C.PVOID(pSid1), C.PVOID(pSid2)))
}

func XEscapeCommFunction(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// HANDLE FindFirstFileExW(
//   LPCWSTR            lpFileName,
//   FINDEX_INFO_LEVELS fInfoLevelId,
//   LPVOID             lpFindFileData,
//   FINDEX_SEARCH_OPS  fSearchOp,
//   LPVOID             lpSearchFilter,
//   DWORD              dwAdditionalFlags
// );
func XFindFirstFileExW(t *TLS, lpFileName uintptr, fInfoLevelId int32, lpFindFileData uintptr, fSearchOp int32, lpSearchFilter uintptr, dwAdditionalFlags uint32) uintptr {
	return uintptr(C.FindFirstFileExW((*C.ushort)(unsafe.Pointer(lpFileName)), C.FINDEX_INFO_LEVELS(fInfoLevelId), C.LPVOID(lpFindFileData), C.FINDEX_SEARCH_OPS(fSearchOp), C.LPVOID(lpSearchFilter), C.ulong(dwAdditionalFlags)))
}

// BOOL FindNextFileW(
//   HANDLE             hFindFile,
//   LPWIN32_FIND_DATAW lpFindFileData
// );
func XFindNextFileW(t *TLS, hFindFile, lpFindFileData uintptr) int32 {
	return int32(C.FindNextFileW(C.HANDLE(hFindFile), (*C.struct__WIN32_FIND_DATAW)(unsafe.Pointer(lpFindFileData))))
}

func XGetCommModemStatus(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL GetComputerNameW(
//   LPWSTR  lpBuffer,
//   LPDWORD nSize
// );
func XGetComputerNameW(t *TLS, lpBuffer, nSize uintptr) int32 {
	return int32(C.GetComputerNameW((*C.ushort)(unsafe.Pointer(lpBuffer)), (*C.ulong)(unsafe.Pointer(nSize))))
}

// DWORD GetCurrentDirectory(
//   DWORD  nBufferLength,
//   LPWTSTR lpBuffer
// );
func XGetCurrentDirectoryW(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	return uint32(C.GetCurrentDirectoryW(C.ulong(nBufferLength), (*C.ushort)(unsafe.Pointer(lpBuffer))))
}

// DWORD GetCurrentThreadId();
func XGetCurrentThreadId(t *TLS) uint32 {
	return uint32(C.GetCurrentThreadId())
}

// DWORD GetEnvironmentVariableA(
//   LPCSTR lpName,
//   LPSTR  lpBuffer,
//   DWORD  nSize
// );
func XGetEnvironmentVariableA(t *TLS, lpName, lpBuffer uintptr, nSize uint32) uint32 {
	panic(todo(""))
}

// DWORD GetEnvironmentVariableW(
//   LPCWSTR lpName,
//   LPWSTR  lpBuffer,
//   DWORD   nSize
// );
func XGetEnvironmentVariableW(t *TLS, lpName, lpBuffer uintptr, nSize uint32) uint32 {
	return uint32(C.GetEnvironmentVariableW((*C.ushort)(unsafe.Pointer(lpName)), (*C.ushort)(unsafe.Pointer(lpBuffer)), C.ulong(nSize)))
}

// BOOL GetExitCodeProcess(
//   HANDLE  hProcess,
//   LPDWORD lpExitCode
// );
func XGetExitCodeProcess(t *TLS, hProcess, lpExitCode uintptr) int32 {
	return int32(C.GetExitCodeProcess(C.HANDLE(hProcess), (*C.ulong)(unsafe.Pointer(lpExitCode))))
}

// BOOL GetExitCodeThread(
//   HANDLE  hThread,
//   LPDWORD lpExitCode
// );
func XGetExitCodeThread(t *TLS, hThread, lpExitCode uintptr) int32 {
	return int32(C.GetExitCodeThread(C.HANDLE(hThread), (*C.ulong)(unsafe.Pointer(lpExitCode))))
}

// BOOL GetFileInformationByHandle(
//   HANDLE                       hFile,
//   LPBY_HANDLE_FILE_INFORMATION lpFileInformation
// );
func XGetFileInformationByHandle(t *TLS, hFile, lpFileInformation uintptr) int32 {
	return int32(C.GetFileInformationByHandle(C.HANDLE(hFile), (*C.struct__BY_HANDLE_FILE_INFORMATION)(unsafe.Pointer(lpFileInformation))))
}

// DWORD GetLogicalDriveStringsA(
//   DWORD nBufferLength,
//   LPSTR lpBuffer
// );
func XGetLogicalDriveStringsA(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	return uint32(C.GetLogicalDriveStringsA(C.ulong(nBufferLength), (*C.char)(unsafe.Pointer(lpBuffer))))
}

func XGetMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGetModuleFileNameA(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD GetModuleFileNameW(
//   HMODULE hModule,
//   LPWSTR  lpFileName,
//   DWORD   nSize
// );
func XGetModuleFileNameW(t *TLS, hModule, lpFileName uintptr, nSize uint32) uint32 {
	return uint32(C.GetModuleFileNameW((*C.struct_HINSTANCE__)(unsafe.Pointer(hModule)), (*C.ushort)(unsafe.Pointer(lpFileName)), C.ulong(nSize)))
}

func goWideBytes(p uintptr, n int) []uint16 {
	b := GoBytes(p, 2*n)
	var w []uint16
	for i := 0; i < len(b); i += 2 {
		w = append(w, *(*uint16)(unsafe.Pointer(&b[i])))
	}
	return w
}

func goWideStringN(p uintptr, n int) string {
	return string(utf16.Decode(goWideBytes(p, n)))
}

// HMODULE GetModuleHandleW(
//   LPCWSTR lpModuleName
// );
func XGetModuleHandleW(t *TLS, lpModuleName uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.GetModuleHandleW((*C.ushort)(unsafe.Pointer(lpModuleName)))))
}

// DWORD GetNamedSecurityInfoW(
//   LPCWSTR              pObjectName,
//   SE_OBJECT_TYPE       ObjectType,
//   SECURITY_INFORMATION SecurityInfo,
//   PSID                 *ppsidOwner,
//   PSID                 *ppsidGroup,
//   PACL                 *ppDacl,
//   PACL                 *ppSacl,
//   PSECURITY_DESCRIPTOR *ppSecurityDescriptor
// );
func XGetNamedSecurityInfoW(t *TLS, pObjectName uintptr, ObjectType, SecurityInfo uint32, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor uintptr) uint32 {
	return uint32(C.GetNamedSecurityInfoW((*C.ushort)(unsafe.Pointer(pObjectName)), C.SE_OBJECT_TYPE(ObjectType), C.ulong(SecurityInfo), (*C.PVOID)(unsafe.Pointer(ppsidOwner)), (*C.PVOID)(unsafe.Pointer(ppsidGroup)), (*C.PACL)(unsafe.Pointer(ppDacl)), (*C.PACL)(unsafe.Pointer(ppSacl)), (*C.PVOID)(unsafe.Pointer(ppSecurityDescriptor))))
}

func XGetOverlappedResult(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD GetPrivateProfileStringA(
//   LPCSTR lpAppName,
//   LPCSTR lpKeyName,
//   LPCSTR lpDefault,
//   LPSTR  lpReturnedString,
//   DWORD  nSize,
//   LPCSTR lpFileName
// );
func XGetPrivateProfileStringA(t *TLS, lpAppName, lpKeyName, lpDefault, lpReturnedString uintptr, nSize uint32, lpFileName uintptr) uint32 {
	return uint32(C.GetPrivateProfileStringA((*C.char)(unsafe.Pointer(lpAppName)), (*C.char)(unsafe.Pointer(lpKeyName)), (*C.char)(unsafe.Pointer(lpDefault)), (*C.char)(unsafe.Pointer(lpReturnedString)), C.ulong(nSize), (*C.char)(unsafe.Pointer(lpFileName))))
}

func XGetProfilesDirectoryW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL GetSecurityDescriptorOwner(
//   PSECURITY_DESCRIPTOR pSecurityDescriptor,
//   PSID                 *pOwner,
//   LPBOOL               lpbOwnerDefaulted
// );
func XGetSecurityDescriptorOwner(t *TLS, pSecurityDescriptor, pOwner, lpbOwnerDefaulted uintptr) int32 {
	return int32(C.GetSecurityDescriptorOwner(C.PVOID(pSecurityDescriptor), (*C.PVOID)(unsafe.Pointer(pOwner)), (*C.int)(unsafe.Pointer(lpbOwnerDefaulted))))
}

func XGetShortPathNameW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// PSID_IDENTIFIER_AUTHORITY GetSidIdentifierAuthority(
//   PSID pSid
// );
func XGetSidIdentifierAuthority(t *TLS, pSid uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.GetSidIdentifierAuthority(C.PVOID(pSid))))
}

// UINT GetTempFileNameW(
//   LPCWSTR lpPathName,
//   LPCWSTR lpPrefixString,
//   UINT    uUnique,
//   LPWSTR  lpTempFileName
// );
func XGetTempFileNameW(t *TLS, lpPathName, lpPrefixString uintptr, uUnique uint32, lpTempFileName uintptr) uint32 {
	return uint32(C.GetTempFileNameW((*C.ushort)(unsafe.Pointer(lpPathName)), (*C.ushort)(unsafe.Pointer(lpPrefixString)), C.uint(uUnique), (*C.ushort)(unsafe.Pointer(lpTempFileName))))
}

// BOOL GetTokenInformation(
//   HANDLE                  TokenHandle,
//   TOKEN_INFORMATION_CLASS TokenInformationClass,
//   LPVOID                  TokenInformation,
//   DWORD                   TokenInformationLength,
//   PDWORD                  ReturnLength
// );
func XGetTokenInformation(t *TLS, TokenHandle uintptr, TokenInformationClass uint32, TokenInformation uintptr, TokenInformationLength uint32, ReturnLength uintptr) int32 {
	return int32(C.GetTokenInformation(C.HANDLE(TokenHandle), C.TOKEN_INFORMATION_CLASS(TokenInformationClass), C.LPVOID(TokenInformation), C.ulong(TokenInformationLength), (*C.ulong)(unsafe.Pointer(ReturnLength))))
}

// BOOL GetUserNameW(
//   LPWSTR  lpBuffer,
//   LPDWORD pcbBuffer
// );
func XGetUserNameW(t *TLS, lpBuffer, pcbBuffer uintptr) int32 {
	return int32(C.GetUserNameW((*C.ushort)(unsafe.Pointer(lpBuffer)), (*C.ulong)(unsafe.Pointer(pcbBuffer))))
}

// BOOL GetVolumeInformationA(
//   LPCSTR  lpRootPathName,
//   LPSTR   lpVolumeNameBuffer,
//   DWORD   nVolumeNameSize,
//   LPDWORD lpVolumeSerialNumber,
//   LPDWORD lpMaximumComponentLength,
//   LPDWORD lpFileSystemFlags,
//   LPSTR   lpFileSystemNameBuffer,
//   DWORD   nFileSystemNameSize
// );
func XGetVolumeInformationA(t *TLS, lpRootPathName, lpVolumeNameBuffer uintptr, nVolumeNameSize uint32, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer uintptr, nFileSystemNameSize uint32) int32 {
	return int32(C.GetVolumeInformationA((*C.char)(unsafe.Pointer(lpRootPathName)), (*C.char)(unsafe.Pointer(lpVolumeNameBuffer)), C.ulong(nVolumeNameSize), (*C.ulong)(unsafe.Pointer(lpVolumeSerialNumber)), (*C.ulong)(unsafe.Pointer(lpMaximumComponentLength)), (*C.ulong)(unsafe.Pointer(lpFileSystemFlags)), (*C.char)(unsafe.Pointer(lpFileSystemNameBuffer)), C.ulong(nFileSystemNameSize)))
}

// BOOL GetVolumeInformationW(
//   LPCWSTR lpRootPathName,
//   LPWSTR  lpVolumeNameBuffer,
//   DWORD   nVolumeNameSize,
//   LPDWORD lpVolumeSerialNumber,
//   LPDWORD lpMaximumComponentLength,
//   LPDWORD lpFileSystemFlags,
//   LPWSTR  lpFileSystemNameBuffer,
//   DWORD   nFileSystemNameSize
// );
func XGetVolumeInformationW(t *TLS, lpRootPathName, lpVolumeNameBuffer uintptr, nVolumeNameSize uint32, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer uintptr, nFileSystemNameSize uint32) int32 {
	return int32(C.GetVolumeInformationW((*C.ushort)(unsafe.Pointer(lpRootPathName)), (*C.ushort)(unsafe.Pointer(lpVolumeNameBuffer)), C.ulong(nVolumeNameSize), (*C.ulong)(unsafe.Pointer(lpVolumeSerialNumber)), (*C.ulong)(unsafe.Pointer(lpMaximumComponentLength)), (*C.ulong)(unsafe.Pointer(lpFileSystemFlags)), (*C.ushort)(unsafe.Pointer(lpFileSystemNameBuffer)), C.ulong(nFileSystemNameSize)))
}

func XGetWindowLongPtrW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGetWindowsDirectoryA(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGlobalAddAtomW(t *TLS, _ ...interface{}) uint16 {
	panic(todo(""))
}

func XGlobalDeleteAtom(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGlobalGetAtomNameW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XIN6_ADDR_EQUAL(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XIN6_IS_ADDR_V4MAPPED(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL ImpersonateSelf(
//   SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
// );
func XImpersonateSelf(t *TLS, ImpersonationLevel int32) int32 {
	return int32(C.ImpersonateSelf(C.SECURITY_IMPERSONATION_LEVEL(ImpersonationLevel)))
}

// void InitializeCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XInitializeCriticalSection(t *TLS, lpCriticalSection uintptr) {
	C.InitializeCriticalSection((*C.struct__RTL_CRITICAL_SECTION)(unsafe.Pointer(lpCriticalSection)))
}

func XIsWindow(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XKillTimer(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// void LeaveCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XLeaveCriticalSection(t *TLS, lpCriticalSection uintptr) {
	C.LeaveCriticalSection((*C.struct__RTL_CRITICAL_SECTION)(unsafe.Pointer(lpCriticalSection)))
}

// HMODULE LoadLibraryExW(
//   LPCWSTR lpLibFileName,
//   HANDLE  hFile,
//   DWORD   dwFlags
// );
func XLoadLibraryExW(t *TLS, lpLibFileName, hFile uintptr, dwFlags uint32) uintptr {
	return uintptr(unsafe.Pointer(C.LoadLibraryExW((*C.ushort)(unsafe.Pointer(lpLibFileName)), C.HANDLE(hFile), C.ulong(dwFlags))))
}

func XMessageBeep(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XMessageBoxW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL MoveFileW(
//   LPCWSTR lpExistingFileName,
//   LPCWSTR lpNewFileName
// );
func XMoveFileW(t *TLS, lpExistingFileName, lpNewFileName uintptr) int32 {
	return int32(C.MoveFileW((*C.ushort)(unsafe.Pointer(lpExistingFileName)), (*C.ushort)(unsafe.Pointer(lpNewFileName))))
}

// DWORD MsgWaitForMultipleObjectsEx(
//   DWORD        nCount,
//   const HANDLE *pHandles,
//   DWORD        dwMilliseconds,
//   DWORD        dwWakeMask,
//   DWORD        dwFlags
// );
func XMsgWaitForMultipleObjectsEx(t *TLS, nCount uint32, pHandles uintptr, dwMilliseconds, dwWakeMask, dwFlags uint32) uint32 {
	return uint32(C.MsgWaitForMultipleObjectsEx(C.ulong(nCount), (*C.HANDLE)(unsafe.Pointer(pHandles)), C.ulong(dwMilliseconds), C.ulong(dwWakeMask), C.ulong(dwFlags)))
}

func XNetApiBufferFree(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// NET_API_STATUS NET_API_FUNCTION NetGetDCName(
//   LPCWSTR ServerName,
//   LPCWSTR DomainName,
//   LPBYTE  *Buffer
// );
func XNetGetDCName(t *TLS, ServerName, DomainName, Buffer uintptr) int32 {
	return int32(sys(t, netGetDCName, ServerName, DomainName, Buffer))
}

// NET_API_STATUS NET_API_FUNCTION NetUserGetInfo(
//   LPCWSTR servername,
//   LPCWSTR username,
//   DWORD   level,
//   LPBYTE  *bufptr
// );
func XNetUserGetInfo(t *TLS, servername, username uintptr, level uint32, bufptr uintptr) uint32 {
	return uint32(sys(t, netUserGetInfo, servername, username, level, bufptr))
}

// BOOL OpenProcessToken(
//   HANDLE  ProcessHandle,
//   DWORD   DesiredAccess,
//   PHANDLE TokenHandle
// );
func XOpenProcessToken(t *TLS, ProcessHandle uintptr, DesiredAccess uint32, TokenHandle uintptr) int32 {
	return int32(C.OpenProcessToken(C.HANDLE(ProcessHandle), C.ulong(DesiredAccess), (*C.HANDLE)(unsafe.Pointer(TokenHandle))))
}

// BOOL OpenThreadToken(
//   HANDLE  ThreadHandle,
//   DWORD   DesiredAccess,
//   BOOL    OpenAsSelf,
//   PHANDLE TokenHandle
// );
func XOpenThreadToken(t *TLS, ThreadHandle uintptr, DesiredAccess uint32, OpenAsSelf int32, TokenHandle uintptr) int32 {
	return int32(C.OpenThreadToken(C.HANDLE(ThreadHandle), C.ulong(DesiredAccess), C.int(OpenAsSelf), (*C.HANDLE)(unsafe.Pointer(TokenHandle))))
}

// BOOL WINAPI PeekConsoleInput(
//   _In_  HANDLE        hConsoleInput,
//   _Out_ PINPUT_RECORD lpBuffer,
//   _In_  DWORD         nLength,
//   _Out_ LPDWORD       lpNumberOfEventsRead
// );
func XPeekConsoleInputW(t *TLS, hConsoleInput, lpBuffer uintptr, nLength uint32, lpNumberOfEventsRead uintptr) int32 {
	return int32(C.PeekConsoleInput(C.HANDLE(hConsoleInput), (*C.struct__INPUT_RECORD)(unsafe.Pointer(lpBuffer)), C.ulong(nLength), (*C.ulong)(unsafe.Pointer(lpNumberOfEventsRead))))
}

// BOOL PeekMessageW(
//   LPMSG lpMsg,
//   HWND  hWnd,
//   UINT  wMsgFilterMin,
//   UINT  wMsgFilterMax,
//   UINT  wRemoveMsg
// );
func XPeekMessageW(t *TLS, lpMsg, hWnd uintptr, wMsgFilterMin, wMsgFilterMax, wRemoveMsg uint32) int32 {
	return int32(C.PeekMessageW((*C.struct_tagMSG)(unsafe.Pointer(lpMsg)), (*C.struct_HWND__)(unsafe.Pointer(hWnd)), C.uint(wMsgFilterMin), C.uint(wMsgFilterMax), C.uint(wRemoveMsg)))
}

// BOOL PeekNamedPipe(
//   HANDLE  hNamedPipe,
//   LPVOID  lpBuffer,
//   DWORD   nBufferSize,
//   LPDWORD lpBytesRead,
//   LPDWORD lpTotalBytesAvail,
//   LPDWORD lpBytesLeftThisMessage
// );
func XPeekNamedPipe(t *TLS, hNamedPipe, lpBuffer uintptr, nBufferSize uint32, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage uintptr) int32 {
	return int32(C.PeekNamedPipe(C.HANDLE(hNamedPipe), C.LPVOID(lpBuffer), C.ulong(nBufferSize), (*C.ulong)(unsafe.Pointer(lpBytesRead)), (*C.ulong)(unsafe.Pointer(lpTotalBytesAvail)), (*C.ulong)(unsafe.Pointer(lpBytesLeftThisMessage))))
}

func XPostMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XPostQuitMessage(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XPurgeComm(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL QueryPerformanceFrequency(
//   LARGE_INTEGER *lpFrequency
// );
func XQueryPerformanceFrequency(t *TLS, lpFrequency uintptr) int32 {
	return int32(C.QueryPerformanceFrequency((*C.LARGE_INTEGER)(unsafe.Pointer(lpFrequency))))
}

// BOOL WINAPI ReadConsole(
//   _In_     HANDLE  hConsoleInput,
//   _Out_    LPVOID  lpBuffer,
//   _In_     DWORD   nNumberOfCharsToRead,
//   _Out_    LPDWORD lpNumberOfCharsRead,
//   _In_opt_ LPVOID  pInputControl
// );
func XReadConsoleW(t *TLS, hConsoleInput, lpBuffer uintptr, nNumberOfCharsToRead uint32, lpNumberOfCharsRead, pInputControl uintptr) int32 {
	return int32(C.ReadConsoleW(C.HANDLE(hConsoleInput), C.LPVOID(unsafe.Pointer(lpBuffer)), C.ulong(nNumberOfCharsToRead), (*C.ulong)(unsafe.Pointer(lpNumberOfCharsRead)), C.LPVOID(pInputControl)))
}

func XRegCloseKey(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegConnectRegistryW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegCreateKeyExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegDeleteKeyW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegDeleteValueW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegEnumKeyExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegEnumValueW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegOpenKeyExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegQueryValueExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegSetValueExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegisterClassExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// ATOM RegisterClassW(
//   const WNDCLASSW *lpWndClass
// );
func XRegisterClassW(t *TLS, lpWndClass uintptr) int32 {
	return int32(C.RegisterClassW((*C.struct_tagWNDCLASSW)(unsafe.Pointer(lpWndClass))))
}

// BOOL RemoveDirectoryW(
//   LPCWSTR lpPathName
// );
func XRemoveDirectoryW(t *TLS, lpPathName uintptr) int32 {
	return int32(C.RemoveDirectoryW((*C.ushort)(unsafe.Pointer(lpPathName))))
}

// BOOL ResetEvent(
//   HANDLE hEvent
// );
func XResetEvent(t *TLS, hEvent uintptr) int32 {
	return int32(C.ResetEvent(C.HANDLE(hEvent)))
}

// BOOL RevertToSelf();
func XRevertToSelf(t *TLS) int32 {
	return int32(C.RevertToSelf())
}

// DWORD SearchPathW(
//   LPCWSTR lpPath,
//   LPCWSTR lpFileName,
//   LPCWSTR lpExtension,
//   DWORD   nBufferLength,
//   LPWSTR  lpBuffer,
//   LPWSTR  *lpFilePart
// );
func XSearchPathW(t *TLS, lpPath, lpFileName, lpExtension uintptr, nBufferLength uint32, lpBuffer, lpFilePart uintptr) int32 {
	return int32(C.SearchPathW((*C.ushort)(unsafe.Pointer(lpPath)), (*C.ushort)(unsafe.Pointer(lpFileName)), (*C.ushort)(unsafe.Pointer(lpExtension)), C.ulong(nBufferLength), (*C.ushort)(unsafe.Pointer(lpBuffer)), (*C.LPWSTR)(unsafe.Pointer(lpFilePart))))
}

func XSendMessageTimeoutW(t *TLS, _ ...interface{}) int64 {
	panic(todo(""))
}

func XSendMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetCommState(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetCommTimeouts(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL WINAPI SetConsoleMode(
//   _In_ HANDLE hConsoleHandle,
//   _In_ DWORD  dwMode
// );
func XSetConsoleMode(t *TLS, hConsoleHandle uintptr, dwMode uint32) int32 {
	return int32(C.SetConsoleMode(C.HANDLE(hConsoleHandle), C.ulong(dwMode)))
}

// BOOL SetFileAttributesW(
//   LPCWSTR lpFileName,
//   DWORD   dwFileAttributes
// );
func XSetFileAttributesW(t *TLS, lpFileName uintptr, dwFileAttributes uint32) int32 {
	return int32(C.SetFileAttributesW((*C.ushort)(unsafe.Pointer(lpFileName)), C.ulong(dwFileAttributes)))
}

func XSetHandleInformation(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL SetThreadPriority(
//   HANDLE hThread,
//   int    nPriority
// );
func XSetThreadPriority(t *TLS, hThread uintptr, nPriority int32) int32 {
	return int32(C.SetThreadPriority(C.HANDLE(hThread), C.int(nPriority)))
}

func XSetTimer(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetWindowLongPtrW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetupComm(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD SleepEx(
//   DWORD dwMilliseconds,
//   BOOL  bAlertable
// );
func XSleepEx(t *TLS, dwMilliseconds uint32, bAlertable int32) uint32 {
	return uint32(C.SleepEx(C.ulong(dwMilliseconds), C.int(bAlertable)))
}

func XTerminateThread(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XTranslateMessage(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL UnregisterClassW(
//   LPCWSTR   lpClassName,
//   HINSTANCE hInstance
// );
func XUnregisterClassW(t *TLS, lpClassName, hInstance uintptr) int32 {
	return int32(C.UnregisterClassW((*C.ushort)(unsafe.Pointer(lpClassName)), (*C.struct_HINSTANCE__)(unsafe.Pointer(hInstance))))
}

func XWSAAsyncSelect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWSAGetLastError(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// int WSAStartup(
//   WORD      wVersionRequired,
//   LPWSADATA lpWSAData
// );
func XWSAStartup(t *TLS, wVersionRequired uint16, lpWSAData uintptr) int32 {
	if err := windows.WSAStartup(uint32(wVersionRequired), (*windows.WSAData)(unsafe.Pointer(lpWSAData))); err != nil {
		return int32(err.(syscall.Errno))
	}

	return 0
}

// BOOL WINAPI WriteConsoleW(
//   _In_             HANDLE  hConsoleOutput,
//   _In_       const VOID    *lpBuffer,
//   _In_             DWORD   nNumberOfCharsToWrite,
//   _Out_opt_        LPDWORD lpNumberOfCharsWritten,
//   _Reserved_       LPVOID  lpReserved
// );
func XWriteConsoleW(t *TLS, hConsoleOutput, lpBuffer uintptr, nNumberOfCharsToWrite uint32, lpNumberOfCharsWritten, lpReserved uintptr) int32 {
	return int32(C.WriteConsoleW(C.HANDLE(hConsoleOutput), unsafe.Pointer(lpBuffer), C.ulong(nNumberOfCharsToWrite), (*C.ulong)(unsafe.Pointer(lpNumberOfCharsWritten)), (C.LPVOID)(unsafe.Pointer(lpReserved))))
}

func XWspiapiFreeAddrInfo(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWspiapiGetNameInfo(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// long _InterlockedExchange(
//    long volatile * Target,
//    long Value
// );
func X_InterlockedExchange(t *TLS, Target uintptr, Value long) long {
	return long(C._InterlockedExchange((*C.long)(unsafe.Pointer(Target)), C.long(Value)))
}

func X__ccgo_in6addr_anyp(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_beginthread(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_beginthreadex(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_controlfp(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

func X_endthreadex(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// void _ftime( struct _timeb *timeptr );
func X_ftime(t *TLS, timeptr uintptr) {
	C._ftime((*C.struct___timeb64)(unsafe.Pointer(timeptr)))
}

func X_snwprintf(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_strnicmp(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_wcsicmp(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// SOCKET WSAAPI accept(
//   SOCKET   s,
//   sockaddr *addr,
//   int      *addrlen
// );
func Xaccept(t *TLS, _ ...interface{}) uint64 {
	panic(todo(""))
}

func Xbind(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xclosesocket(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xconnect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xgethostname(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xgetpeername(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xgetsockname(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xgmtime(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func Xinet_ntoa(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func Xioctlsocket(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xlisten(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// int lstrcmpiA(
//   LPCSTR lpString1,
//   LPCSTR lpString2
// );
func XlstrcmpiA(t *TLS, lpString1, lpString2 uintptr) int32 {
	return int32(C.lstrcmpiA((*C.char)(unsafe.Pointer(lpString1)), (*C.char)(unsafe.Pointer(lpString2))))
}

func XlstrlenW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xrecv(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xselect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xsend(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xshutdown(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// SOCKET WSAAPI socket(
//   int af,
//   int type,
//   int protocol
// );
func Xsocket(t *TLS, _ ...interface{}) uint64 {
	panic(todo(""))
}

// wchar_t *wcschr(
//    const wchar_t *str,
//    wchar_t c
// );
func Xwcschr(t *TLS, str uintptr, c wchar_t) uintptr {
	return uintptr(unsafe.Pointer(C.wcschr((*C.ushort)(unsafe.Pointer(str)), C.ushort(c))))
}

func Xwcscpy(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// int _wcsicmp(
//    const wchar_t *string1,
//    const wchar_t *string2
// );
func Xwcsicmp(t *TLS, string1, string2 uintptr) int32 {
	return int32(C._wcsicmp((*C.ushort)(unsafe.Pointer(string1)), (*C.ushort)(unsafe.Pointer(string2))))
}

// int wcsncmp(
//    const wchar_t *string1,
//    const wchar_t *string2,
//    size_t count
// );
func Xwcsncmp(t *TLS, string1, string2 uintptr, count types.Size_t) int32 {
	return int32(C.wcsncmp((*C.ushort)(unsafe.Pointer(string1)), (*C.ushort)(unsafe.Pointer(string2)), C.size_t(count)))
}

// int WINAPIV wsprintfA(
//   LPSTR  ,
//   LPCSTR ,
//   ...
// );
func XwsprintfA(t *TLS, a, b, va uintptr) int32 {
	r := int32(sysv(t, wsprintfA, a, b, va))
	// if dmesgs {
	// 	dmesg("%v: %q %v: %q %v", origin(1), GoString(b), varargs(va), GoString(a), r)
	// }
	return r
}

func XwsprintfW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// UINT WINAPI GetConsoleCP(void);
func XGetConsoleCP(t *TLS) uint32 {
	return uint32(C.GetConsoleCP())
}

// HANDLE GetCurrentThread();
func XGetCurrentThread(t *TLS) uintptr {
	return uintptr(C.GetCurrentThread())
}

// UINT GetACP();
func XGetACP(t *TLS) uint32 {
	return uint32(C.GetACP())
}

// LPWSTR GetCommandLineW();
func XGetCommandLineW(t *TLS) uintptr {
	return uintptr(unsafe.Pointer(C.GetCommandLineW()))
}

// BOOL AddAccessDeniedAce(
//   PACL  pAcl,
//   DWORD dwAceRevision,
//   DWORD AccessMask,
//   PSID  pSid
// );
func XAddAccessDeniedAce(t *TLS, pAcl uintptr, dwAceRevision, AccessMask uint32, pSid uintptr) int32 {
	return int32(C.AddAccessDeniedAce((*C.struct__ACL)(unsafe.Pointer(pAcl)), C.ulong(dwAceRevision), C.ulong(AccessMask), C.PVOID(pSid)))
}

// BOOL AddAce(
//   PACL   pAcl,
//   DWORD  dwAceRevision,
//   DWORD  dwStartingAceIndex,
//   LPVOID pAceList,
//   DWORD  nAceListLength
// );
func XAddAce(t *TLS, pAcl uintptr, dwAceRevision, dwStartingAceIndex uint32, pAceList uintptr, nAceListLength uint32) int32 {
	return int32(C.AddAce((*C.struct__ACL)(unsafe.Pointer(pAcl)), C.ulong(dwAceRevision), C.ulong(dwStartingAceIndex), C.LPVOID(pAceList), C.ulong(nAceListLength)))
}

// BOOL GetAce(
//   PACL   pAcl,
//   DWORD  dwAceIndex,
//   LPVOID *pAce
// );
func XGetAce(t *TLS, pAcl uintptr, dwAceIndex uint32, pAce uintptr) int32 {
	return int32(C.GetAce((*C.struct__ACL)(unsafe.Pointer(pAcl)), C.ulong(dwAceIndex), (*C.LPVOID)(unsafe.Pointer(pAce))))
}

// BOOL GetAclInformation(
//   PACL                  pAcl,
//   LPVOID                pAclInformation,
//   DWORD                 nAclInformationLength,
//   ACL_INFORMATION_CLASS dwAclInformationClass
// );
func XGetAclInformation(t *TLS, pAcl, pAclInformation uintptr, nAclInformationLength, dwAclInformationClass uint32) int32 {
	return int32(C.GetAclInformation((*C.struct__ACL)(unsafe.Pointer(pAcl)), C.LPVOID(pAclInformation), C.ulong(nAclInformationLength), C.ACL_INFORMATION_CLASS(dwAclInformationClass)))
}

// BOOL GetFileSecurityA(
//   LPCSTR               lpFileName,
//   SECURITY_INFORMATION RequestedInformation,
//   PSECURITY_DESCRIPTOR pSecurityDescriptor,
//   DWORD                nLength,
//   LPDWORD              lpnLengthNeeded
// );
func XGetFileSecurityA(t *TLS, lpFileName uintptr, RequestedInformation uint32, pSecurityDescriptor uintptr, nLength uint32, lpnLengthNeeded uintptr) int32 {
	return int32(C.GetFileSecurityA((*C.char)(unsafe.Pointer(lpFileName)), C.ulong(RequestedInformation), C.PVOID(pSecurityDescriptor), C.ulong(nLength), (*C.ulong)(unsafe.Pointer(lpnLengthNeeded))))
}

// BOOL GetFileSecurityW(
//   LPCSTR               lpFileName,
//   SECURITY_INFORMATION RequestedInformation,
//   PSECURITY_DESCRIPTOR pSecurityDescriptor,
//   DWORD                nLength,
//   LPDWORD              lpnLengthNeeded
// );
func XGetFileSecurityW(t *TLS, lpFileName uintptr, RequestedInformation uint32, pSecurityDescriptor uintptr, nLength uint32, lpnLengthNeeded uintptr) int32 {
	return int32(C.GetFileSecurityW((*C.ushort)(unsafe.Pointer(lpFileName)), C.ulong(RequestedInformation), C.PVOID(pSecurityDescriptor), C.ulong(nLength), (*C.ulong)(unsafe.Pointer(lpnLengthNeeded))))
}

// DWORD GetLengthSid(
//   PSID pSid
// );
func XGetLengthSid(t *TLS, pSid uintptr) int32 {
	return int32(C.GetLengthSid(C.PVOID(pSid)))
}

// BOOL GetSecurityDescriptorDacl(
//   PSECURITY_DESCRIPTOR pSecurityDescriptor,
//   LPBOOL               lpbDaclPresent,
//   PACL                 *pDacl,
//   LPBOOL               lpbDaclDefaulted
// );
func XGetSecurityDescriptorDacl(t *TLS, pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted uintptr) int32 {
	return int32(C.GetSecurityDescriptorDacl(C.PVOID(pSecurityDescriptor), (*C.int)(unsafe.Pointer(lpbDaclPresent)), (*C.PACL)(unsafe.Pointer(pDacl)), (*C.int)(unsafe.Pointer(lpbDaclDefaulted))))
}

// DWORD GetSidLengthRequired(
//   UCHAR nSubAuthorityCount
// );
func XGetSidLengthRequired(t *TLS, nSubAuthorityCount uint8) int32 {
	return int32(C.GetSidLengthRequired(C.uchar(nSubAuthorityCount)))
}

// PDWORD GetSidSubAuthority(
//   PSID  pSid,
//   DWORD nSubAuthority
// );
func XGetSidSubAuthority(t *TLS, pSid uintptr, nSubAuthority uint32) uintptr {
	return uintptr(unsafe.Pointer(C.GetSidSubAuthority(C.PVOID(pSid), C.ulong(nSubAuthority))))
}

// BOOL InitializeAcl(
//   PACL  pAcl,
//   DWORD nAclLength,
//   DWORD dwAclRevision
// );
func XInitializeAcl(t *TLS, pAcl uintptr, nAclLength, dwAclRevision uint32) int32 {
	return int32(C.InitializeAcl((*C.struct__ACL)(unsafe.Pointer(pAcl)), C.ulong(nAclLength), C.ulong(dwAclRevision)))
}

// BOOL InitializeSid(
//   PSID                      Sid,
//   PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
//   BYTE                      nSubAuthorityCount
// );
func XInitializeSid(t *TLS, Sid, pIdentifierAuthority uintptr, nSubAuthorityCount uint8) int32 {
	return int32(C.InitializeSid(C.PVOID(Sid), (*C.struct__SID_IDENTIFIER_AUTHORITY)(unsafe.Pointer(pIdentifierAuthority)), C.uchar(nSubAuthorityCount)))
}

// VOID RaiseException(
//   DWORD           dwExceptionCode,
//   DWORD           dwExceptionFlags,
//   DWORD           nNumberOfArguments,
//   const ULONG_PTR *lpArguments
// );
func XRaiseException(t *TLS, dwExceptionCode, dwExceptionFlags, nNumberOfArguments uint32, lpArguments uintptr) {
	C.RaiseException(C.ulong(dwExceptionCode), C.ulong(dwExceptionFlags), C.ulong(nNumberOfArguments), (*C.ulonglong)(unsafe.Pointer(lpArguments)))
}

// UINT SetErrorMode(
//   UINT uMode
// );
func XSetErrorMode(t *TLS, uMode uint32) int32 {
	return int32(C.SetErrorMode(C.uint(uMode)))
}

// DWORD SetNamedSecurityInfoA(
//   LPSTR                pObjectName,
//   SE_OBJECT_TYPE       ObjectType,
//   SECURITY_INFORMATION SecurityInfo,
//   PSID                 psidOwner,
//   PSID                 psidGroup,
//   PACL                 pDacl,
//   PACL                 pSacl
// );
func XSetNamedSecurityInfoA(t *TLS, pObjectName uintptr, ObjectType, SecurityInfo uint32, psidOwner, psidGroup, pDacl, pSacl uintptr) uint32 {
	return uint32(C.SetNamedSecurityInfoA((*C.char)(unsafe.Pointer(pObjectName)), C.SE_OBJECT_TYPE(ObjectType), C.ulong(SecurityInfo), C.PVOID(psidOwner), C.PVOID(psidGroup), (*C.struct__ACL)(unsafe.Pointer(pDacl)), (*C.struct__ACL)(unsafe.Pointer(pSacl))))
}

// int chmod(const char *pathname, mode_t mode)
func Xchmod(t *TLS, pathname uintptr, mode int32) int32 {
	return int32(C.chmod((*C.char)(unsafe.Pointer(pathname)), C.int(mode)))
}

// int sscanf(const char *str, const char *format, ...);
func Xsscanf(t *TLS, str, format, va uintptr) int32 {
	if dmesgs {
		dmesg("%v: %q %q, errno %v", origin(1), GoString(str), GoString(format), __ccgo_errno())
	}
	r := int32(sysv(t, sscanf, str, format, va))
	if dmesgs {
		dmesg("%v: errno %v", origin(1), __ccgo_errno())
	}
	return r
}

func __ccgo_errno() int32 {
	return int32(C.__ccgo_errno())
}

// int write(
//    int fd,
//    const void *buffer,
//    unsigned int count
// );
func Xwrite(t *TLS, fd int32, buffer uintptr, count uint32) int32 {
	return int32(C.write(C.int(fd), unsafe.Pointer(buffer), C.uint(count)))
}

// BOOL CreateProcessA(
//   LPCSTR                lpApplicationName,
//   LPSTR                 lpCommandLine,
//   LPSECURITY_ATTRIBUTES lpProcessAttributes,
//   LPSECURITY_ATTRIBUTES lpThreadAttributes,
//   BOOL                  bInheritHandles,
//   DWORD                 dwCreationFlags,
//   LPVOID                lpEnvironment,
//   LPCSTR                lpCurrentDirectory,
//   LPSTARTUPINFOA        lpStartupInfo,
//   LPPROCESS_INFORMATION lpProcessInformation
// );
func XCreateProcessA(t *TLS, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes uintptr, bInheritHandles int32, dwCreationFlags uint32, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation uintptr) int32 {
	return int32(C.CreateProcessA((*C.char)(unsafe.Pointer(lpApplicationName)), (*C.char)(unsafe.Pointer(lpCommandLine)), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpProcessAttributes)), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpThreadAttributes)), C.int(bInheritHandles), C.ulong(dwCreationFlags), C.LPVOID(lpEnvironment), (*C.char)(unsafe.Pointer(lpCurrentDirectory)), (*C.struct__STARTUPINFOA)(unsafe.Pointer(lpStartupInfo)), (*C.struct__PROCESS_INFORMATION)(unsafe.Pointer(lpProcessInformation))))
}

// BOOL CreateProcessW(
//   LPCWSTR               lpApplicationName,
//   LPWSTR                lpCommandLine,
//   LPSECURITY_ATTRIBUTES lpProcessAttributes,
//   LPSECURITY_ATTRIBUTES lpThreadAttributes,
//   BOOL                  bInheritHandles,
//   DWORD                 dwCreationFlags,
//   LPVOID                lpEnvironment,
//   LPCWSTR               lpCurrentDirectory,
//   LPSTARTUPINFOW        lpStartupInfo,
//   LPPROCESS_INFORMATION lpProcessInformation
// );
func XCreateProcessW(t *TLS, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes uintptr, bInheritHandles int32, dwCreationFlags uint32, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation uintptr) int32 {
	return int32(C.CreateProcessW((*C.ushort)(unsafe.Pointer(lpApplicationName)), (*C.ushort)(unsafe.Pointer(lpCommandLine)), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpProcessAttributes)), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpThreadAttributes)), C.int(bInheritHandles), C.ulong(dwCreationFlags), C.LPVOID(lpEnvironment), (*C.ushort)(unsafe.Pointer(lpCurrentDirectory)), (*C.struct__STARTUPINFOW)(unsafe.Pointer(lpStartupInfo)), (*C.struct__PROCESS_INFORMATION)(unsafe.Pointer(lpProcessInformation))))
}

// DWORD WaitForInputIdle(
//   HANDLE hProcess,
//   DWORD  dwMilliseconds
// );
func XWaitForInputIdle(t *TLS, hProcess uintptr, dwMilliseconds uint32) int32 {
	return int32(C.WaitForInputIdle(C.HANDLE(hProcess), C.ulong(dwMilliseconds)))
}

// long int strtol(const char *nptr, char **endptr, int base);
func Xstrtol(t *TLS, nptr, endptr uintptr, base int32) long {
	return long(C.strtol((*C.char)(unsafe.Pointer(nptr)), (**C.char)(unsafe.Pointer(endptr)), C.int(base)))
	//TODO seenDigits, neg, next, n, _ := strToUint64(t, nptr, base)
	//TODO if endptr != 0 {
	//TODO 	*(*uintptr)(unsafe.Pointer(endptr)) = next
	//TODO }
	//TODO if !seenDigits {
	//TODO 	*(*int32)(unsafe.Pointer(X_errno(t))) = errno.EINVAL
	//TODO 	return 0
	//TODO }

	//TODO if n > limits.LONG_MAX {
	//TODO 	*(*int32)(unsafe.Pointer(X_errno(t))) = errno.ERANGE
	//TODO 	return limits.LONG_MAX
	//TODO }

	//TODO if neg {
	//TODO 	n = -n
	//TODO }
	//TODO n1 := int64(n)
	//TODO if n1 < limits.LONG_MIN {
	//TODO 	*(*int32)(unsafe.Pointer(X_errno(t))) = errno.ERANGE
	//TODO 	return limits.LONG_MIN
	//TODO }

	//TODO return long(n1)
}

// unsigned long int strtoul(const char *nptr, char **endptr, int base);
func Xstrtoul(t *TLS, nptr, endptr uintptr, base int32) ulong {
	return ulong(C.strtoul((*C.char)(unsafe.Pointer(nptr)), (**C.char)(unsafe.Pointer(endptr)), C.int(base)))
	// seenDigits, neg, next, n, _ := strToUint64(t, nptr, base)
	// if endptr != 0 {
	// 	*(*uintptr)(unsafe.Pointer(endptr)) = next
	// }
	// if !seenDigits {
	// 	*(*int32)(unsafe.Pointer(X_errno(t))) = errno.EINVAL
	// 	return 0
	// }

	// if n > limits.ULONG_MAX {
	// 	*(*int32)(unsafe.Pointer(X_errno(t))) = errno.ERANGE
	// 	return limits.ULONG_MAX
	// }

	// if neg {
	// 	n = -n
	// }
	// return ulong(n)
}

// int rename(const char *oldpath, const char *newpath);
func Xrename(t *TLS, oldpath, newpath uintptr) int32 {
	return int32(C.rename((*C.char)(unsafe.Pointer(oldpath)), (*C.char)(unsafe.Pointer(newpath))))
}

// int unlink(const char *pathname);
func Xunlink(t *TLS, pathname uintptr) int32 {
	return int32(C.unlink((*C.char)(unsafe.Pointer(pathname))))
}

// unsigned int _set_abort_behavior(
//    unsigned int flags,
//    unsigned int mask
// );
func X_set_abort_behavior(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

// HANDLE OpenEventA(
//   DWORD  dwDesiredAccess,
//   BOOL   bInheritHandle,
//   LPCSTR lpName
// );
func XOpenEventA(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func Xclose(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xopen(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_fstat64(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xread(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_commit(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xferror(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_chsize(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_snprintf(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_findfirst64i32(t *TLS, _ ...interface{}) int64 {
	panic(todo(""))
}

func X_findnext64i32(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_findclose(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xatof(t *TLS, _ ...interface{}) float64 {
	panic(todo(""))
}
