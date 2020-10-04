// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

/*

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <windows.h>

extern char ***__imp_environ;
extern unsigned __ccgo_getLastError();
extern void *__ccgo_environ();
extern void *__ccgo_errno_location();

*/
import "C"

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"modernc.org/libc/sys/types"
)

// Keep these outside of the var block otherwise go generate will miss them.
// var X__imp__environ = uintptr(C.__ccgo_environ_location())
var X__imp__environ = uintptr(unsafe.Pointer(C.__imp__environ))

type (
	long     = int32
	longlong = int64
	ulong    = uint32
)

var (
	// msvcrt.dll
	sprintf uintptr
	fprintf uintptr

	// kernel32.dll
	formatMessageW uintptr

	// ntdll.dll
	rtlGetVersion uintptr
)

func init() {
	mustLinkDll("msvcrt.dll", []linkFunc{
		{"sprintf", &sprintf},
		{"fprintf", &fprintf},
	})
	mustLinkDll("kernel32.dll", []linkFunc{
		{"FormatMessageW", &formatMessageW},
	})
	mustLinkDll("ntdll.dll", []linkFunc{
		{"RtlGetVersion", &rtlGetVersion},
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

// void *realloc(void *ptr, size_t size);
func Xrealloc(t *TLS, ptr uintptr, size types.Size_t) uintptr {
	return uintptr(C.realloc(unsafe.Pointer(ptr), C.size_t(size)))
}

func Environ() uintptr {
	panic(todo(""))
	return uintptr(C.__ccgo_environ())
}

func Xexit(t *TLS, status int32) {
	panic(todo(""))
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

// int memcmp(const void *s1, const void *s2, size_t n);
func Xmemcmp(t *TLS, s1, s2 uintptr, n types.Size_t) int32 {
	return int32(C.memcmp(unsafe.Pointer(s1), unsafe.Pointer(s2), C.size_t(n)))
}

// int printf(const char *format, ...);
func Xprintf(t *TLS, format, args uintptr) int32 {
	panic(todo(""))
	// return int32(sysv(t, printfAddr, format, args))
}

// char *strchr(const char *s, int c)
func Xstrchr(t *TLS, s uintptr, c int32) uintptr {
	return uintptr(unsafe.Pointer(C.strchr((*C.char)(unsafe.Pointer(s)), C.int(c))))
}

// int strcmp(const char *s1, const char *s2)
func Xstrcmp(t *TLS, s1, s2 uintptr) int32 {
	return int32(C.strcmp((*C.char)(unsafe.Pointer(s1)), (*C.char)(unsafe.Pointer(s2))))
}

// char *strcpy(char *dest, const char *src)
func Xstrcpy(t *TLS, dest, src uintptr) (r uintptr) {
	return uintptr(unsafe.Pointer(C.strcpy((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)))))
}

// size_t strlen(const char *s)
func Xstrlen(t *TLS, s uintptr) (r types.Size_t) {
	return types.Size_t(C.strlen((*C.char)(unsafe.Pointer(s))))
}

// void abort(void);
func Xabort(t *TLS) {
	panic(todo(""))
	C.abort()
}

// int snprintf(char *str, size_t size, const char *format, ...);
func Xsnprintf(t *TLS, str uintptr, size types.Size_t, format, args uintptr) (r int32) {
	panic(todo(""))
}

// int sprintf(char *str, const char *format, ...);
func Xsprintf(t *TLS, str, format, args uintptr) (r int32) {
	r = int32(sysv(t, sprintf, str, format, args))
	// if dmesgs {
	// 	dmesg("%v: %q %v: %q %v", origin(1), GoString(format), varargs(args), GoString(str), r)
	// }
	return r
}

// void *memset(void *s, int c, size_t n)
func Xmemset(t *TLS, s uintptr, c int32, n types.Size_t) uintptr {
	return uintptr(unsafe.Pointer(C.memset(unsafe.Pointer(s), C.int(c), C.size_t(n))))
}

// void *memcpy(void *dest, const void *src, size_t n);
func Xmemcpy(t *TLS, dest, src uintptr, n types.Size_t) (r uintptr) {
	return uintptr(unsafe.Pointer(C.memcpy(unsafe.Pointer(dest), unsafe.Pointer(src), C.size_t(n))))
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

// void _exit(int status);
func X_exit(t *TLS, status int32) {
	panic(todo(""))
	os.Exit(int(status))
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

// int vwscanf(const wchar_t * restrict format, va_list arg);
func X__ms_vwscanf(t *TLS, format, ap uintptr) int32 {
	panic(todo(""))
}

// int _vsnwprintf(wchar_t *buffer, size_t count, const wchar_t *format, va_list argptr);
func X_vsnwprintf(t *TLS, buffer uintptr, count types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
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

// int vswscanf(const wchar_t *buffer, const wchar_t *format, va_list arglist);
func X__ms_vswscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// struct tm *localtime( const time_t *sourceTime );
func Xlocaltime(t *TLS, sourceTime uintptr) uintptr {
	panic(todo(""))
	return uintptr(unsafe.Pointer(C.localtime((*C.longlong)(unsafe.Pointer(sourceTime)))))
}

// int fprintf(FILE *stream, const char *format, ...);
func Xfprintf(t *TLS, stream, format, args uintptr) int32 {
	return int32(sysv(t, fprintf, stream, format, args))
}

// __acrt_iob_func
func X__acrt_iob_func(t *TLS, fd uint32) uintptr {
	return uintptr(unsafe.Pointer(C.__acrt_iob_func(C.uint(fd))))
}

func X_endthreadex(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_beginthreadex(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD GetCurrentThreadId();
func XGetCurrentThreadId(t *TLS) uint32 {
	return uint32(C.GetCurrentThreadId())
}

// int fflush(FILE *stream);
func Xfflush(t *TLS, stream uintptr) int32 {
	panic(todo(""))
	return int32(C.fflush((*C.FILE)(unsafe.Pointer(stream))))
}

// BOOL CloseHandle(
//   HANDLE hObject
// );
func XCloseHandle(t *TLS, hObject uintptr) int32 {
	return int32(C.CloseHandle(C.HANDLE(hObject)))
}

// void *memmove(void *dest, const void *src, size_t n);
func Xmemmove(t *TLS, dest, src uintptr, n types.Size_t) uintptr {
	return uintptr(C.memmove(unsafe.Pointer(dest), unsafe.Pointer(src), C.size_t(n)))
}

// int strncmp(const char *s1, const char *s2, size_t n)
func Xstrncmp(t *TLS, s1, s2 uintptr, n types.Size_t) int32 {
	return int32(C.strncmp((*C.char)(unsafe.Pointer(s1)), (*C.char)(unsafe.Pointer(s2)), C.size_t(n)))
}

// long _InterlockedCompareExchange(
//    long volatile * Destination,
//    long Exchange,
//    long Comparand
// );
func X_InterlockedCompareExchange(t *TLS, Destination uintptr, Exchange, Comparand long) long {
	return long(C._InterlockedCompareExchange((*C.long)(unsafe.Pointer(Destination)), C.long(Exchange), C.long(Comparand)))
}

// char *strrchr(const char *s, int c)
func Xstrrchr(t *TLS, s uintptr, c int32) (r uintptr) {
	return uintptr(unsafe.Pointer(C.strrchr((*C.char)(unsafe.Pointer(s)), C.int(c))))
}

// size_t strcspn(const char *s, const char *reject);
func Xstrcspn(t *TLS, s, reject uintptr) (r types.Size_t) {
	return types.Size_t(C.strcspn((*C.char)(unsafe.Pointer(s)), (*C.char)(unsafe.Pointer(reject))))
}

// int rename(const char *oldpath, const char *newpath);
func Xrename(t *TLS, oldpath, newpath uintptr) int32 {
	panic(todo(""))
	return int32(C.rename((*C.char)(unsafe.Pointer(oldpath)), (*C.char)(unsafe.Pointer(newpath))))
}

// BOOL AreFileApisANSI();
func XAreFileApisANSI(t *TLS) int32 {
	panic(todo(""))
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

// HANDLE CreateMutexW(
//   LPSECURITY_ATTRIBUTES lpMutexAttributes,
//   BOOL                  bInitialOwner,
//   LPCWSTR               lpName
// );
func XCreateMutexW(t *TLS, lpMutexAttributes uintptr, bInitialOwner int32, lpName uintptr) uintptr {
	panic(todo(""))
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

// BOOL FreeLibrary(HMODULE hLibModule);
func XFreeLibrary(t *TLS, hLibModule uintptr) int32 {
	panic(todo(""))
}

// DWORD GetCurrentProcessId();
func XGetCurrentProcessId(t *TLS) uint32 {
	panic(todo(""))
	return uint32(C.GetCurrentProcessId())
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
	panic(todo(""))
	return uint32(C.GetFileAttributesA((*C.char)(unsafe.Pointer(lpFileName))))
}

// DWORD GetFileAttributesW(
//   LPCWSTR lpFileName
// );
func XGetFileAttributesW(t *TLS, lpFileName uintptr) uint32 {
	return uint32(C.GetFileAttributesW((*C.ushort)(unsafe.Pointer(lpFileName))))
}

// BOOL GetFileAttributesExW(
//   LPCWSTR                lpFileName,
//   GET_FILEEX_INFO_LEVELS fInfoLevelId,
//   LPVOID                 lpFileInformation
// );
func XGetFileAttributesExW(t *TLS, lpFileName uintptr, fInfoLevelId uint32, lpFileInformation uintptr) int32 {
	return int32(C.GetFileAttributesExW((*C.ushort)(unsafe.Pointer(lpFileName)), C.GET_FILEEX_INFO_LEVELS(fInfoLevelId), C.LPVOID(unsafe.Pointer(lpFileInformation))))
}

// DWORD GetFileSize(
//   HANDLE  hFile,
//   LPDWORD lpFileSizeHigh
// );
func XGetFileSize(t *TLS, hFile, lpFileSizeHigh uintptr) uint32 {
	return uint32(C.GetFileSize(C.HANDLE(hFile), (*C.ulong)(unsafe.Pointer(lpFileSizeHigh))))
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

// DWORD GetLastError();
func XGetLastError(t *TLS) uint32 {
	return uint32(C.__ccgo_getLastError())
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
	panic(todo(""))
	// return int32(sys(t, cancelSynchronousIo, hThread))
}

// void GetSystemInfo(
//   LPSYSTEM_INFO lpSystemInfo
// );
func XGetSystemInfo(t *TLS, lpSystemInfo uintptr) {
	C.GetSystemInfo((*C.struct__SYSTEM_INFO)(unsafe.Pointer(lpSystemInfo)))
}

// void GetSystemTime(LPSYSTEMTIME lpSystemTime);
func XGetSystemTime(t *TLS, lpSystemTime uintptr) {
	panic(todo(""))
	C.GetSystemTime((*C.struct__SYSTEMTIME)(unsafe.Pointer(lpSystemTime)))
}

// void GetSystemTimeAsFileTime(
//   LPFILETIME lpSystemTimeAsFileTime
// );
func XGetSystemTimeAsFileTime(t *TLS, lpSystemTimeAsFileTime uintptr) {
	C.GetSystemTimeAsFileTime((*C.struct__FILETIME)(unsafe.Pointer(lpSystemTimeAsFileTime)))
}

// DWORD GetTempPathA(
//   DWORD nBufferLength,
//   LPSTR lpBuffer
// );
func XGetTempPathA(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	panic(todo(""))
}

// DWORD GetTempPathW(
//   DWORD  nBufferLength,
//   LPWSTR lpBuffer
// );
func XGetTempPathW(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	panic(todo(""))
	return uint32(C.GetTempPathW(C.ulong(nBufferLength), (*C.ushort)(unsafe.Pointer(lpBuffer))))
}

// DWORD GetTickCount();
func XGetTickCount(t *TLS) uint32 {
	panic(todo(""))
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

// LPVOID HeapAlloc(
//   HANDLE hHeap,
//   DWORD  dwFlags,
//   SIZE_T dwBytes
// );
func XHeapAlloc(t *TLS, hHeap uintptr, dwFlags uint32, dwBytes types.Size_t) uintptr {
	panic(todo(""))
	return uintptr(C.HeapAlloc(C.HANDLE(hHeap), C.ulong(dwFlags), C.ulonglong(dwBytes)))
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
	panic(todo(""))
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

// SIZE_T HeapCompact(
//   HANDLE hHeap,
//   DWORD  dwFlags
// );
func XHeapCompact(t *TLS, hHeap uintptr, dwFlags uint32) types.Size_t {
	panic(todo(""))
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

// HLOCAL LocalFree(
//   HLOCAL hMem
// );
func XLocalFree(t *TLS, hMem uintptr) uintptr {
	return uintptr(C.LocalFree(C.HANDLE(hMem)))
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

// LPVOID MapViewOfFile(
//   HANDLE hFileMappingObject,
//   DWORD  dwDesiredAccess,
//   DWORD  dwFileOffsetHigh,
//   DWORD  dwFileOffsetLow,
//   SIZE_T dwNumberOfBytesToMap
// );
func XMapViewOfFile(t *TLS, hFileMappingObject uintptr, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow uint32, dwNumberOfBytesToMap types.Size_t) uintptr {
	panic(todo(""))
	return uintptr(C.MapViewOfFile(C.HANDLE(hFileMappingObject), C.ulong(dwDesiredAccess), C.ulong(dwFileOffsetHigh), C.ulong(dwFileOffsetLow), C.ulonglong(dwNumberOfBytesToMap)))
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

// BOOL QueryPerformanceCounter(
//   LARGE_INTEGER *lpPerformanceCount
// );
func XQueryPerformanceCounter(t *TLS, lpPerformanceCount uintptr) int32 {
	return int32(C.QueryPerformanceCounter((*C.LARGE_INTEGER)(unsafe.Pointer(lpPerformanceCount))))
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
	panic(todo(""))
	return int32(C.SetEndOfFile(C.HANDLE(hFile)))
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

// void Sleep(
//   DWORD dwMilliseconds
// );
func XSleep(t *TLS, dwMilliseconds uint32) {
	C.Sleep(C.ulong(dwMilliseconds))
}

// BOOL SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime);
func XSystemTimeToFileTime(t *TLS, lpSystemTime, lpFileTime uintptr) int32 {
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

// BOOL UnmapViewOfFile(
//   LPCVOID lpBaseAddress
// );
func XUnmapViewOfFile(t *TLS, lpBaseAddress uintptr) int32 {
	panic(todo(""))
	return int32(C.UnmapViewOfFile(C.LPCVOID(lpBaseAddress)))
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

// DWORD WaitForSingleObject(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds
// );
func XWaitForSingleObject(t *TLS, hHandle uintptr, dwMilliseconds uint32) uint32 {
	return uint32(C.WaitForSingleObject(C.HANDLE(hHandle), C.ulong(dwMilliseconds)))
}

// DWORD WaitForSingleObjectEx(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds,
//   BOOL   bAlertable
// );
func XWaitForSingleObjectEx(t *TLS, hHandle uintptr, dwMilliseconds uint32, bAlertable int32) uint32 {
	return uint32(C.WaitForSingleObjectEx(C.HANDLE(hHandle), C.ulong(dwMilliseconds), C.int(bAlertable)))
}

// void OutputDebugStringA(
//   LPCSTR lpOutputString
// )
func XOutputDebugStringA(t *TLS, lpOutputString uintptr) {
	panic(todo(""))
}

// void OutputDebugStringW(
//   LPCWSTR lpOutputString
// );
func XOutputDebugStringW(t *TLS, lpOutputString uintptr) {
	panic(todo(""))
}

// HANDLE GetProcessHeap();
func XGetProcessHeap(t *TLS) uintptr {
	return uintptr(C.GetProcessHeap())
}

// _CRTIMP extern int *__cdecl _errno(void); // /usr/share/mingw-w64/include/errno.h:17:
func X_errno(t *TLS) uintptr {
	return uintptr(C.__ccgo_errno_location())
}

// int atoi(const char *nptr);
func Xatoi(t *TLS, nptr uintptr) int32 {
	panic(todo(""))
	return int32(C.atoi((*C.char)(unsafe.Pointer(nptr))))
}

// char *strncpy(char *dest, const char *src, size_t n)
func Xstrncpy(t *TLS, dest, src uintptr, n types.Size_t) (r uintptr) {
	panic(todo(""))
	return uintptr(unsafe.Pointer(C.strncpy((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)), C.size_t(n))))
}

// char *getenv(const char *name);
func Xgetenv(t *TLS, name uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.getenv((*C.char)(unsafe.Pointer(name)))))
}

// char *strstr(const char *haystack, const char *needle);
func Xstrstr(t *TLS, haystack, needle uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.strstr((*C.char)(unsafe.Pointer(haystack)), (*C.char)(unsafe.Pointer(needle)))))
}

// BOOL FlushViewOfFile(
//   LPCVOID lpBaseAddress,
//   SIZE_T  dwNumberOfBytesToFlush
// );
func XFlushViewOfFile(t *TLS, lpBaseAddress uintptr, dwNumberOfBytesToFlush types.Size_t) int32 {
	panic(todo(""))
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

// time_t mktime(struct tm *tm);
func Xmktime(t *TLS, ptm uintptr) types.Time_t {
	panic(todo(""))
	return types.Time_t(C.mktime((*C.struct_tm)(unsafe.Pointer(ptm))))
}

// void tzset (void);
func Xtzset(t *TLS) {
	panic(todo(""))
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

func Xgetsockopt(t *TLS, _ ...interface{}) int32 {
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
	panic(todo(""))
	return int32(C.isatty(C.int(fd)))
}

// BOOL IsDebuggerPresent();
func XIsDebuggerPresent(t *TLS) int32 {
	panic(todo(""))
	return int32(C.IsDebuggerPresent())
}

func XExitProcess(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xsetsockopt(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// char *strcat(char *dest, const char *src)
func Xstrcat(t *TLS, dest, src uintptr) (r uintptr) {
	panic(todo(""))
	return uintptr(unsafe.Pointer(C.strcat((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)))))
}

// char *strerror(int errnum);
func Xstrerror(t *TLS, errnum int32) uintptr {
	panic(todo(""))
	return uintptr(unsafe.Pointer(C.strerror(C.int(errnum))))
}

// int tolower(int c);
func Xtolower(t *TLS, c int32) int32 {
	return int32(C.tolower(C.int(c)))
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

// HANDLE WINAPI GetStdHandle(
//   _In_ DWORD nStdHandle
// );
func XGetStdHandle(t *TLS, nStdHandle uint32) uintptr {
	return uintptr(C.GetStdHandle(C.ulong(nStdHandle)))
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
	panic(todo(""))
	return int32(C.DuplicateHandle(C.HANDLE(hSourceProcessHandle), C.HANDLE(hSourceHandle), C.HANDLE(hTargetProcessHandle), (*C.HANDLE)(unsafe.Pointer(lpTargetHandle)), C.ulong(dwDesiredAccess), C.int(bInheritHandle), C.ulong(dwOptions)))
}

// HANDLE GetCurrentProcess();
func XGetCurrentProcess(t *TLS) uintptr {
	panic(todo(""))
	return uintptr(C.GetCurrentProcess())
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

// BOOL WINAPI ReadConsole(
//   _In_     HANDLE  hConsoleInput,
//   _Out_    LPVOID  lpBuffer,
//   _In_     DWORD   nNumberOfCharsToRead,
//   _Out_    LPDWORD lpNumberOfCharsRead,
//   _In_opt_ LPVOID  pInputControl
// );
func XReadConsoleW(t *TLS, hConsoleInput, lpBuffer uintptr, nNumberOfCharsToRead uint32, lpNumberOfCharsRead, pInputControl uintptr) int32 {
	panic(todo(""))
	return int32(C.ReadConsoleW(C.HANDLE(hConsoleInput), C.LPVOID(unsafe.Pointer(lpBuffer)), C.ulong(nNumberOfCharsToRead), (*C.ulong)(unsafe.Pointer(lpNumberOfCharsRead)), C.LPVOID(pInputControl)))
}

// BOOL WINAPI WriteConsoleW(
//   _In_             HANDLE  hConsoleOutput,
//   _In_       const VOID    *lpBuffer,
//   _In_             DWORD   nNumberOfCharsToWrite,
//   _Out_opt_        LPDWORD lpNumberOfCharsWritten,
//   _Reserved_       LPVOID  lpReserved
// );
func XWriteConsoleW(t *TLS, hConsoleOutput, lpBuffer uintptr, nNumberOfCharsToWrite uint32, lpNumberOfCharsWritten, lpReserved uintptr) int32 {
	panic(todo(""))
	return int32(C.WriteConsoleW(C.HANDLE(hConsoleOutput), unsafe.Pointer(lpBuffer), C.ulong(nNumberOfCharsToWrite), (*C.ulong)(unsafe.Pointer(lpNumberOfCharsWritten)), (C.LPVOID)(unsafe.Pointer(lpReserved))))
}

// BOOL ResetEvent(
//   HANDLE hEvent
// );
func XResetEvent(t *TLS, hEvent uintptr) int32 {
	panic(todo(""))
	return int32(C.ResetEvent(C.HANDLE(hEvent)))
}

// BOOL WINAPI PeekConsoleInput(
//   _In_  HANDLE        hConsoleInput,
//   _Out_ PINPUT_RECORD lpBuffer,
//   _In_  DWORD         nLength,
//   _Out_ LPDWORD       lpNumberOfEventsRead
// );
func XPeekConsoleInputW(t *TLS, hConsoleInput, lpBuffer uintptr, nLength uint32, lpNumberOfEventsRead uintptr) int32 {
	panic(todo(""))
	return int32(C.PeekConsoleInput(C.HANDLE(hConsoleInput), (*C.struct__INPUT_RECORD)(unsafe.Pointer(lpBuffer)), C.ulong(nLength), (*C.ulong)(unsafe.Pointer(lpNumberOfEventsRead))))
}
