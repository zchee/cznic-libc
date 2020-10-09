// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

/*

#include <aclapi.h>
#include <fcntl.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"modernc.org/libc/sys/types"
)

// Keep these outside of the var block otherwise go generate will miss them.
var X__imp__environ = uintptr(unsafe.Pointer(C.__imp__environ))

const (
	INVALID_HANDLE_VALUE = ^(uintptr(0))
)

type (
	long     = int32
	longlong = int64
	ulong    = uint32
)

type procAddr uintptr

var (
	threads   = map[uintptr]*TLS{}
	threadsMu sync.Mutex

	// msvcrt.dll
	_open     procAddr
	_snprintf procAddr
	calloc    procAddr
	fflush    procAddr
	fprintf   procAddr
	free      procAddr
	localtime procAddr
	malloc    procAddr
	realloc   procAddr
	rename    procAddr

	// ntdll.dll
	rtlGetVersion procAddr

	// user32.dll
	wsprintfA procAddr

	// netapi32.lib
	netGetDCName   procAddr
	netUserGetInfo procAddr

	// kernel32.dll
	areFileApisANSI      procAddr
	createFileA          procAddr
	createFileW          procAddr
	formatMessageW       procAddr
	lockFileEx           procAddr
	createFileMappingW   procAddr
	deleteFileW          procAddr
	flushFileBuffers     procAddr
	getCurrentProcessId  procAddr
	getFileAttributesA   procAddr
	getFileAttributesW   procAddr
	getFileAttributesExW procAddr
	getFileSize          procAddr
	getFullPathNameW     procAddr
)

func init() {
	mustLinkDll("kernel32.dll", []linkFunc{
		{"AreFileApisANSI", &areFileApisANSI},
		{"CreateFileA", &createFileA},
		{"CreateFileW", &createFileW},
		{"FormatMessageW", &formatMessageW},
		{"LockFileEx", &lockFileEx},
		{"CreateFileMappingW", &createFileMappingW},
		{"DeleteFileW", &deleteFileW},
		{"FlushFileBuffers", &flushFileBuffers},
		{"GetCurrentProcessId", &getCurrentProcessId},
		{"GetFileAttributesA", &getFileAttributesA},
		{"GetFileAttributesW", &getFileAttributesW},
		{"GetFileAttributesExW", &getFileAttributesExW},
		{"GetFileSize", &getFileSize},
		{"GetFullPathNameW", &getFullPathNameW},
	})
	mustLinkDll("msvcrt.dll", []linkFunc{
		{"_open", &_open},
		{"_snprintf", &_snprintf},
		{"calloc", &calloc},
		{"fflush", &fflush},
		{"fprintf", &fprintf},
		{"free", &free},
		{"localtime", &localtime},
		{"malloc", &malloc},
		{"realloc", &realloc},
		{"rename", &rename},
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
	p    *procAddr
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

		*v.p = procAddr(p)
	}
}

type TLS struct {
	//TODO errnop    uintptr
	ID        int32
	done      chan struct{}
	exitCode  uint32
	hThread   uintptr
	lastError syscall.Errno
	obj       uintptr
	stack     stackHeader

	locked bool
}

func NewTLS() *TLS {
	id := atomic.AddInt32(&tid, 1)
	t := &TLS{ID: id, done: make(chan struct{})}
	//TODO t.errnop = mustCalloc(t, types.Size_t(unsafe.Sizeof(int32(0))))
	t.obj = addObject(t)
	t.hThread = mustMalloc(t, types.Size_t(unsafe.Sizeof(uintptr(0))))
	*(*uintptr)(unsafe.Pointer(t.hThread)) = t.obj
	threadsMu.Lock()
	threads[t.hThread] = t
	trc("len(threads): %v, hThread %#x", len(threads), t.hThread) //TODO-
	threadsMu.Unlock()
	return t
}

func (t *TLS) Close() {
	//TODO Xfree(t, t.errnop)
	Xfree(t, t.hThread)
	removeObject(t.obj)
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

// void free(void *ptr);
func Xfree(t *TLS, p uintptr) {
	sys(t, free, p)
}

// void *malloc(size_t size);
func Xmalloc(t *TLS, n types.Size_t) uintptr {
	return sys(t, malloc, n)
}

// void *calloc(size_t nmemb, size_t size);
func Xcalloc(t *TLS, n, size types.Size_t) uintptr {
	return sys(t, calloc, n, size)
}

// void *realloc(void *ptr, size_t size);
func Xrealloc(t *TLS, ptr uintptr, size types.Size_t) uintptr {
	return sys(t, realloc, ptr, size)
}

func Environ() uintptr {
	return uintptr(C.__ccgo_environ())
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

// int printf(const char *format, ...);
func Xprintf(t *TLS, format, args uintptr) int32 {
	panic(todo(""))
	// return int32(sysv(t, printfAddr, format, args))
}

// void abort(void);
func Xabort(t *TLS) {
	C.abort()
}

// int snprintf(char *str, size_t size, const char *format, ...);
func Xsnprintf(t *TLS, str uintptr, size types.Size_t, format, args uintptr) (r int32) {
	panic(todo(""))
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

func sysv(t *TLS, proc procAddr, args ...interface{}) uintptr {
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

func sys(t *TLS, proc procAddr, args ...interface{}) uintptr {
	n, _ := sys2(t, proc, args...)
	return n
}

func sys2(t *TLS, proc procAddr, args ...interface{}) (r uintptr, err error) {
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
		r, _, t.lastError = syscall.Syscall(uintptr(proc), na0, a[0], a[1], a[2])
	case 6:
		r, _, t.lastError = syscall.Syscall6(uintptr(proc), na0, a[0], a[1], a[2], a[3], a[4], a[5])
	case 9:
		r, _, t.lastError = syscall.Syscall9(uintptr(proc), na0, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
	case 12:
		r, _, t.lastError = syscall.Syscall12(uintptr(proc), na0, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11])
	case 15:
		r, _, t.lastError = syscall.Syscall15(uintptr(proc), na0, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14])
	case 18:
		r, _, t.lastError = syscall.Syscall18(uintptr(proc), na0, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15], a[16], a[17])
	default:
		panic(todo("", na))
	}
	if t.lastError != 0 {
		if dmesgs {
			dmesg("%v: FAIL %v\n\t%v:\n\t%v:", origin(3), t.lastError, origin(4), origin(5))
		}
		C.SetLastError(C.ulong(t.lastError)) //TODO-
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
	return sys(t, localtime, (sourceTime))
}

// int fprintf(FILE *stream, const char *format, ...);
func Xfprintf(t *TLS, stream, format, args uintptr) int32 {
	return int32(sysv(t, fprintf, stream, format, args))
}

// __acrt_iob_func
func X__acrt_iob_func(t *TLS, fd uint32) uintptr {
	return uintptr(unsafe.Pointer(C.__acrt_iob_func(C.uint(fd))))
}

// int fflush(FILE *stream);
func Xfflush(t *TLS, stream uintptr) int32 {
	return int32(sys(t, fflush, stream))
}

// long _InterlockedCompareExchange(
//    long volatile * Destination,
//    long Exchange,
//    long Comparand
// );
func X_InterlockedCompareExchange(t *TLS, Destination uintptr, Exchange, Comparand long) long {
	r := atomic.LoadInt32((*int32)(unsafe.Pointer(Destination)))
	atomic.CompareAndSwapInt32((*int32)(unsafe.Pointer(Destination)), Comparand, Exchange)
	return r
}

// int rename(const char *oldpath, const char *newpath);
func Xrename(t *TLS, oldpath, newpath uintptr) int32 {
	return int32(sys(t, rename, oldpath, newpath))
}

// BOOL AreFileApisANSI();
func XAreFileApisANSI(t *TLS) int32 {
	return int32(sys(t, areFileApisANSI))
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
	return sys(t, createFileA, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
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
	r := sys(t, createFileW, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
	if dmesgs {
		dmesg("%v: %q: %v", origin(1), goWideString(lpFileName), int(r))
	}
	return r
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
	return sys(t, createFileMappingW, hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName)
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
	r := int32(sys(t, deleteFileW, lpFileName))
	if dmesgs && r == 0 {
		dmesg("%v: %q: %v", origin(1), goWideString(lpFileName), r)
	}
	return r
}

// BOOL FlushFileBuffers(
//   HANDLE hFile
// );
func XFlushFileBuffers(t *TLS, hFile uintptr) int32 {
	return int32(sys(t, flushFileBuffers, hFile))
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
	return uint32(sys(t, getCurrentProcessId))
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
	return uint32(sys(t, getFileAttributesA, lpFileName))
}

// DWORD GetFileAttributesW(
//   LPCWSTR lpFileName
// );
func XGetFileAttributesW(t *TLS, lpFileName uintptr) uint32 {
	return uint32(sys(t, getFileAttributesW, lpFileName))
}

// BOOL GetFileAttributesExW(
//   LPCWSTR                lpFileName,
//   GET_FILEEX_INFO_LEVELS fInfoLevelId,
//   LPVOID                 lpFileInformation
// );
func XGetFileAttributesExW(t *TLS, lpFileName uintptr, fInfoLevelId uint32, lpFileInformation uintptr) int32 {
	if dmesgs {
		dmesg("%v: %q", origin(1), goWideString(lpFileName))
	}
	return int32(sys(t, getFileAttributesExW, lpFileName, fInfoLevelId, lpFileInformation))
}

// DWORD GetFileSize(
//   HANDLE  hFile,
//   LPDWORD lpFileSizeHigh
// );
func XGetFileSize(t *TLS, hFile, lpFileSizeHigh uintptr) uint32 {
	return uint32(sys(t, getFileSize, hFile, lpFileSizeHigh))
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
	return uint32(sys(t, getFullPathNameW, lpFileName, nBufferLength, lpBuffer, lpFilePart))
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

// void GetSystemInfo(
//   LPSYSTEM_INFO lpSystemInfo
// );
func XGetSystemInfo(t *TLS, lpSystemInfo uintptr) {
	C.GetSystemInfo((*C.struct__SYSTEM_INFO)(unsafe.Pointer(lpSystemInfo)))
}

// void GetSystemTime(LPSYSTEMTIME lpSystemTime);
func XGetSystemTime(t *TLS, lpSystemTime uintptr) {
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
	return uint32(C.GetTempPathW(C.ulong(nBufferLength), (*C.ushort)(unsafe.Pointer(lpBuffer))))
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

// LPVOID HeapAlloc(
//   HANDLE hHeap,
//   DWORD  dwFlags,
//   SIZE_T dwBytes
// );
func XHeapAlloc(t *TLS, hHeap uintptr, dwFlags uint32, dwBytes types.Size_t) uintptr {
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
	//TODO- return int32(C.LockFileEx(C.HANDLE(hFile), C.ulong(dwFlags), C.ulong(dwReserved), C.ulong(nNumberOfBytesToLockLow), C.ulong(nNumberOfBytesToLockHigh), (*C.struct__OVERLAPPED)(unsafe.Pointer(lpOverlapped))))
	return int32(sys(t, lockFileEx, hFile, dwFlags, dwReserved, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh, lpOverlapped))
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
	return int32(C.atoi((*C.char)(unsafe.Pointer(nptr))))
}

// char *strncpy(char *dest, const char *src, size_t n)
func Xstrncpy(t *TLS, dest, src uintptr, n types.Size_t) (r uintptr) {
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
	return int32(C.FlushViewOfFile(C.LPCVOID(lpBaseAddress), C.ulonglong(dwNumberOfBytesToFlush)))
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
	return int32(C.isatty(C.int(fd)))
}

// BOOL IsDebuggerPresent();
func XIsDebuggerPresent(t *TLS) int32 {
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
	return uintptr(unsafe.Pointer(C.strcat((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)))))
}

// char *strerror(int errnum);
func Xstrerror(t *TLS, errnum int32) uintptr {
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
	return int32(C.DuplicateHandle(C.HANDLE(hSourceProcessHandle), C.HANDLE(hSourceHandle), C.HANDLE(hTargetProcessHandle), (*C.HANDLE)(unsafe.Pointer(lpTargetHandle)), C.ulong(dwDesiredAccess), C.int(bInheritHandle), C.ulong(dwOptions)))
}

// HANDLE GetCurrentProcess();
func XGetCurrentProcess(t *TLS) uintptr {
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
	return int32(C.WriteConsoleW(C.HANDLE(hConsoleOutput), unsafe.Pointer(lpBuffer), C.ulong(nNumberOfCharsToWrite), (*C.ulong)(unsafe.Pointer(lpNumberOfCharsWritten)), (C.LPVOID)(unsafe.Pointer(lpReserved))))
}

// BOOL ResetEvent(
//   HANDLE hEvent
// );
func XResetEvent(t *TLS, hEvent uintptr) int32 {
	return int32(C.ResetEvent(C.HANDLE(hEvent)))
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

// int _commit(
//    int fd
// );
func X_commit(t *TLS, fd int32) int32 {
	return int32(C._commit(C.int(fd)))
}

// int _stat64(const char *path, struct __stat64 *buffer);
func X_stat64(t *TLS, path, buffer uintptr) int32 {
	return int32(C._stat64((*C.char)(unsafe.Pointer(path)), (*C.struct__stat64)(unsafe.Pointer(buffer))))
}

// int _chsize(
//    int fd,
//    long size
// );
func X_chsize(t *TLS, fd int32, size long) int32 {
	return int32(C._chsize(C.int(fd), C.long(size)))
}

// int ferror(FILE *stream);
func Xferror(t *TLS, stream uintptr) int32 {
	return int32(C.ferror((*C.struct__iobuf)(unsafe.Pointer(stream))))
}

// int _snprintf(char *str, size_t size, const char *format, ...);
func X_snprintf(t *TLS, str uintptr, size types.Size_t, format, args uintptr) int32 {
	return int32(sysv(t, _snprintf, str, size, format, args))
}

// intptr_t _findfirst64i32(
//    const char *filespec,
//    struct _finddata64i32_t *fileinfo
// );
func X_findfirst64i32(t *TLS, filespec, fileinfo uintptr) types.Intptr_t {
	return types.Intptr_t(C._findfirst64i32((*C.char)(unsafe.Pointer(filespec)), (*C.struct__finddata64i32_t)(unsafe.Pointer(fileinfo))))
}

// int _findnext64i32(
//    intptr_t handle,
//    struct _finddata64i32_t *fileinfo
// );
func X_findnext64i32(t *TLS, handle types.Intptr_t, fileinfo uintptr) int32 {
	return int32(C._findnext64i32(C.longlong(handle), (*C.struct__finddata64i32_t)(unsafe.Pointer(fileinfo))))
}

// int _findclose(
//    intptr_t handle
// );
func X_findclose(t *TLS, handle types.Intptr_t) int32 {
	return int32(C._findclose(C.longlong(handle)))
}

// DWORD GetEnvironmentVariableA(
//   LPCSTR lpName,
//   LPSTR  lpBuffer,
//   DWORD  nSize
// );
func XGetEnvironmentVariableA(t *TLS, lpName, lpBuffer uintptr, nSize uint32) uint32 {
	return uint32(C.GetEnvironmentVariableA((*C.char)(unsafe.Pointer(lpName)), (*C.char)(unsafe.Pointer(lpBuffer)), C.ulong(nSize)))
}

// int open(const char *pathname, int flags, ...);
func Xopen(t *TLS, pathname uintptr, flags int32, args uintptr) int32 {
	return int32(sysv(t, _open, pathname, flags, args))
}

// int _close(
//    int fd
// );
func Xclose(t *TLS, fd int32) int32 {
	return int32(C.close(C.int(fd)))
}

// int _fstat64(
//    int fd,
//    struct __stat64 *buffer
// );
func X_fstat64(t *TLS, fd int32, buffer uintptr) int32 {
	return int32(C._fstat64(C.int(fd), (*C.struct__stat64)(unsafe.Pointer(buffer))))
}

// HANDLE CreateEventA(
//   LPSECURITY_ATTRIBUTES lpEventAttributes,
//   BOOL                  bManualReset,
//   BOOL                  bInitialState,
//   LPCSTR                lpName
// );
func XCreateEventA(t *TLS, lpEventAttributes uintptr, bManualReset, bInitialState int32, lpName uintptr) uintptr {
	return uintptr(C.CreateEventA((*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpEventAttributes)), C.int(bManualReset), C.int(bInitialState), (*C.char)(unsafe.Pointer(lpName))))
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

// UINT WINAPI GetConsoleCP(void);
func XGetConsoleCP(t *TLS) uint32 {
	return uint32(C.GetConsoleCP())
}

// BOOL WINAPI SetConsoleMode(
//   _In_ HANDLE hConsoleHandle,
//   _In_ DWORD  dwMode
// );
func XSetConsoleMode(t *TLS, hConsoleHandle uintptr, dwMode uint32) int32 {
	return int32(C.SetConsoleMode(C.HANDLE(hConsoleHandle), C.ulong(dwMode)))
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

// BOOL WINAPI CancelSynchronousIo(
//   _In_ HANDLE hThread
// );
func XCancelSynchronousIo(t *TLS, hThread uintptr) int32 {
	panic(todo(""))
	// return int32(sys(t, cancelSynchronousIo, hThread))
}

func X_endthreadex(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_beginthread(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// uintptr_t _beginthreadex( // NATIVE CODE
//    void *security,
//    unsigned stack_size,
//    unsigned ( __stdcall *start_address )( void * ),
//    void *arglist,
//    unsigned initflag,
//    unsigned *thrdaddr
// );
func X_beginthreadex(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD GetCurrentThreadId();
func XGetCurrentThreadId(t *TLS) uint32 {
	return uint32(t.ID)
}

// HANDLE CreateThread(
//   LPSECURITY_ATTRIBUTES   lpThreadAttributes,
//   SIZE_T                  dwStackSize,
//   LPTHREAD_START_ROUTINE  lpStartAddress,
//   __drv_aliasesMem LPVOID lpParameter,
//   DWORD                   dwCreationFlags,
//   LPDWORD                 lpThreadId
// );
func XCreateThread(t *TLS, lpThreadAttributes uintptr, dwStackSize types.Size_t, lpStartAddress, lpParameter uintptr, dwCreationFlags uint32, lpThreadId uintptr) uintptr {
	const CREATE_SUSPENDED = 0x00000004
	if dwCreationFlags&CREATE_SUSPENDED != 0 {
		panic(todo(""))
	}

	nt := NewTLS()
	go func() {
		nt.lockOSThread()
		nt.exitCode = (*(*func(*TLS, uintptr) uint32)(unsafe.Pointer(&lpStartAddress)))(nt, lpParameter)
		close(nt.done)
	}()
	return nt.hThread
}

// BOOL GetExitCodeThread(
//   HANDLE  hThread,
//   LPDWORD lpExitCode
// );
func XGetExitCodeThread(t *TLS, hThread, lpExitCode uintptr) int32 {
	panic(todo(""))
	return int32(C.GetExitCodeThread(C.HANDLE(hThread), (*C.ulong)(unsafe.Pointer(lpExitCode))))
}

// DWORD WaitForSingleObject(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds
// );
func XWaitForSingleObject(t *TLS, hHandle uintptr, dwMilliseconds uint32) uint32 {
	const (
		WAIT_OBJECT_0 = 0x00000000 // The state of the specified object is signaled.
		WAIT_TIMEOUT  = 0x00000102 // The time-out interval elapsed, and the object's state is nonsignaled.
	)
	threadsMu.Lock()
	if t2, ok := threads[hHandle]; ok {
		threadsMu.Unlock()
		select {
		case <-time.After(time.Duration(dwMilliseconds) * time.Millisecond):
			panic(todo("%#x", hHandle))
		case <-t2.done:
			return WAIT_OBJECT_0
		}
	}

	threadsMu.Unlock()
	return uint32(C.WaitForSingleObject(C.HANDLE(hHandle), C.ulong(dwMilliseconds)))
}

// BOOL CloseHandle(
//   HANDLE hObject
// );
func XCloseHandle(t *TLS, hObject uintptr) int32 {
	threadsMu.Lock()
	if t2, ok := threads[hObject]; ok {
		delete(threads, hObject)
		threadsMu.Unlock()
		t2.Close()
		return 1
	}

	threadsMu.Unlock()
	return int32(C.CloseHandle(C.HANDLE(hObject)))
}

// DWORD WaitForSingleObjectEx(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds,
//   BOOL   bAlertable
// );
func XWaitForSingleObjectEx(t *TLS, hHandle uintptr, dwMilliseconds uint32, bAlertable int32) uint32 {
	threadsMu.Lock()
	if _, ok := threads[hHandle]; ok {
		panic(todo("%#x", hHandle))
	}

	threadsMu.Unlock()
	return uint32(C.WaitForSingleObjectEx(C.HANDLE(hHandle), C.ulong(dwMilliseconds), C.int(bAlertable)))
}

// DWORD MsgWaitForMultipleObjectsEx(
//   DWORD        nCount,
//   const HANDLE *pHandles,
//   DWORD        dwMilliseconds,
//   DWORD        dwWakeMask,
//   DWORD        dwFlags
// );
func XMsgWaitForMultipleObjectsEx(t *TLS, nCount uint32, pHandles uintptr, dwMilliseconds, dwWakeMask, dwFlags uint32) uint32 {
	panic(todo(""))
	return uint32(C.MsgWaitForMultipleObjectsEx(C.ulong(nCount), (*C.HANDLE)(unsafe.Pointer(pHandles)), C.ulong(dwMilliseconds), C.ulong(dwWakeMask), C.ulong(dwFlags)))
}

// BOOL SetThreadPriority(
//   HANDLE hThread,
//   int    nPriority
// );
func XSetThreadPriority(t *TLS, hThread uintptr, nPriority int32) int32 {
	//TODO- return int32(C.SetThreadPriority(C.HANDLE(hThread), C.int(nPriority)))
	o := *(*uintptr)(unsafe.Pointer(hThread))
	if _, ok := getObject(o).(*TLS); !ok {
		panic(todo(""))
	}

	clearLastError()
	return 1
}

func clearLastError() {
	C.SetLastError(0)
}

func XPurgeComm(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XClearCommError(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// void DeleteCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XDeleteCriticalSection(t *TLS, lpCriticalSection uintptr) {
	C.DeleteCriticalSection((*C.struct__RTL_CRITICAL_SECTION)(unsafe.Pointer(lpCriticalSection)))
}

func XGetOverlappedResult(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// void EnterCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XEnterCriticalSection(t *TLS, lpCriticalSection uintptr) {
	C.EnterCriticalSection((*C.struct__RTL_CRITICAL_SECTION)(unsafe.Pointer(lpCriticalSection)))
}

// void LeaveCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XLeaveCriticalSection(t *TLS, lpCriticalSection uintptr) {
	C.LeaveCriticalSection((*C.struct__RTL_CRITICAL_SECTION)(unsafe.Pointer(lpCriticalSection)))
}

func XSetupComm(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetCommTimeouts(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// void InitializeCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XInitializeCriticalSection(t *TLS, lpCriticalSection uintptr) {
	C.InitializeCriticalSection((*C.struct__RTL_CRITICAL_SECTION)(unsafe.Pointer(lpCriticalSection)))
}

func XBuildCommDCBW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetCommState(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_strnicmp(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XEscapeCommFunction(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGetCommModemStatus(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL MoveFileW(
//   LPCWSTR lpExistingFileName,
//   LPCWSTR lpNewFileName
// );
func XMoveFileW(t *TLS, lpExistingFileName, lpNewFileName uintptr) int32 {
	return int32(C.MoveFileW((*C.ushort)(unsafe.Pointer(lpExistingFileName)), (*C.ushort)(unsafe.Pointer(lpNewFileName))))
}

// LPWSTR CharLowerW(
//   LPWSTR lpsz
// );
func XCharLowerW(t *TLS, lpsz uintptr) uintptr {
	return uintptr(unsafe.Pointer((C.CharLowerW((*C.ushort)(unsafe.Pointer(lpsz))))))
}

// BOOL CreateDirectoryW(
//   LPCWSTR                lpPathName,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes
// );
func XCreateDirectoryW(t *TLS, lpPathName, lpSecurityAttributes uintptr) int32 {
	return int32(C.CreateDirectoryW((*C.ushort)(unsafe.Pointer(lpPathName)), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpSecurityAttributes))))
}

// BOOL SetFileAttributesW(
//   LPCWSTR lpFileName,
//   DWORD   dwFileAttributes
// );
func XSetFileAttributesW(t *TLS, lpFileName uintptr, dwFileAttributes uint32) int32 {
	return int32(C.SetFileAttributesW((*C.ushort)(unsafe.Pointer(lpFileName)), C.ulong(dwFileAttributes)))
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

// BOOL CopyFileW(
//   LPCWSTR lpExistingFileName,
//   LPCWSTR lpNewFileName,
//   BOOL    bFailIfExists
// );
func XCopyFileW(t *TLS, lpExistingFileName, lpNewFileName uintptr, bFailIfExists int32) int32 {
	return int32(C.CopyFileW((*C.ushort)(unsafe.Pointer(lpExistingFileName)), (*C.ushort)(unsafe.Pointer(lpNewFileName)), C.int(bFailIfExists)))
}

// BOOL RemoveDirectoryW(
//   LPCWSTR lpPathName
// );
func XRemoveDirectoryW(t *TLS, lpPathName uintptr) int32 {
	return int32(C.RemoveDirectoryW((*C.ushort)(unsafe.Pointer(lpPathName))))
}

// HANDLE FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
func XFindFirstFileW(t *TLS, lpFileName, lpFindFileData uintptr) uintptr {
	return uintptr(C.FindFirstFileW((*C.ushort)(unsafe.Pointer(lpFileName)), (*C.struct__WIN32_FIND_DATAW)(unsafe.Pointer(lpFindFileData))))
}

// BOOL FindClose(HANDLE hFindFile);
func XFindClose(t *TLS, hFindFile uintptr) int32 {
	return int32(C.FindClose(C.HANDLE(hFindFile)))
}

// BOOL FindNextFileW(
//   HANDLE             hFindFile,
//   LPWIN32_FIND_DATAW lpFindFileData
// );
func XFindNextFileW(t *TLS, hFindFile, lpFindFileData uintptr) int32 {
	return int32(C.FindNextFileW(C.HANDLE(hFindFile), (*C.struct__WIN32_FIND_DATAW)(unsafe.Pointer(lpFindFileData))))
}

// DWORD GetLogicalDriveStringsA(
//   DWORD nBufferLength,
//   LPSTR lpBuffer
// );
func XGetLogicalDriveStringsA(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	return uint32(C.GetLogicalDriveStringsA(C.ulong(nBufferLength), (*C.char)(unsafe.Pointer(lpBuffer))))
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

// BOOL CreateHardLinkW(
//   LPCWSTR               lpFileName,
//   LPCWSTR               lpExistingFileName,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes
// );
func XCreateHardLinkW(t *TLS, lpFileName, lpExistingFileName, lpSecurityAttributes uintptr) int32 {
	return int32(C.CreateHardLinkW((*C.ushort)(unsafe.Pointer(lpFileName)), (*C.ushort)(unsafe.Pointer(lpExistingFileName)), (*C.struct__SECURITY_ATTRIBUTES)(unsafe.Pointer(lpSecurityAttributes))))
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

// int wcsncmp(
//    const wchar_t *string1,
//    const wchar_t *string2,
//    size_t count
// );
func Xwcsncmp(t *TLS, string1, string2 uintptr, count types.Size_t) int32 {
	return int32(C.wcsncmp((*C.ushort)(unsafe.Pointer(string1)), (*C.ushort)(unsafe.Pointer(string2)), C.size_t(count)))
}

func XMessageBeep(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XMessageBoxW(t *TLS, _ ...interface{}) int32 {
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

func XlstrlenW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGetProfilesDirectoryW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XNetApiBufferFree(t *TLS, _ ...interface{}) int32 {
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

func XGetWindowsDirectoryA(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
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

// BOOL GetSecurityDescriptorOwner(
//   PSECURITY_DESCRIPTOR pSecurityDescriptor,
//   PSID                 *pOwner,
//   LPBOOL               lpbOwnerDefaulted
// );
func XGetSecurityDescriptorOwner(t *TLS, pSecurityDescriptor, pOwner, lpbOwnerDefaulted uintptr) int32 {
	return int32(C.GetSecurityDescriptorOwner(C.PVOID(pSecurityDescriptor), (*C.PVOID)(unsafe.Pointer(pOwner)), (*C.int)(unsafe.Pointer(lpbOwnerDefaulted))))
}

// PSID_IDENTIFIER_AUTHORITY GetSidIdentifierAuthority(
//   PSID pSid
// );
func XGetSidIdentifierAuthority(t *TLS, pSid uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.GetSidIdentifierAuthority(C.PVOID(pSid))))
}

// BOOL ImpersonateSelf(
//   SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
// );
func XImpersonateSelf(t *TLS, ImpersonationLevel int32) int32 {
	return int32(C.ImpersonateSelf(C.SECURITY_IMPERSONATION_LEVEL(ImpersonationLevel)))
}

// BOOL OpenThreadToken(
//   HANDLE  ThreadHandle,
//   DWORD   DesiredAccess,
//   BOOL    OpenAsSelf,
//   PHANDLE TokenHandle
// );
func XOpenThreadToken(t *TLS, ThreadHandle uintptr, DesiredAccess uint32, OpenAsSelf int32, TokenHandle uintptr) int32 {
	panic(todo(""))
	return int32(C.OpenThreadToken(C.HANDLE(ThreadHandle), C.ulong(DesiredAccess), C.int(OpenAsSelf), (*C.HANDLE)(unsafe.Pointer(TokenHandle))))
}

// HANDLE GetCurrentThread();
func XGetCurrentThread(t *TLS) uintptr {
	//TODO- return uintptr(C.GetCurrentThread())
	return t.hThread
}

// BOOL RevertToSelf();
func XRevertToSelf(t *TLS) int32 {
	return int32(C.RevertToSelf())
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

// int _wcsicmp(
//    const wchar_t *string1,
//    const wchar_t *string2
// );
func Xwcsicmp(t *TLS, string1, string2 uintptr) int32 {
	return int32(C._wcsicmp((*C.ushort)(unsafe.Pointer(string1)), (*C.ushort)(unsafe.Pointer(string2))))
}

// BOOL SetCurrentDirectoryW(
//   LPCTSTR lpPathName
// );
func XSetCurrentDirectoryW(t *TLS, lpPathName uintptr) int32 {
	return int32(C.SetCurrentDirectoryW((*C.ushort)(unsafe.Pointer(lpPathName))))
}

// DWORD GetCurrentDirectory(
//   DWORD  nBufferLength,
//   LPWTSTR lpBuffer
// );
func XGetCurrentDirectoryW(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	return uint32(C.GetCurrentDirectoryW(C.ulong(nBufferLength), (*C.ushort)(unsafe.Pointer(lpBuffer))))
}

// BOOL GetFileInformationByHandle(
//   HANDLE                       hFile,
//   LPBY_HANDLE_FILE_INFORMATION lpFileInformation
// );
func XGetFileInformationByHandle(t *TLS, hFile, lpFileInformation uintptr) int32 {
	return int32(C.GetFileInformationByHandle(C.HANDLE(hFile), (*C.struct__BY_HANDLE_FILE_INFORMATION)(unsafe.Pointer(lpFileInformation))))
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

// wchar_t *wcschr(
//    const wchar_t *str,
//    wchar_t c
// );
func Xwcschr(t *TLS, str uintptr, c wchar_t) uintptr {
	return uintptr(unsafe.Pointer(C.wcschr((*C.ushort)(unsafe.Pointer(str)), C.ushort(c))))
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

// BOOL OpenProcessToken(
//   HANDLE  ProcessHandle,
//   DWORD   DesiredAccess,
//   PHANDLE TokenHandle
// );
func XOpenProcessToken(t *TLS, ProcessHandle uintptr, DesiredAccess uint32, TokenHandle uintptr) int32 {
	return int32(C.OpenProcessToken(C.HANDLE(ProcessHandle), C.ulong(DesiredAccess), (*C.HANDLE)(unsafe.Pointer(TokenHandle))))
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

// BOOL EqualSid(
//   PSID pSid1,
//   PSID pSid2
// );
func XEqualSid(t *TLS, pSid1, pSid2 uintptr) int32 {
	return int32(C.EqualSid(C.PVOID(pSid1), C.PVOID(pSid2)))
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

// HMODULE GetModuleHandleW(
//   LPCWSTR lpModuleName
// );
func XGetModuleHandleW(t *TLS, lpModuleName uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.GetModuleHandleW((*C.ushort)(unsafe.Pointer(lpModuleName)))))
}

// DWORD GetEnvironmentVariableW(
//   LPCWSTR lpName,
//   LPWSTR  lpBuffer,
//   DWORD   nSize
// );
func XGetEnvironmentVariableW(t *TLS, lpName, lpBuffer uintptr, nSize uint32) uint32 {
	return uint32(C.GetEnvironmentVariableW((*C.ushort)(unsafe.Pointer(lpName)), (*C.ushort)(unsafe.Pointer(lpBuffer)), C.ulong(nSize)))
}

// int lstrcmpiA(
//   LPCSTR lpString1,
//   LPCSTR lpString2
// );
func XlstrcmpiA(t *TLS, lpString1, lpString2 uintptr) int32 {
	return int32(C.lstrcmpiA((*C.char)(unsafe.Pointer(lpString1)), (*C.char)(unsafe.Pointer(lpString2))))
}

func XGetModuleFileNameA(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// UINT GetACP();
func XGetACP(t *TLS) uint32 {
	return uint32(C.GetACP())
}

// BOOL GetUserNameW(
//   LPWSTR  lpBuffer,
//   LPDWORD pcbBuffer
// );
func XGetUserNameW(t *TLS, lpBuffer, pcbBuffer uintptr) int32 {
	return int32(C.GetUserNameW((*C.ushort)(unsafe.Pointer(lpBuffer)), (*C.ulong)(unsafe.Pointer(pcbBuffer))))
}

// HMODULE LoadLibraryExW(
//   LPCWSTR lpLibFileName,
//   HANDLE  hFile,
//   DWORD   dwFlags
// );
func XLoadLibraryExW(t *TLS, lpLibFileName, hFile uintptr, dwFlags uint32) uintptr {
	return uintptr(unsafe.Pointer(C.LoadLibraryExW((*C.ushort)(unsafe.Pointer(lpLibFileName)), C.HANDLE(hFile), C.ulong(dwFlags))))
}

func Xwcscpy(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XwsprintfW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// ATOM RegisterClassW(
//   const WNDCLASSW *lpWndClass
// );
func XRegisterClassW(t *TLS, lpWndClass uintptr) int32 {
	return int32(C.RegisterClassW((*C.struct_tagWNDCLASSW)(unsafe.Pointer(lpWndClass))))
}

func XKillTimer(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDestroyWindow(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL UnregisterClassW(
//   LPCWSTR   lpClassName,
//   HINSTANCE hInstance
// );
func XUnregisterClassW(t *TLS, lpClassName, hInstance uintptr) int32 {
	return int32(C.UnregisterClassW((*C.ushort)(unsafe.Pointer(lpClassName)), (*C.struct_HINSTANCE__)(unsafe.Pointer(hInstance))))
}

func XPostMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetTimer(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
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

// LRESULT LRESULT DefWindowProcW(
//   HWND   hWnd,
//   UINT   Msg,
//   WPARAM wParam,
//   LPARAM lParam
// );
func XDefWindowProcW(t *TLS, _ ...interface{}) int64 {
	panic(todo(""))
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

func XGetMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XPostQuitMessage(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XTranslateMessage(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDispatchMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD SleepEx(
//   DWORD dwMilliseconds,
//   BOOL  bAlertable
// );
func XSleepEx(t *TLS, dwMilliseconds uint32, bAlertable int32) uint32 {
	return uint32(C.SleepEx(C.ulong(dwMilliseconds), C.int(bAlertable)))
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

func XGetShortPathNameW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL GetExitCodeProcess(
//   HANDLE  hProcess,
//   LPDWORD lpExitCode
// );
func XGetExitCodeProcess(t *TLS, hProcess, lpExitCode uintptr) int32 {
	return int32(C.GetExitCodeProcess(C.HANDLE(hProcess), (*C.ulong)(unsafe.Pointer(lpExitCode))))
}

// int _getpid( void );
func Xgetpid(t *TLS) int32 {
	return int32(C._getpid())
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

// long _InterlockedExchange(
//    long volatile * Target,
//    long Value
// );
func X_InterlockedExchange(t *TLS, Target uintptr, Value long) long {
	return long(C._InterlockedExchange((*C.long)(unsafe.Pointer(Target)), C.long(Value)))
}

func XTerminateThread(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL GetComputerNameW(
//   LPWSTR  lpBuffer,
//   LPDWORD nSize
// );
func XGetComputerNameW(t *TLS, lpBuffer, nSize uintptr) int32 {
	return int32(C.GetComputerNameW((*C.ushort)(unsafe.Pointer(lpBuffer)), (*C.ulong)(unsafe.Pointer(nSize))))
}

func Xgethostname(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSendMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xrecv(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWSAGetLastError(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xsend(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xclosesocket(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWspiapiFreeAddrInfo(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xshutdown(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xgetpeername(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWspiapiGetNameInfo(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XIN6_ADDR_EQUAL(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xgetsockname(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X__ccgo_in6addr_anyp(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XIN6_IS_ADDR_V4MAPPED(t *TLS, _ ...interface{}) int32 {
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

func XSetHandleInformation(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xbind(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xconnect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// uint16_t htons(uint16_t hostshort);
func Xhtons(t *TLS, hostshort uint16) uint16 {
	panic(todo(""))
}

func Xlisten(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xioctlsocket(t *TLS, _ ...interface{}) int32 {
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

func Xselect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGetWindowLongPtrW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetWindowLongPtrW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWSAAsyncSelect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xinet_ntoa(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func X_controlfp(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

// BOOL QueryPerformanceFrequency(
//   LARGE_INTEGER *lpFrequency
// );
func XQueryPerformanceFrequency(t *TLS, lpFrequency uintptr) int32 {
	return int32(C.QueryPerformanceFrequency((*C.LARGE_INTEGER)(unsafe.Pointer(lpFrequency))))
}

// void _ftime( struct _timeb *timeptr );
func X_ftime(t *TLS, timeptr uintptr) {
	C._ftime((*C.struct___timeb64)(unsafe.Pointer(timeptr)))
}

func Xgmtime(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeInitializeW(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

func XDdeCreateStringHandleW(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeNameService(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_snwprintf(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeQueryStringW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_wcsicmp(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeCreateDataHandle(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeAccessData(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeUnaccessData(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeUninitialize(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeConnect(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeFreeStringHandle(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegisterClassExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGlobalGetAtomNameW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSendMessageTimeoutW(t *TLS, _ ...interface{}) int64 {
	panic(todo(""))
}

func XGlobalAddAtomW(t *TLS, _ ...interface{}) uint16 {
	panic(todo(""))
}

func XEnumWindows(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XIsWindow(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGlobalDeleteAtom(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeGetLastError(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

func XDdeClientTransaction(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeAbandonTransaction(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeFreeDataHandle(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeGetData(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeDisconnect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegCloseKey(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegDeleteValueW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegEnumKeyExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegQueryValueExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegEnumValueW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegConnectRegistryW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegCreateKeyExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegOpenKeyExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegDeleteKeyW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegSetValueExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}
