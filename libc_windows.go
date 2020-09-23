// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"unicode/utf16"
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

// Keep these outside of the var block otherwise go generate will miss them.
var X__imp__environ uintptr

var (
	// msvcrt.dll
	_access  uintptr
	_isatty  uintptr
	_setmode uintptr
	_stricmp uintptr

	// kernel32.dll
	closeHandle             uintptr
	createFileW             uintptr
	formatMessageW          uintptr
	getCurrentProcessId     uintptr
	getFileAttributesExW    uintptr
	getFullPathNameW        uintptr
	getSystemInfo           uintptr
	getVersionExA           uintptr
	localFree               uintptr
	multiByteToWideChar     uintptr
	readFile                uintptr
	wideCharToMultiByte     uintptr
	lockFileEx              uintptr
	unlockFileEx            uintptr
	getFileSize             uintptr
	getSystemTime           uintptr
	getTickCount            uintptr
	queryPerformanceCounter uintptr
	writeFile               uintptr
	flushFileBuffers        uintptr
	getFileAttributesW      uintptr
	deleteFileW             uintptr
	setEvent                uintptr
)

func init() {
	mustLinkDll("msvcrt.dll", []linkFunc{
		{"_access", &_access},
		{"_isatty", &_isatty},
		{"_setmode", &_setmode},
		{"_stricmp", &_stricmp},
	})
	mustLinkDll("kernel32.dll", []linkFunc{
		{"CloseHandle", &closeHandle},
		{"CreateFileW", &createFileW},
		{"FormatMessageW", &formatMessageW},
		{"GetCurrentProcessId", &getCurrentProcessId},
		{"GetFileAttributesExW", &getFileAttributesExW},
		{"GetFullPathNameW", &getFullPathNameW},
		{"GetSystemInfo", &getSystemInfo},
		{"GetVersionExA", &getVersionExA},
		{"LocalFree", &localFree},
		{"MultiByteToWideChar", &multiByteToWideChar},
		{"ReadFile", &readFile},
		{"WideCharToMultiByte", &wideCharToMultiByte},
		{"LockFileEx", &lockFileEx},
		{"UnlockFileEx", &unlockFileEx},
		{"GetFileSize", &getFileSize},
		{"GetSystemTime", &getSystemTime},
		{"GetTickCount", &getTickCount},
		{"QueryPerformanceCounter", &queryPerformanceCounter},
		{"WriteFile", &writeFile},
		{"FlushFileBuffers", &flushFileBuffers},
		{"GetFileAttributesW", &getFileAttributesW},
		{"DeleteFileW", &deleteFileW},
		{"SetEvent", &setEvent},
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

type file uintptr

func (f file) fd() int32 {
	if f == 0 { //TODO-
		return unistd.STDOUT_FILENO
	}

	return (*stdio.FILE)(unsafe.Pointer(f)).F_file
}

func (f file) setFd(fd int32) { (*stdio.FILE)(unsafe.Pointer(f)).F_file = fd }
func (f file) err() bool      { return (*stdio.FILE)(unsafe.Pointer(f)).F_flag&1 != 0 }
func (f file) setErr()        { (*stdio.FILE)(unsafe.Pointer(f)).F_flag |= 1 }

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

func (f file) fflush(t *TLS) int32 {
	return 0 //TODO
}

func fwrite(fd int32, b []byte) (int, error) {
	switch fd {
	case unistd.STDOUT_FILENO:
		return write(os.Stdout, b)
	case unistd.STDERR_FILENO:
		return write(os.Stderr, b)
	default:
		panic(todo("%v: %q", fd, b))
	}
}

func Xabort(t *TLS) {
	panic(todo(""))
}

// int fseek(FILE *stream, long offset, int whence);
func Xfseek(t *TLS, stream uintptr, offset long, whence int32) int32 {
	panic(todo(""))
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
		if dmesgs {
			dmesg("%v: %q %q: %v", origin(1), GoString(pathname), GoString(mode), err)
		}
		t.setErrno(err)
		return 0
	}

	if p := newFile(t, int32(fd)); p != 0 {
		if dmesgs {
			dmesg("%v: %q %q: ok", origin(1), GoString(pathname), GoString(mode))
		}
		return p
	}

	Xclose(t, int32(fd))
	t.setErrno(errno.ENOMEM)
	if dmesgs {
		dmesg("%v: %q %q: OOM", origin(1), GoString(pathname), GoString(mode))
	}
	return 0
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

// int _fileno(FILE *stream);
func X_fileno(t *TLS, stream uintptr) int32 {
	return file(stream).fd()
}

// int vsscanf(const char *str, const char *format, va_list ap);
func X__mingw_vsscanf(t *TLS, str, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfscanf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__mingw_vfscanf(t *TLS, stream, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfprintf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__mingw_vfprintf(t *TLS, stream, format, ap uintptr) int32 {
	return Xvfprintf(t, stream, format, ap)
}

// int vsprintf(char * restrict s, const char * restrict format, va_list arg);
func X__mingw_vsprintf(t *TLS, s, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsnprintf(char *str, size_t size, const char *format, va_list ap);
func X__mingw_vsnprintf(t *TLS, str uintptr, size types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vswscanf(const wchar_t *buffer, const wchar_t *format, va_list arglist);
func X__mingw_vswscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfwscanf(FILE *stream, const wchar_t *format, va_list argptr;);
func X__mingw_vfwscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
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

// // int __isoc99_sscanf(const char *str, const char *format, ...);
// func Xgnu_sscanf(t *TLS, str, format, va uintptr) int32 {
// 	return scanf(strings.NewReader(GoString(str)), format, va)
// }

// BOOL AreFileApisANSI();
func XAreFileApisANSI(t *TLS) int32 {
	panic(todo(""))
}

// BOOL CloseHandle(
//   HANDLE hObject
// );
func XCloseHandle(t *TLS, hObject uintptr) int32 {
	return int32(sys(t, closeHandle, hObject))
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
	r, err := sys2(t, createFileW, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile)
	if dmesgs {
		dmesg("%v: %q, access %#x, shared %#x, dispo %#x, attr %#x: %d %v", origin(1), goWideString(lpFileName), dwDesiredAccess, dwShareMode, dwCreationDisposition, dwFlagsAndAttributes, r, err)
	}
	return r
}

// HANDLE CreateMutexW(
//   LPSECURITY_ATTRIBUTES lpMutexAttributes,
//   BOOL                  bInitialOwner,
//   LPCWSTR               lpName
// );
func XCreateMutexW(t *TLS, lpMutexAttributes uintptr, bInitialOwner int32, lpName uintptr) uintptr {
	panic(todo(""))
}

// DebugBreak
func XDebugBreak(t *TLS) {
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
	return int32(sys(t, deleteFileW, lpFileName))
}

// BOOL FindClose(HANDLE hFindFile);
func XFindClose(t *TLS, hFindFile uintptr) int32 {
	panic(todo(""))
}

// HANDLE FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
func XFindFirstFileW(t *TLS, lpFileName, lpFindFileData uintptr) uintptr {
	panic(todo(""))
}

// BOOL FlushFileBuffers(
//   HANDLE hFile
// );
func XFlushFileBuffers(t *TLS, hFile uintptr) int32 {
	return int32(sys(t, flushFileBuffers, hFile))
}

// BOOL FlushViewOfFile(
//   LPCVOID lpBaseAddress,
//   SIZE_T  dwNumberOfBytesToFlush
// );
func XFlushViewOfFile(t *TLS, lpBaseAddress uintptr, dwNumberOfBytesToFlush types.Size_t) int32 {
	panic(todo(""))
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
	if dmesgs {
		var nargs uintptr
		if Arguments != 0 {
			nargs = *(*uintptr)(unsafe.Pointer(Arguments - 8))
		}
		dmesg("%v: %q nargs %v", GoString(lpSource), nargs)
	}
	return uint32(sysv(t, formatMessageW, dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments))
}

// BOOL FreeLibrary(HMODULE hLibModule);
func XFreeLibrary(t *TLS, hLibModule uintptr) int32 {
	panic(todo(""))
}

// BOOL WINAPI GetConsoleScreenBufferInfo(
//   _In_  HANDLE                      hConsoleOutput,
//   _Out_ PCONSOLE_SCREEN_BUFFER_INFO lpConsoleScreenBufferInfo
// );
func XGetConsoleScreenBufferInfo(t *TLS, hConsoleOutput, lpConsoleScreenBufferInfo uintptr) int32 {
	panic(todo(""))
}

// HANDLE GetCurrentProcess();
func XGetCurrentProcess(t *TLS) uintptr {
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
	panic(todo(""))
}

// BOOL GetFileAttributesExW(
//   LPCWSTR                lpFileName,
//   GET_FILEEX_INFO_LEVELS fInfoLevelId,
//   LPVOID                 lpFileInformation
// );
func XGetFileAttributesExW(t *TLS, lpFileName uintptr, fInfoLevelId uint32, lpFileInformation uintptr) int32 {
	return int32(sys(t, getFileAttributesExW, lpFileName, fInfoLevelId, lpFileInformation))
}

// DWORD GetFileAttributesW(
//   LPCWSTR lpFileName
// );
func XGetFileAttributesW(t *TLS, lpFileName uintptr) uint32 {
	return uint32(sys(t, getFileAttributesW, lpFileName))
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
	return uint32(t.lastError)
}

// FARPROC GetProcAddress(HMODULE hModule, LPCSTR  lpProcName);
func XGetProcAddress(t *TLS, hModule, lpProcName uintptr) uintptr {
	panic(todo(""))
}

// HANDLE GetProcessHeap();
func XGetProcessHeap(t *TLS) uintptr {
	panic(todo(""))
}

// HANDLE WINAPI GetStdHandle(
//   _In_ DWORD nStdHandle
// );
func XGetStdHandle(t *TLS, nStdHandle uint32) uintptr {
	panic(todo(""))
}

// void GetSystemInfo(
//   LPSYSTEM_INFO lpSystemInfo
// );
func XGetSystemInfo(t *TLS, lpSystemInfo uintptr) {
	sys(t, getSystemInfo, lpSystemInfo)
}

// void GetSystemTime(LPSYSTEMTIME lpSystemTime);
func XGetSystemTime(t *TLS, lpSystemTime uintptr) {
	sys(t, getSystemTime, lpSystemTime)
}

// void GetSystemTimeAsFileTime(
//   LPFILETIME lpSystemTimeAsFileTime
// );
func XGetSystemTimeAsFileTime(t *TLS, lpSystemTimeAsFileTime uintptr) {
	panic(todo(""))
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
}

// DWORD GetTickCount();
func XGetTickCount(t *TLS) uint32 {
	return uint32(sys(t, getTickCount))
}

// BOOL GetVersionExA(
//   LPOSVERSIONINFOA lpVersionInformation
// );
func XGetVersionExA(t *TLS, lpVersionInformation uintptr) int32 {
	return int32(sys(t, getVersionExA, lpVersionInformation))
}

// BOOL GetVersionExW(
//   LPOSVERSIONINFOW lpVersionInformation
// );
func XGetVersionExW(t *TLS, lpVersionInformation uintptr) int32 {
	panic(todo(""))
}

// LPVOID HeapAlloc(
//   HANDLE hHeap,
//   DWORD  dwFlags,
//   SIZE_T dwBytes
// );
func XHeapAlloc(t *TLS, hHeap uintptr, dwFlags uint32, dwBytes types.Size_t) uintptr {
	panic(todo(""))
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
	panic(todo(""))
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
	return sys(t, localFree, hMem)
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
func XLockFileEx(t *TLS, hFile uintptr, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh uint32, lpOverlapped uintptr) int32 {
	return int32(sys(t, lockFileEx, hFile, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh, lpOverlapped))
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
	return int32(sys(t, multiByteToWideChar, CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar))
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

// BOOL QueryPerformanceCounter(
//   LARGE_INTEGER *lpPerformanceCount
// );
func XQueryPerformanceCounter(t *TLS, lpPerformanceCount uintptr) int32 {
	return int32(sys(t, queryPerformanceCounter, lpPerformanceCount))
}

// BOOL ReadFile(
//   HANDLE       hFile,
//   LPVOID       lpBuffer,
//   DWORD        nNumberOfBytesToRead,
//   LPDWORD      lpNumberOfBytesRead,
//   LPOVERLAPPED lpOverlapped
// );
func XReadFile(t *TLS, hFile, lpBuffer uintptr, nNumberOfBytesToRead uint32, lpNumberOfBytesRead, lpOverlapped uintptr) int32 {
	n := sys(t, readFile, hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped)
	return int32(n)
}

// BOOL WINAPI SetConsoleCtrlHandler(
//   _In_opt_ PHANDLER_ROUTINE HandlerRoutine,
//   _In_     BOOL             Add
// );
func XSetConsoleCtrlHandler(t *TLS, HandlerRoutine uintptr, Add int32) int32 {
	return 1 //TODO
}

// BOOL WINAPI SetConsoleTextAttribute(
//   _In_ HANDLE hConsoleOutput,
//   _In_ WORD   wAttributes
// );
func XSetConsoleTextAttribute(t *TLS, hConsoleOutput uintptr, wAttributes uint16) int32 {
	panic(todo(""))
}

// BOOL SetCurrentDirectory(
//   LPCTSTR lpPathName
// );
func XSetCurrentDirectoryW(t *TLS, lpPathName uintptr) int32 {
	panic(todo(""))
}

// BOOL SetEndOfFile(
//   HANDLE hFile
// );
func XSetEndOfFile(t *TLS, hFile uintptr) int32 {
	panic(todo(""))
}

// DWORD SetFilePointer(
//   HANDLE hFile,
//   LONG   lDistanceToMove,
//   PLONG  lpDistanceToMoveHigh,
//   DWORD  dwMoveMethod
// );
func XSetFilePointer(t *TLS, hFile uintptr, lDistanceToMove long, lpDistanceToMoveHigh uintptr, dwMoveMethod uint32) uint32 {
	panic(todo(""))
}

// BOOL SetFileTime(
//   HANDLE         hFile,
//   const FILETIME *lpCreationTime,
//   const FILETIME *lpLastAccessTime,
//   const FILETIME *lpLastWriteTime
// );
func XSetFileTime(t *TLS, hFindFile uintptr, lpCreationTime, lpLastAccessTime, lpLastWriteTime uintptr) int32 {
	panic(todo(""))
}

// void Sleep(
//   DWORD dwMilliseconds
// );
func XSleep(t *TLS, dwMilliseconds uint32) {
	panic(todo(""))
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
	return int32(sys(t, unlockFileEx, hFile, dwReserved, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh, lpOverlapped))
}

// BOOL UnmapViewOfFile(
//   LPCVOID lpBaseAddress
// );
func XUnmapViewOfFile(t *TLS, lpBaseAddress uintptr) int32 {
	panic(todo(""))
}

// DWORD WaitForSingleObject(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds
// );
func XWaitForSingleObject(t *TLS, hHandle uintptr, dwMilliseconds uint32) uint32 {
	panic(todo(""))
}

// DWORD WaitForSingleObjectEx(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds,
//   BOOL   bAlertable
// );
func XWaitForSingleObjectEx(t *TLS, hHandle uintptr, dwMilliseconds uint32, bAlertable int32) uint32 {
	panic(todo(""))
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
	return int32(sys(t, wideCharToMultiByte, CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar))
}

// BOOL WriteFile(
//   HANDLE       hFile,
//   LPCVOID      lpBuffer,
//   DWORD        nNumberOfBytesToWrite,
//   LPDWORD      lpNumberOfBytesWritten,
//   LPOVERLAPPED lpOverlapped
// );
func XWriteFile(t *TLS, hFile, lpBuffer uintptr, nNumberOfBytesToWrite uint32, lpNumberOfBytesWritten, lpOverlapped uintptr) int32 {
	return int32(sys(t, writeFile, hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped))
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

// __acrt_iob_func
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

// __ms_vfscanf
// // int vfscanf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__ms_vfscanf(t *TLS, stream, format, ap uintptr) int32 {
	panic(todo(""))
}

// __ms_vfwscanf
// // int vfwscanf(FILE *stream, const wchar_t *format, va_list argptr;);
func X__ms_vfwscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// __ms_vscanf
// // int vscanf(const char *format, va_list ap);
func X__ms_vscanf(t *TLS, format, ap uintptr) int32 {
	panic(todo(""))
}

// __ms_vsnprintf
// // int vsnprintf(char *str, size_t size, const char *format, va_list ap);
func X__ms_vsnprintf(t *TLS, str uintptr, size types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// __ms_vsscanf
// int vsscanf(const char *str, const char *format, va_list ap);
func X__ms_vsscanf(t *TLS, str, format, ap uintptr) int32 {
	panic(todo(""))
}

// __ms_vswscanf
// // int vswscanf(const wchar_t *buffer, const wchar_t *format, va_list arglist);
func X__ms_vswscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// __ms_vwscanf
// // int vwscanf(const wchar_t * restrict format, va_list arg);
func X__ms_vwscanf(t *TLS, format, ap uintptr) int32 {
	panic(todo(""))
}

// int _access(
//    const char *path,
//    int mode
// );
func X_access(t *TLS, pathname uintptr, mode int32) int32 {
	n, err := sys2(t, _access, pathname, mode)
	if err != nil {
		t.setErrno(err)
		return -1
	}

	return int32(n)
}

// void _assert(
//    char const* message,
//    char const* filename,
//    unsigned line
// );
func X_assert(t *TLS, message, filename uintptr, line uint32) {
	panic(todo(""))
}

// int _chmod( const char *filename, int pmode );
func X_chmod(t *TLS, filename uintptr, pmode int32) int32 {
	panic(todo(""))
}

// _CRTIMP extern int *__cdecl _errno(void); // /usr/share/mingw-w64/include/errno.h:17:
func X_errno(t *TLS) uintptr {
	return t.errnop
}

// int _isatty( int fd );
func X_isatty(t *TLS, fd int32) int32 {
	n, err := sys2(t, _isatty, fd)
	if err != nil {
		t.setErrno(err)
		return 0
	}

	return int32(n)
}

// int _mkdir(const char *dirname);
func X_mkdir(t *TLS, dirname uintptr) int32 {
	panic(todo(""))
}

// int pclose(FILE *stream);
func X_pclose(t *TLS, stream uintptr) int32 {
	panic(todo(""))
}

// FILE *_popen(
//     const char *command,
//     const char *mode
// );
func X_popen(t *TLS, command, mode uintptr) uintptr {
	panic(todo(""))
}

// int _setmode (int fd, int mode);
func X_setmode(t *TLS, fd, mode int32) int32 {
	n, err := sys2(t, _setmode, fd, mode)
	if err != nil {
		t.setErrno(err)
		return -1
	}

	return int32(n)
}

// int _stat64(const char *path, struct __stat64 *buffer);
func X_stat64(t *TLS, path, buffer uintptr) int32 {
	panic(todo(""))
}

// char *strdup(const char *s);
func X_strdup(t *TLS, s uintptr) uintptr {
	return Xstrdup(t, s)
}

// int _unlink(
//    const char *filename
// );
func X_unlink(t *TLS, filename uintptr) int32 {
	panic(todo(""))
}

// _vsnwprintf
// // int _vsnwprintf(wchar_t *buffer, size_t count, const wchar_t *format, va_list argptr);
func X_vsnwprintf(t *TLS, buffer uintptr, count types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// int _wunlink(
//    const wchar_t *filename
// );
func X_wunlink(t *TLS, filename uintptr) int32 {
	panic(todo(""))
}

func Xclosedir(tls *TLS, dir uintptr) int32 {
	panic(todo(""))
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

// int fputs(const char *s, FILE *stream);
func Xfputs(t *TLS, s, stream uintptr) int32 {
	if _, err := fwrite(file(stream).fd(), GoBytes(s, int(Xstrlen(t, s)))); err != nil {
		return -1
	}

	return 0
}

// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
func Xfread(t *TLS, ptr uintptr, size, nmemb types.Size_t, stream uintptr) types.Size_t {
	//m, _, err := windows.Read(windows.Handle(file(stream).fd(),) uintptr(file(stream).fd()), ptr, uintptr(size*nmemb))
	n := size * nmemb
	m, err := windows.Read(windows.Handle(file(stream).fd()), (*RawMem)(unsafe.Pointer(ptr))[:n:n])
	if err != nil {
		file(stream).setErr()
		return 0
	}

	if dmesgs {
		dmesg("%v: %d %#x x %#x: %#x\n%s", origin(1), file(stream).fd(), size, nmemb, types.Size_t(m)/size, hex.Dump(GoBytes(ptr, int(m))))
		// dmesg("%v: %d %#x x %#x: %#x", origin(1), file(stream).fd(), size, nmemb, types.Size_t(m)/size)
	}
	return types.Size_t(m) / size
}

// long ftell(FILE *stream);
func Xftell(t *TLS, stream uintptr) long {
	panic(todo(""))
}

// size_t fwrite(const void *buffer, size_t size, size_t count, FILE *stream);
func Xfwrite(t *TLS, buffer uintptr, size, count types.Size_t, stream uintptr) types.Size_t {
	panic(todo(""))
}

// int _getpid( void );
func Xgetpid(t *TLS) int32 {
	panic(todo(""))
}

// struct tm *localtime( const time_t *sourceTime );
func Xlocaltime(t *TLS, sourceTime uintptr) uintptr {
	panic(todo(""))
}

func Xopendir(tls *TLS, name uintptr) uintptr {
	panic(todo(""))
}

func Xreaddir(tls *TLS, dir uintptr) uintptr {
	panic(todo(""))
}

// setvbuf
// int setvbuf(
//    FILE *stream,
//    char *buffer,
//    int mode,
//    size_t size
// );
func Xsetvbuf(t *TLS, stream, buffer uintptr, mode int32, size types.Size_t) int32 {
	return 0 //TODO
}

// int system(
//    const char *command
// );
func Xsystem(t *TLS, command uintptr) int32 {
	panic(todo(""))
}

func sysv(t *TLS, proc uintptr, args ...interface{}) uintptr { //TODO-
	va := args[len(args)-1].(uintptr)
	if va != 0 {
		args = args[:len(args)-1]
		va -= 8
		n := int(VaInt32(&va))
		for i := 0; i < n; i++ {
			args = append(args, VaInt64(&va))
		}
	}
	if dmesgs {
		dmesg("%v: %v", origin(1), args)
	}
	return sys(t, proc, args...)
}

func sys(t *TLS, proc uintptr, args ...interface{}) uintptr { //TODO-
	n, _ := sys2(t, proc, args...)
	return n
}

func sys2(t *TLS, proc uintptr, args ...interface{}) (r uintptr, err error) { //TODO-
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
		case int32:
			a[i] = uintptr(x)
		case int64:
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

type TLS struct {
	ID        int32
	errnop    uintptr
	lastError syscall.Errno
	stack     stackHeader
}

// char *setlocale(int category, const char *locale);
func Xsetlocale(t *TLS, category int32, locale uintptr) uintptr {
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

// int _stricmp(
//    const char *string1,
//    const char *string2
// );
func X_stricmp(t *TLS, string1, string2 uintptr) int32 {
	return int32(sys(t, _stricmp, string1, string2))
}

// BOOL SetEvent(
//   HANDLE hEvent
// );
func XSetEvent(t *TLS, hEvent uintptr) int32 {
	return int32(sys(t, setEvent, hEvent))
}

func XAccessCheck(t *TLS) {
	panic(todo(""))
}

func XBuildCommDCBW(t *TLS) {
	panic(todo(""))
}

func XCharLowerW(t *TLS) {
	panic(todo(""))
}

func XClearCommError(t *TLS) {
	panic(todo(""))
}

func XCopyFileW(t *TLS) {
	panic(todo(""))
}

func XCreateDirectoryW(t *TLS) {
	panic(todo(""))
}

func XCreateEventW(t *TLS) {
	panic(todo(""))
}

func XCreateHardLinkW(t *TLS) {
	panic(todo(""))
}

func XCreatePipe(t *TLS) {
	panic(todo(""))
}

func XCreateThread(t *TLS) {
	panic(todo(""))
}

func XCreateWindowExW(t *TLS) {
	panic(todo(""))
}

func XDdeAbandonTransaction(t *TLS) {
	panic(todo(""))
}

func XDdeAccessData(t *TLS) {
	panic(todo(""))
}

func XDdeClientTransaction(t *TLS) {
	panic(todo(""))
}

func XDdeConnect(t *TLS) {
	panic(todo(""))
}

func XDdeCreateDataHandle(t *TLS) {
	panic(todo(""))
}

func XDdeCreateStringHandleW(t *TLS) {
	panic(todo(""))
}

func XDdeDisconnect(t *TLS) {
	panic(todo(""))
}

func XDdeFreeDataHandle(t *TLS) {
	panic(todo(""))
}

func XDdeFreeStringHandle(t *TLS) {
	panic(todo(""))
}

func XDdeGetData(t *TLS) {
	panic(todo(""))
}

func XDdeGetLastError(t *TLS) {
	panic(todo(""))
}

func XDdeInitializeW(t *TLS) {
	panic(todo(""))
}

func XDdeNameService(t *TLS) {
	panic(todo(""))
}

func XDdeQueryStringW(t *TLS) {
	panic(todo(""))
}

func XDdeUnaccessData(t *TLS) {
	panic(todo(""))
}

func XDdeUninitialize(t *TLS) {
	panic(todo(""))
}

func XDefWindowProcW(t *TLS) {
	panic(todo(""))
}

func XDeleteCriticalSection(t *TLS) {
	panic(todo(""))
}

func XDestroyWindow(t *TLS) {
	panic(todo(""))
}

func XDeviceIoControl(t *TLS) {
	panic(todo(""))
}

func XDispatchMessageW(t *TLS) {
	panic(todo(""))
}

func XDuplicateHandle(t *TLS) {
	panic(todo(""))
}

func XEnterCriticalSection(t *TLS) {
	panic(todo(""))
}

func XEnumWindows(t *TLS) {
	panic(todo(""))
}

func XEqualSid(t *TLS) {
	panic(todo(""))
}

func XEscapeCommFunction(t *TLS) {
	panic(todo(""))
}

func XExitProcess(t *TLS) {
	panic(todo(""))
}

func XFindFirstFileExW(t *TLS) {
	panic(todo(""))
}

func XFindNextFileW(t *TLS) {
	panic(todo(""))
}

func XGetCommModemStatus(t *TLS) {
	panic(todo(""))
}

func XGetCommState(t *TLS) {
	panic(todo(""))
}

func XGetComputerNameW(t *TLS) {
	panic(todo(""))
}

func XGetConsoleMode(t *TLS) {
	panic(todo(""))
}

func XGetCurrentDirectoryW(t *TLS) {
	panic(todo(""))
}

func XGetCurrentThreadId(t *TLS) {
	panic(todo(""))
}

func XGetEnvironmentVariableA(t *TLS) {
	panic(todo(""))
}

func XGetEnvironmentVariableW(t *TLS) {
	panic(todo(""))
}

func XGetExitCodeProcess(t *TLS) {
	panic(todo(""))
}

func XGetExitCodeThread(t *TLS) {
	panic(todo(""))
}

func XGetFileInformationByHandle(t *TLS) {
	panic(todo(""))
}

func XGetFileSecurityW(t *TLS) {
	panic(todo(""))
}

func XGetFileType(t *TLS) {
	panic(todo(""))
}

func XGetLogicalDriveStringsA(t *TLS) {
	panic(todo(""))
}

func XGetMessageW(t *TLS) {
	panic(todo(""))
}

func XGetModuleFileNameA(t *TLS) {
	panic(todo(""))
}

func XGetModuleFileNameW(t *TLS) {
	panic(todo(""))
}

func XGetModuleHandleW(t *TLS) {
	panic(todo(""))
}

func XGetNamedSecurityInfoW(t *TLS) {
	panic(todo(""))
}

func XGetOverlappedResult(t *TLS) {
	panic(todo(""))
}

func XGetPrivateProfileStringA(t *TLS) {
	panic(todo(""))
}

func XGetProfilesDirectoryW(t *TLS) {
	panic(todo(""))
}

func XGetSecurityDescriptorOwner(t *TLS) {
	panic(todo(""))
}

func XGetShortPathNameW(t *TLS) {
	panic(todo(""))
}

func XGetSidIdentifierAuthority(t *TLS) {
	panic(todo(""))
}

func XGetTempFileNameW(t *TLS) {
	panic(todo(""))
}

func XGetTokenInformation(t *TLS) {
	panic(todo(""))
}

func XGetUserNameW(t *TLS) {
	panic(todo(""))
}

func XGetVolumeInformationA(t *TLS) {
	panic(todo(""))
}

func XGetVolumeInformationW(t *TLS) {
	panic(todo(""))
}

func XGetVolumeNameForVolumeMountPointW(t *TLS) {
	panic(todo(""))
}

func XGetWindowLongPtrW(t *TLS) {
	panic(todo(""))
}

func XGetWindowsDirectoryA(t *TLS) {
	panic(todo(""))
}

func XGlobalAddAtomW(t *TLS) {
	panic(todo(""))
}

func XGlobalDeleteAtom(t *TLS) {
	panic(todo(""))
}

func XGlobalGetAtomNameW(t *TLS) {
	panic(todo(""))
}

func XIN6_ADDR_EQUAL(t *TLS) {
	panic(todo(""))
}

func XIN6_IS_ADDR_V4MAPPED(t *TLS) {
	panic(todo(""))
}

func XImpersonateSelf(t *TLS) {
	panic(todo(""))
}

func XInitializeCriticalSection(t *TLS) {
	panic(todo(""))
}

func XIsDebuggerPresent(t *TLS) {
	panic(todo(""))
}

func XIsWindow(t *TLS) {
	panic(todo(""))
}

func XKillTimer(t *TLS) {
	panic(todo(""))
}

func XLeaveCriticalSection(t *TLS) {
	panic(todo(""))
}

func XLoadLibraryExW(t *TLS) {
	panic(todo(""))
}

func XMessageBeep(t *TLS) {
	panic(todo(""))
}

func XMessageBoxW(t *TLS) {
	panic(todo(""))
}

func XMoveFileW(t *TLS) {
	panic(todo(""))
}

func XMsgWaitForMultipleObjectsEx(t *TLS) {
	panic(todo(""))
}

func XNetApiBufferFree(t *TLS) {
	panic(todo(""))
}

func XNetGetDCName(t *TLS) {
	panic(todo(""))
}

func XNetUserGetInfo(t *TLS) {
	panic(todo(""))
}

func XOpenProcessToken(t *TLS) {
	panic(todo(""))
}

func XOpenThreadToken(t *TLS) {
	panic(todo(""))
}

func XPeekConsoleInputW(t *TLS) {
	panic(todo(""))
}

func XPeekMessageW(t *TLS) {
	panic(todo(""))
}

func XPeekNamedPipe(t *TLS) {
	panic(todo(""))
}

func XPostMessageW(t *TLS) {
	panic(todo(""))
}

func XPostQuitMessage(t *TLS) {
	panic(todo(""))
}

func XPurgeComm(t *TLS) {
	panic(todo(""))
}

func XQueryPerformanceFrequency(t *TLS) {
	panic(todo(""))
}

func XReadConsoleW(t *TLS) {
	panic(todo(""))
}

func XRegCloseKey(t *TLS) {
	panic(todo(""))
}

func XRegConnectRegistryW(t *TLS) {
	panic(todo(""))
}

func XRegCreateKeyExW(t *TLS) {
	panic(todo(""))
}

func XRegDeleteKeyW(t *TLS) {
	panic(todo(""))
}

func XRegDeleteValueW(t *TLS) {
	panic(todo(""))
}

func XRegEnumKeyExW(t *TLS) {
	panic(todo(""))
}

func XRegEnumValueW(t *TLS) {
	panic(todo(""))
}

func XRegOpenKeyExW(t *TLS) {
	panic(todo(""))
}

func XRegQueryValueExW(t *TLS) {
	panic(todo(""))
}

func XRegSetValueExW(t *TLS) {
	panic(todo(""))
}

func XRegisterClassExW(t *TLS) {
	panic(todo(""))
}

func XRegisterClassW(t *TLS) {
	panic(todo(""))
}

func XRemoveDirectoryW(t *TLS) {
	panic(todo(""))
}

func XResetEvent(t *TLS) {
	panic(todo(""))
}

func XRevertToSelf(t *TLS) {
	panic(todo(""))
}

func XSearchPathW(t *TLS) {
	panic(todo(""))
}

func XSendMessageTimeoutW(t *TLS) {
	panic(todo(""))
}

func XSendMessageW(t *TLS) {
	panic(todo(""))
}

func XSetCommState(t *TLS) {
	panic(todo(""))
}

func XSetCommTimeouts(t *TLS) {
	panic(todo(""))
}

func XSetConsoleMode(t *TLS) {
	panic(todo(""))
}

func XSetFileAttributesW(t *TLS) {
	panic(todo(""))
}

func XSetHandleInformation(t *TLS) {
	panic(todo(""))
}

func XSetThreadPriority(t *TLS) {
	panic(todo(""))
}

func XSetTimer(t *TLS) {
	panic(todo(""))
}

func XSetWindowLongPtrW(t *TLS) {
	panic(todo(""))
}

func XSetupComm(t *TLS) {
	panic(todo(""))
}

func XSleepEx(t *TLS) {
	panic(todo(""))
}

func XTerminateThread(t *TLS) {
	panic(todo(""))
}

func XTranslateMessage(t *TLS) {
	panic(todo(""))
}

func XUnregisterClassW(t *TLS) {
	panic(todo(""))
}

func XWSAAsyncSelect(t *TLS) {
	panic(todo(""))
}

func XWSAGetLastError(t *TLS) {
	panic(todo(""))
}

func XWSAStartup(t *TLS) {
	panic(todo(""))
}

func XWriteConsoleW(t *TLS) {
	panic(todo(""))
}

func XWspiapiFreeAddrInfo(t *TLS) {
	panic(todo(""))
}

func XWspiapiGetAddrInfo(t *TLS) {
	panic(todo(""))
}

func XWspiapiGetNameInfo(t *TLS) {
	panic(todo(""))
}

func X_InterlockedExchange(t *TLS) {
	panic(todo(""))
}

func X__builtin_huge_val(t *TLS) {
	panic(todo(""))
}

func X__ccgo_in6addr_anyp(t *TLS) {
	panic(todo(""))
}

func X_beginthreadex(t *TLS) {
	panic(todo(""))
}

func X_controlfp(t *TLS) {
	panic(todo(""))
}

func X_endthreadex(t *TLS) {
	panic(todo(""))
}

func X_ftime(t *TLS) {
	panic(todo(""))
}

func X_snwprintf(t *TLS) {
	panic(todo(""))
}

func X_strnicmp(t *TLS) {
	panic(todo(""))
}

func X_wcsicmp(t *TLS) {
	panic(todo(""))
}

func X_wcsnicmp(t *TLS) {
	panic(todo(""))
}

func Xaccept(t *TLS) {
	panic(todo(""))
}

func Xbind(t *TLS) {
	panic(todo(""))
}

func Xclosesocket(t *TLS) {
	panic(todo(""))
}

func Xconnect(t *TLS) {
	panic(todo(""))
}

func Xgai_strerrorW(t *TLS) {
	panic(todo(""))
}

func Xgethostname(t *TLS) {
	panic(todo(""))
}

func Xgetpeername(t *TLS) {
	panic(todo(""))
}

func Xgetservbyname(t *TLS) {
	panic(todo(""))
}

func Xgetsockname(t *TLS) {
	panic(todo(""))
}

func Xgetsockopt(t *TLS) {
	panic(todo(""))
}

func Xgmtime(t *TLS) {
	panic(todo(""))
}

func Xinet_ntoa(t *TLS) {
	panic(todo(""))
}

func Xioctlsocket(t *TLS) {
	panic(todo(""))
}

func Xislower(t *TLS) {
	panic(todo(""))
}

func Xlisten(t *TLS) {
	panic(todo(""))
}

func XlstrcmpiA(t *TLS) {
	panic(todo(""))
}

func XlstrlenW(t *TLS) {
	panic(todo(""))
}

func Xputenv(t *TLS) {
	panic(todo(""))
}

func Xrecv(t *TLS) {
	panic(todo(""))
}

func Xselect(t *TLS) {
	panic(todo(""))
}

func Xsend(t *TLS) {
	panic(todo(""))
}

func Xsetsockopt(t *TLS) {
	panic(todo(""))
}

func Xshutdown(t *TLS) {
	panic(todo(""))
}

func Xsocket(t *TLS) {
	panic(todo(""))
}

func Xstrerror(t *TLS) {
	panic(todo(""))
}

func Xwcschr(t *TLS) {
	panic(todo(""))
}

func Xwcscmp(t *TLS) {
	panic(todo(""))
}

func Xwcscpy(t *TLS) {
	panic(todo(""))
}

func Xwcsicmp(t *TLS) {
	panic(todo(""))
}

func Xwcslen(t *TLS) {
	panic(todo(""))
}

func Xwcsncmp(t *TLS) {
	panic(todo(""))
}

func XwsprintfA(t *TLS) {
	panic(todo(""))
}

func XwsprintfW(t *TLS) {
	panic(todo(""))
}

func XGetConsoleCP(t *TLS) {
	panic(todo(""))
}

func XGetCurrentThread(t *TLS) {
	panic(todo(""))
}

func XGetACP(t *TLS) {
	panic(todo(""))
}

func XGetCommandLineW(t *TLS) {
	panic(todo(""))
}

func XAddAccessDeniedAce(t *TLS) {
	panic(todo(""))
}

func XAddAce(t *TLS) {
	panic(todo(""))
}

func XGetAce(t *TLS) {
	panic(todo(""))
}

func XGetAclInformation(t *TLS) {
	panic(todo(""))
}

func XGetFileSecurityA(t *TLS) {
	panic(todo(""))
}

func XGetLengthSid(t *TLS) {
	panic(todo(""))
}

func XGetSecurityDescriptorDacl(t *TLS) {
	panic(todo(""))
}

func XGetSidLengthRequired(t *TLS) {
	panic(todo(""))
}

func XGetSidSubAuthority(t *TLS) {
	panic(todo(""))
}

func XInitializeAcl(t *TLS) {
	panic(todo(""))
}

func XInitializeSid(t *TLS) {
	panic(todo(""))
}

func XRaiseException(t *TLS) {
	panic(todo(""))
}

func XSetErrorMode(t *TLS) {
	panic(todo(""))
}

func XSetNamedSecurityInfoA(t *TLS) {
	panic(todo(""))
}

func Xchmod(t *TLS) {
	panic(todo(""))
}

func Xsscanf(t *TLS) {
	panic(todo(""))
}

func Xwrite(t *TLS) {
	panic(todo(""))
}
