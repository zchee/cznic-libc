// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"os"
	"strings"
	"sync/atomic"
	"syscall"
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

var (
	msvcrt   = syscall.NewLazyDLL("msvcrt.dll")
	_access  = msvcrt.NewProc("_access")
	_isatty  = msvcrt.NewProc("_isatty")
	_setmode = msvcrt.NewProc("_setmode")

	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	getSystemInfo = kernel32.NewProc("GetSystemInfo")
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

func (f file) fflush(t *TLS) int32 {
	return 0 //TODO
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
	panic(todo(""))
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
	panic(todo(""))
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
	panic(todo(""))
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
func XFormatMessageW(t *TLS, dwFlagsAndAttributes uint32, lpSource uintptr, dwMessageId, dwLanguageId uint32, lpBuffer uintptr, nSize uint32, Arguments uintptr) uint32 {
	panic(todo(""))
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
	panic(todo(""))
}

// BOOL GetFileAttributesExW(
//   LPCWSTR                lpFileName,
//   GET_FILEEX_INFO_LEVELS fInfoLevelId,
//   LPVOID                 lpFileInformation
// );
func XGetFileAttributesExW(t *TLS, lpFileName uintptr, fInfoLevelId uint32, lpFileInformation uintptr) int32 {
	panic(todo(""))
}

// DWORD GetFileAttributesW(
//   LPCWSTR lpFileName
// );
func XGetFileAttributesW(t *TLS, lpFileName uintptr) uint32 {
	panic(todo(""))
}

// DWORD GetFileSize(
//   HANDLE  hFile,
//   LPDWORD lpFileSizeHigh
// );
func XGetFileSize(t *TLS, hFile, lpFileSizeHigh uintptr) uint32 {
	panic(todo(""))
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
	panic(todo(""))
}

// DWORD GetLastError();
func XGetLastError(t *TLS) uint32 {
	panic(todo(""))
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
	syscall.Syscall(getSystemInfo.Addr(), 1, lpSystemInfo, 0, 0)
}

// void GetSystemTime(LPSYSTEMTIME lpSystemTime);
func XGetSystemTime(t *TLS, lpSystemTime uintptr) {
	panic(todo(""))
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
	panic(todo(""))
}

// BOOL GetVersionExA(
//   LPOSVERSIONINFOA lpVersionInformation
// );
func XGetVersionExA(t *TLS, lpVersionInformation uintptr) int32 {
	panic(todo(""))
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
	panic(todo(""))
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
	panic(todo(""))
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
	panic(todo(""))
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
	panic(todo(""))
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
	panic(todo(""))
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
	panic(todo(""))
}

// BOOL WriteFile(
//   HANDLE       hFile,
//   LPCVOID      lpBuffer,
//   DWORD        nNumberOfBytesToWrite,
//   LPDWORD      lpNumberOfBytesWritten,
//   LPOVERLAPPED lpOverlapped
// );
func XWriteFile(t *TLS, hFile, lpBuffer uintptr, nNumberOfBytesToWrite uint32, lpNumberOfBytesWritten, lpOverlapped uintptr) int32 {
	panic(todo(""))
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
	n, _, err := syscall.Syscall(_access.Addr(), 2, pathname, uintptr(mode), 0)
	if err != 0 {
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
	n, _, err := syscall.Syscall(_isatty.Addr(), 1, uintptr(fd), 0, 0)
	if err != 0 {
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
	n, _, err := syscall.Syscall(_setmode.Addr(), 2, uintptr(fd), uintptr(mode), 0)
	if err != 0 {
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
	panic(todo(""))
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