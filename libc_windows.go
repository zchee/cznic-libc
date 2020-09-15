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

// int _fileno(FILE *stream); // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/fileno?view=vs-2019
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
//
// func __debugbreak(t *TLS) {
// 	panic(todo(""))
// }
//
// // int pclose(FILE *stream);
// func X_pclose(t *TLS, stream uintptr) int32 {
// 	panic(todo(""))
// }
//
// // int _setmode (int fd, int mode); // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/setmode?view=vs-2019
// func X_setmode(t *TLS, fd, mode int32) {
// 	panic(todo(""))
// }
//
// // HANDLE GetCurrentProcess(); // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
// func XGetCurrentProcess() windows.Handle {
// 	panic(todo(""))
// }
//
// // HMODULE LoadLibraryA(LPCSTR lpLibFileName); // https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
// func XLoadLibraryA(t *TLS, lpLibFileName uintptr) windows.Handle {
// 	panic(todo(""))
// }
//
// // FARPROC GetProcAddress(HMODULE hModule, LPCSTR  lpProcName); // https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
// func XGetProcAddress(t *TLS, hModule, lpProcName uintptr) uintptr {
// 	panic(todo(""))
// }
//
// // BOOL FreeLibrary(HMODULE hLibModule); // https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary
// func XFreeLibrary(t *TLS, hLibModule windows.Handle) int32 {
// 	panic(todo(""))
// }
//
// // long ftell(FILE *stream);
// func Xftell(t *TLS, stream uintptr) long {
// 	panic(todo(""))
// }
//
// // size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
// func Xfread(t *TLS, ptr uintptr, size, nmemb types.Size_t, stream uintptr) types.Size_t {
// 	panic(todo(""))
// }
//
// // BOOL SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime); // https://docs.microsoft.com/en-us/windows/win32/api/timezoneapi/nf-timezoneapi-systemtimetofiletime
// func XSystemTimeToFileTime(t *TLS, lpSystemTime, lpFileTime uintptr) int32 {
// 	panic(todo(""))
// }
//
// // HANDLE FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData); // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew
// func XFindFirstFileW(t *TLS, lpFileName, lpFindFileData uintptr) windows.Handle {
// 	panic(todo(""))
// }
//
// // BOOL FindClose(HANDLE hFindFile); // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findclose
// func XFindClose(t *TLS, hFindFile windows.Handle) int32 {
// 	panic(todo(""))
// }
//
// // int _stat64(const char *path, struct __stat64 *buffer); // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/stat-functions?view=vs-2019
// func X_stat64(t *TLS, path, buffer uintptr) int32 {
// 	panic(todo(""))
// }
//
// // int _mkdir(const char *dirname); // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/mkdir-wmkdir?view=vs-2019
// func X_mkdir(t *TLS, dirname uintptr) int32 {
// 	panic(todo(""))
// }
//
// // _CRTIMP extern int *__cdecl _errno(void); // /usr/share/mingw-w64/include/errno.h:17:
// func X_errno(t *TLS) uintptr {
// 	return t.errnop
// }
//
// // int _chmod( const char *filename, int pmode ); // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/chmod-wchmod?view=vs-2019
// func X_chmod(t *TLS, filename uintptr, pmode int32) int32 {
// 	panic(todo(""))
// }
//
// // size_t fwrite(const void *buffer, size_t size, size_t count, FILE *stream); // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/fwrite?view=vs-2019
// func Xfwrite(t *TLS, buffer uintptr, size, count types.Size_t, stream uintptr) types.Size_t {
// 	panic(todo(""))
// }
//
// // void GetSystemTime(LPSYSTEMTIME lpSystemTime); // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime
// func XGetSystemTime(t *TLS, lpSystemTime uintptr) {
// 	panic(todo(""))
// }
//
// // HANDLE CreateFileW( // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
// //   LPCWSTR               lpFileName,
// //   DWORD                 dwDesiredAccess,
// //   DWORD                 dwShareMode,
// //   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
// //   DWORD                 dwCreationDisposition,
// //   DWORD                 dwFlagsAndAttributes,
// //   HANDLE                hTemplateFile
// // );
// func XCreateFileW(t *TLS, lpFileName uintptr, dwDesiredAccess, dwShareMode uint32, lpSecurityAttributes uintptr, dwCreationDisposition, dwFlagsAndAttributes uint32, hTemplateFile windows.Handle) windows.Handle {
// 	panic(todo(""))
// }
//
// // BOOL SetFileTime( // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime
// //   HANDLE         hFile,
// //   const FILETIME *lpCreationTime,
// //   const FILETIME *lpLastAccessTime,
// //   const FILETIME *lpLastWriteTime
// // );
// func XSetFileTime(t *TLS, hFindFile windows.Handle, lpCreationTime, lpLastAccessTime, lpLastWriteTime uintptr) int32 {
// 	panic(todo(""))
// }
//
// // BOOL CloseHandle( // https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
// //   HANDLE hObject
// // );
// func XCloseHandle(t *TLS, hObject windows.Handle) int32 {
// 	panic(todo(""))
// }
//
// func Xopendir(tls *TLS, name uintptr) uintptr {
// 	panic(todo(""))
// }
//
// func Xreaddir(tls *TLS, dir uintptr) uintptr {
// 	panic(todo(""))
// }
//
// func Xclosedir(tls *TLS, dir uintptr) int32 {
// 	panic(todo(""))
// }
//
// // void _assert( // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/assert-macro-assert-wassert?view=vs-2019
// //    char const* message,
// //    char const* filename,
// //    unsigned line
// // );
// func X_assert(t *TLS, message, filename uintptr, line uint32) {
// 	panic(todo(""))
// }
//
// // int system( // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=vs-2019
// //    const char *command
// // );
// func Xsystem(t *TLS, command uintptr) int32 {
// 	panic(todo(""))
// }
//
// // int _unlink( // https://docs.microsoft.com/lv-lv/cpp/c-runtime-library/reference/unlink-wunlink?view=vs-2015
// //    const char *filename
// // );
// func X_unlink(t *TLS, filename uintptr) int32 {
// 	panic(todo(""))
// }
//
// // char *strdup(const char *s);
// func X_strdup(t *TLS, s uintptr) uintptr {
// 	return Xstrdup(t, s)
// }
//
// // int _access( // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/access-waccess?view=vs-2019
// //    const char *path,
// //    int mode
// // );
// func X_access(t *TLS, pathname uintptr, mode int32) int32 {
// 	panic(todo(""))
// }
//
// // int _wunlink( // https://docs.microsoft.com/lv-lv/cpp/c-runtime-library/reference/unlink-wunlink?view=vs-2015
// //    const wchar_t *filename
// // );
// func X_wunlink(t *TLS, filename uintptr) int32 {
// 	panic(todo(""))
// }
//
// // AreFileApisANSI
// func XAreFileApisANSI(t *TLS) {
// 	panic(todo(""))
// }
//
// // CreateFileA
// func XCreateFileA(t *TLS) {
// 	panic(todo(""))
// }
//
// // CreateFileMappingA
// func XCreateFileMappingA(t *TLS) {
// 	panic(todo(""))
// }
//
// // CreateFileMappingW
// func XCreateFileMappingW(t *TLS) {
// 	panic(todo(""))
// }
//
// // CreateMutexW
// func XCreateMutexW(t *TLS) {
// 	panic(todo(""))
// }
//
// // DebugBreak
// func XDebugBreak(t *TLS) {
// 	panic(todo(""))
// }
//
// // DeleteFileA
// func XDeleteFileA(t *TLS) {
// 	panic(todo(""))
// }
//
// // DeleteFileW
// func XDeleteFileW(t *TLS) {
// 	panic(todo(""))
// }
//
// // FlushFileBuffers
// func XFlushFileBuffers(t *TLS) {
// 	panic(todo(""))
// }
//
// // FlushViewOfFile
// func XFlushViewOfFile(t *TLS) {
// 	panic(todo(""))
// }
//
// // FormatMessageA
// func XFormatMessageA(t *TLS) {
// 	panic(todo(""))
// }
//
// // FormatMessageW
// func XFormatMessageW(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetConsoleScreenBufferInfo
// func XGetConsoleScreenBufferInfo(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetCurrentProcessId
// func XGetCurrentProcessId(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetDiskFreeSpaceA
// func XGetDiskFreeSpaceA(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetDiskFreeSpaceW
// func XGetDiskFreeSpaceW(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetFileAttributesA
// func XGetFileAttributesA(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetFileAttributesExW
// func XGetFileAttributesExW(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetFileAttributesW
// func XGetFileAttributesW(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetFileSize
// func XGetFileSize(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetFullPathNameA
// func XGetFullPathNameA(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetFullPathNameW
// func XGetFullPathNameW(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetLastError
// func XGetLastError(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetProcessHeap
// func XGetProcessHeap(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetStdHandle
// func XGetStdHandle(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetSystemInfo
// func XGetSystemInfo(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetSystemTimeAsFileTime
// func XGetSystemTimeAsFileTime(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetTempPathA
// func XGetTempPathA(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetTempPathW
// func XGetTempPathW(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetTickCount
// func XGetTickCount(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetVersionExA
// func XGetVersionExA(t *TLS) {
// 	panic(todo(""))
// }
//
// // GetVersionExW
// func XGetVersionExW(t *TLS) {
// 	panic(todo(""))
// }
//
// // HeapAlloc
// func XHeapAlloc(t *TLS) {
// 	panic(todo(""))
// }
//
// // HeapCompact
// func XHeapCompact(t *TLS) {
// 	panic(todo(""))
// }
//
// // HeapCreate
// func XHeapCreate(t *TLS) {
// 	panic(todo(""))
// }
//
// // HeapDestroy
// func XHeapDestroy(t *TLS) {
// 	panic(todo(""))
// }
//
// // HeapFree
// func XHeapFree(t *TLS) {
// 	panic(todo(""))
// }
//
// // HeapReAlloc
// func XHeapReAlloc(t *TLS) {
// 	panic(todo(""))
// }
//
// // HeapSize
// func XHeapSize(t *TLS) {
// 	panic(todo(""))
// }
//
// // HeapValidate
// func XHeapValidate(t *TLS) {
// 	panic(todo(""))
// }
//
// // LoadLibraryW
// func XLoadLibraryW(t *TLS) {
// 	panic(todo(""))
// }
//
// // LocalFree
// func XLocalFree(t *TLS) {
// 	panic(todo(""))
// }
//
// // LockFile
// func XLockFile(t *TLS) {
// 	panic(todo(""))
// }
//
// // LockFileEx
// func XLockFileEx(t *TLS) {
// 	panic(todo(""))
// }
//
// // MapViewOfFile
// func XMapViewOfFile(t *TLS) {
// 	panic(todo(""))
// }
//
// // MultiByteToWideChar
// func XMultiByteToWideChar(t *TLS) {
// 	panic(todo(""))
// }
//
// // OutputDebugStringA
// func XOutputDebugStringA(t *TLS) {
// 	panic(todo(""))
// }
//
// // OutputDebugStringW
// func XOutputDebugStringW(t *TLS) {
// 	panic(todo(""))
// }
//
// // QueryPerformanceCounter
// func XQueryPerformanceCounter(t *TLS) {
// 	panic(todo(""))
// }
//
// // ReadFile
// func XReadFile(t *TLS) {
// 	panic(todo(""))
// }
//
// // SetConsoleCtrlHandler
// func XSetConsoleCtrlHandler(t *TLS) {
// 	panic(todo(""))
// }
//
// // SetConsoleTextAttribute
// func XSetConsoleTextAttribute(t *TLS) {
// 	panic(todo(""))
// }
//
// // SetCurrentDirectoryW
// func XSetCurrentDirectoryW(t *TLS) {
// 	panic(todo(""))
// }
//
// // SetEndOfFile
// func XSetEndOfFile(t *TLS) {
// 	panic(todo(""))
// }
//
// // SetFilePointer
// func XSetFilePointer(t *TLS) {
// 	panic(todo(""))
// }
//
// // Sleep
// func XSleep(t *TLS) {
// 	panic(todo(""))
// }
//
// // UnlockFile
// func XUnlockFile(t *TLS) {
// 	panic(todo(""))
// }
//
// // UnlockFileEx
// func XUnlockFileEx(t *TLS) {
// 	panic(todo(""))
// }
//
// // UnmapViewOfFile
// func XUnmapViewOfFile(t *TLS) {
// 	panic(todo(""))
// }
//
// // WaitForSingleObject
// func XWaitForSingleObject(t *TLS) {
// 	panic(todo(""))
// }
//
// // WaitForSingleObjectEx
// func XWaitForSingleObjectEx(t *TLS) {
// 	panic(todo(""))
// }
//
// // WideCharToMultiByte
// func XWideCharToMultiByte(t *TLS) {
// 	panic(todo(""))
// }
//
// // WriteFile
// func XWriteFile(t *TLS) {
// 	panic(todo(""))
// }
//
// // _InterlockedCompareExchange
// func X_InterlockedCompareExchange(t *TLS) {
// 	panic(todo(""))
// }
//
// // __atomic_load_n
// func X__atomic_load_n(t *TLS) {
// 	panic(todo(""))
// }
//
// // __atomic_store_n
// func X__atomic_store_n(t *TLS) {
// 	panic(todo(""))
// }
//
// // __builtin_add_overflow
// func X__builtin_add_overflow(t *TLS) {
// 	panic(todo(""))
// }
//
// // __builtin_bswap16
// func X__builtin_bswap16(t *TLS) {
// 	panic(todo(""))
// }
//
// // __builtin_bswap32
// func X__builtin_bswap32(t *TLS) {
// 	panic(todo(""))
// }
//
// // __builtin_clzll
// func X__builtin_clzll(t *TLS) {
// 	panic(todo(""))
// }
//
// // __builtin_inff
// func X__builtin_inff(t *TLS) {
// 	panic(todo(""))
// }
//
// // __builtin_mul_overflow
// func X__builtin_mul_overflow(t *TLS) {
// 	panic(todo(""))
// }
//
// // __builtin_sub_overflow
// func X__builtin_sub_overflow(t *TLS) {
// 	panic(todo(""))
// }
//
// // _isatty
// func X_isatty(t *TLS) {
// 	panic(todo(""))
// }
//
// // _popen
// func X_popen(t *TLS) {
// 	panic(todo(""))
// }
//
// // getpid
// func Xgetpid(t *TLS) {
// 	panic(todo(""))
// }
//
// // localtime
// func Xlocaltime(t *TLS) {
// 	panic(todo(""))
// }
//
// // setvbuf
// func Xsetvbuf(t *TLS) {
// 	panic(todo(""))
// }
//
// // strtol
// func Xstrtol(t *TLS) {
// 	panic(todo(""))
// }

// AreFileApisANSI
func XAreFileApisANSI(t *TLS) {
	panic(todo(""))
}

// CloseHandle
func XCloseHandle(t *TLS) {
	panic(todo(""))
}

// CreateFileA
func XCreateFileA(t *TLS) {
	panic(todo(""))
}

// CreateFileMappingA
func XCreateFileMappingA(t *TLS) {
	panic(todo(""))
}

// CreateFileMappingW
func XCreateFileMappingW(t *TLS) {
	panic(todo(""))
}

// CreateFileW
func XCreateFileW(t *TLS) {
	panic(todo(""))
}

// CreateMutexW
func XCreateMutexW(t *TLS) {
	panic(todo(""))
}

// DebugBreak
func XDebugBreak(t *TLS) {
	panic(todo(""))
}

// DeleteFileA
func XDeleteFileA(t *TLS) {
	panic(todo(""))
}

// DeleteFileW
func XDeleteFileW(t *TLS) {
	panic(todo(""))
}

// FindClose
func XFindClose(t *TLS) {
	panic(todo(""))
}

// FindFirstFileW
func XFindFirstFileW(t *TLS) {
	panic(todo(""))
}

// FlushFileBuffers
func XFlushFileBuffers(t *TLS) {
	panic(todo(""))
}

// FlushViewOfFile
func XFlushViewOfFile(t *TLS) {
	panic(todo(""))
}

// FormatMessageA
func XFormatMessageA(t *TLS) {
	panic(todo(""))
}

// FormatMessageW
func XFormatMessageW(t *TLS) {
	panic(todo(""))
}

// FreeLibrary
func XFreeLibrary(t *TLS) {
	panic(todo(""))
}

// GetConsoleScreenBufferInfo
func XGetConsoleScreenBufferInfo(t *TLS) {
	panic(todo(""))
}

// GetCurrentProcess
func XGetCurrentProcess(t *TLS) {
	panic(todo(""))
}

// GetCurrentProcessId
func XGetCurrentProcessId(t *TLS) {
	panic(todo(""))
}

// GetDiskFreeSpaceA
func XGetDiskFreeSpaceA(t *TLS) {
	panic(todo(""))
}

// GetDiskFreeSpaceW
func XGetDiskFreeSpaceW(t *TLS) {
	panic(todo(""))
}

// GetFileAttributesA
func XGetFileAttributesA(t *TLS) {
	panic(todo(""))
}

// GetFileAttributesExW
func XGetFileAttributesExW(t *TLS) {
	panic(todo(""))
}

// GetFileAttributesW
func XGetFileAttributesW(t *TLS) {
	panic(todo(""))
}

// GetFileSize
func XGetFileSize(t *TLS) {
	panic(todo(""))
}

// GetFullPathNameA
func XGetFullPathNameA(t *TLS) {
	panic(todo(""))
}

// GetFullPathNameW
func XGetFullPathNameW(t *TLS) {
	panic(todo(""))
}

// GetLastError
func XGetLastError(t *TLS) {
	panic(todo(""))
}

// GetProcAddress
func XGetProcAddress(t *TLS) {
	panic(todo(""))
}

// GetProcessHeap
func XGetProcessHeap(t *TLS) {
	panic(todo(""))
}

// GetStdHandle
func XGetStdHandle(t *TLS) {
	panic(todo(""))
}

// GetSystemInfo
func XGetSystemInfo(t *TLS) {
	panic(todo(""))
}

// GetSystemTime
func XGetSystemTime(t *TLS) {
	panic(todo(""))
}

// GetSystemTimeAsFileTime
func XGetSystemTimeAsFileTime(t *TLS) {
	panic(todo(""))
}

// GetTempPathA
func XGetTempPathA(t *TLS) {
	panic(todo(""))
}

// GetTempPathW
func XGetTempPathW(t *TLS) {
	panic(todo(""))
}

// GetTickCount
func XGetTickCount(t *TLS) {
	panic(todo(""))
}

// GetVersionExA
func XGetVersionExA(t *TLS) {
	panic(todo(""))
}

// GetVersionExW
func XGetVersionExW(t *TLS) {
	panic(todo(""))
}

// HeapAlloc
func XHeapAlloc(t *TLS) {
	panic(todo(""))
}

// HeapCompact
func XHeapCompact(t *TLS) {
	panic(todo(""))
}

// HeapCreate
func XHeapCreate(t *TLS) {
	panic(todo(""))
}

// HeapDestroy
func XHeapDestroy(t *TLS) {
	panic(todo(""))
}

// HeapFree
func XHeapFree(t *TLS) {
	panic(todo(""))
}

// HeapReAlloc
func XHeapReAlloc(t *TLS) {
	panic(todo(""))
}

// HeapSize
func XHeapSize(t *TLS) {
	panic(todo(""))
}

// HeapValidate
func XHeapValidate(t *TLS) {
	panic(todo(""))
}

// LoadLibraryA
func XLoadLibraryA(t *TLS) {
	panic(todo(""))
}

// LoadLibraryW
func XLoadLibraryW(t *TLS) {
	panic(todo(""))
}

// LocalFree
func XLocalFree(t *TLS) {
	panic(todo(""))
}

// LockFile
func XLockFile(t *TLS) {
	panic(todo(""))
}

// LockFileEx
func XLockFileEx(t *TLS) {
	panic(todo(""))
}

// MapViewOfFile
func XMapViewOfFile(t *TLS) {
	panic(todo(""))
}

// MultiByteToWideChar
func XMultiByteToWideChar(t *TLS) {
	panic(todo(""))
}

// OutputDebugStringA
func XOutputDebugStringA(t *TLS) {
	panic(todo(""))
}

// OutputDebugStringW
func XOutputDebugStringW(t *TLS) {
	panic(todo(""))
}

// QueryPerformanceCounter
func XQueryPerformanceCounter(t *TLS) {
	panic(todo(""))
}

// ReadFile
func XReadFile(t *TLS) {
	panic(todo(""))
}

// SetConsoleCtrlHandler
func XSetConsoleCtrlHandler(t *TLS) {
	panic(todo(""))
}

// SetConsoleTextAttribute
func XSetConsoleTextAttribute(t *TLS) {
	panic(todo(""))
}

// SetCurrentDirectoryW
func XSetCurrentDirectoryW(t *TLS) {
	panic(todo(""))
}

// SetEndOfFile
func XSetEndOfFile(t *TLS) {
	panic(todo(""))
}

// SetFilePointer
func XSetFilePointer(t *TLS) {
	panic(todo(""))
}

// SetFileTime
func XSetFileTime(t *TLS) {
	panic(todo(""))
}

// Sleep
func XSleep(t *TLS) {
	panic(todo(""))
}

// SystemTimeToFileTime
func XSystemTimeToFileTime(t *TLS) {
	panic(todo(""))
}

// UnlockFile
func XUnlockFile(t *TLS) {
	panic(todo(""))
}

// UnlockFileEx
func XUnlockFileEx(t *TLS) {
	panic(todo(""))
}

// UnmapViewOfFile
func XUnmapViewOfFile(t *TLS) {
	panic(todo(""))
}

// WaitForSingleObject
func XWaitForSingleObject(t *TLS) {
	panic(todo(""))
}

// WaitForSingleObjectEx
func XWaitForSingleObjectEx(t *TLS) {
	panic(todo(""))
}

// WideCharToMultiByte
func XWideCharToMultiByte(t *TLS) {
	panic(todo(""))
}

// WriteFile
func XWriteFile(t *TLS) {
	panic(todo(""))
}

// _InterlockedCompareExchange
func X_InterlockedCompareExchange(t *TLS) {
	panic(todo(""))
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

// __builtin_inff
func X__builtin_inff(t *TLS) {
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

// _access
func X_access(t *TLS) {
	panic(todo(""))
}

// _assert
func X_assert(t *TLS) {
	panic(todo(""))
}

// _chmod
func X_chmod(t *TLS) {
	panic(todo(""))
}

// _errno
func X_errno(t *TLS) {
	panic(todo(""))
}

// _isatty
func X_isatty(t *TLS) {
	panic(todo(""))
}

// _mkdir
func X_mkdir(t *TLS) {
	panic(todo(""))
}

// _pclose
func X_pclose(t *TLS) {
	panic(todo(""))
}

// _popen
func X_popen(t *TLS) {
	panic(todo(""))
}

// _setmode
func X_setmode(t *TLS) {
	panic(todo(""))
}

// _stat64
func X_stat64(t *TLS) {
	panic(todo(""))
}

// _strdup
func X_strdup(t *TLS) {
	panic(todo(""))
}

// _unlink
func X_unlink(t *TLS) {
	panic(todo(""))
}

// _vsnwprintf
// // int _vsnwprintf(wchar_t *buffer, size_t count, const wchar_t *format, va_list argptr);
func X_vsnwprintf(t *TLS, buffer uintptr, count types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// _wunlink
func X_wunlink(t *TLS) {
	panic(todo(""))
}

// closedir
func Xclosedir(t *TLS) {
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

// fread
func Xfread(t *TLS) {
	panic(todo(""))
}

// ftell
func Xftell(t *TLS) {
	panic(todo(""))
}

// fwrite
func Xfwrite(t *TLS) {
	panic(todo(""))
}

// getpid
func Xgetpid(t *TLS) {
	panic(todo(""))
}

// isalnum
func Xisalnum(t *TLS) {
	panic(todo(""))
}

// isalpha
func Xisalpha(t *TLS) {
	panic(todo(""))
}

// isdigit
func Xisdigit(t *TLS) {
	panic(todo(""))
}

// isprint
func Xisprint(t *TLS) {
	panic(todo(""))
}

// isspace
func Xisspace(t *TLS) {
	panic(todo(""))
}

// localtime
func Xlocaltime(t *TLS) {
	panic(todo(""))
}

// opendir
func Xopendir(t *TLS) {
	panic(todo(""))
}

// readdir
func Xreaddir(t *TLS) {
	panic(todo(""))
}

// setvbuf
func Xsetvbuf(t *TLS) {
	panic(todo(""))
}

// strtol
func Xstrtol(t *TLS) {
	panic(todo(""))
}

// system
func Xsystem(t *TLS) {
	panic(todo(""))
}
