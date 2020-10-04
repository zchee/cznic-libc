// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build libc.ccgo

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
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"modernc.org/libc/sys/types"
)

var (
	// msvcrt.dll
	printfAddr uintptr
	sscanf     uintptr

	// kernel32.dll
	cancelSynchronousIo uintptr

	// user32.dll
	wsprintfA uintptr

	// netapi32.lib
	netUserGetInfo uintptr
	netGetDCName   uintptr
)

func init() {
	mustLinkDll("msvcrt.dll", []linkFunc{
		{"printf", &printfAddr},
		{"sscanf", &sscanf},
	})
	mustLinkDll("kernel32.dll", []linkFunc{
		{"CancelSynchronousIo", &cancelSynchronousIo},
	})
	mustLinkDll("user32.dll", []linkFunc{
		{"wsprintfA", &wsprintfA},
	})
	mustLinkDll("netapi32.dll", []linkFunc{
		{"NetUserGetInfo", &netUserGetInfo},
		{"NetGetDCName", &netGetDCName},
	})
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

func X___errno_location(t *TLS) uintptr {
	return uintptr(C.__ccgo_errno_location())
}

func X__builtin_abort(t *TLS) {
	C.abort()
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

// int putc(int c, FILE *stream);
func Xputc(t *TLS, c int32, fp uintptr) int32 {
	return int32(C.putc(C.int(c), (*C.FILE)(unsafe.Pointer(fp))))
}

// int fputs(const char *s, FILE *stream);
func Xfputs(t *TLS, s, stream uintptr) int32 {
	panic(todo(""))
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

// BOOL SetFileTime(
//   HANDLE         hFile,
//   const FILETIME *lpCreationTime,
//   const FILETIME *lpLastAccessTime,
//   const FILETIME *lpLastWriteTime
// );
func XSetFileTime(t *TLS, hFile uintptr, lpCreationTime, lpLastAccessTime, lpLastWriteTime uintptr) int32 {
	return int32(C.SetFileTime(C.HANDLE(hFile), (*C.struct__FILETIME)(unsafe.Pointer(lpCreationTime)), (*C.struct__FILETIME)(unsafe.Pointer(lpLastAccessTime)), (*C.struct__FILETIME)(unsafe.Pointer(lpLastWriteTime))))
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

// int _setmode (int fd, int mode);
func X_setmode(t *TLS, fd, mode int32) int32 {
	return int32(C._setmode(C.int(fd), C.int(mode)))
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

// int _fileno(FILE *stream);
func X_fileno(t *TLS, stream uintptr) int32 {
	return int32(C._fileno((*C.FILE)(unsafe.Pointer(stream))))
}

func Xvfprintf(t *TLS, stream, format, ap uintptr) int32 {
	return int32(sysv(t, fprintf, stream, format, ap))
}

// void rewind(FILE *stream);
func Xrewind(t *TLS, stream uintptr) {
	C.rewind((*C.struct__iobuf)(unsafe.Pointer(stream)))
}

// int fputc(int c, FILE *stream);
func Xfputc(t *TLS, c int32, stream uintptr) int32 {
	panic(todo(""))
}

// int fgetc(FILE *stream);
func Xfgetc(t *TLS, stream uintptr) int32 {
	panic(todo(""))
}

// uint16_t htons(uint16_t hostshort);
func Xhtons(t *TLS, hostshort uint16) uint16 {
	panic(todo(""))
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

func X_controlfp(t *TLS, _ ...interface{}) uint32 {
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
