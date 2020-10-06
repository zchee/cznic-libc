// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build libc.cgo

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

*/
import "C"

import (
	"os"
	"unicode/utf16"
	"unsafe"

	"modernc.org/libc/sys/types"
)

var (
	// msvcrt.dll
	printfAddr procAddr
	sscanf     procAddr

	// kernel32.dll
	cancelSynchronousIo procAddr
)

func init() {
	mustLinkDll("msvcrt.dll", []linkFunc{
		{"printf", &printfAddr},
		{"sscanf", &sscanf},
	})
	mustLinkDll("kernel32.dll", []linkFunc{
		{"CancelSynchronousIo", &cancelSynchronousIo},
	})
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

// int _wunlink(
//    const wchar_t *filename
// );
func X_wunlink(t *TLS, filename uintptr) int32 {
	panic(todo(""))
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

func Xread(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xatof(t *TLS, _ ...interface{}) float64 {
	panic(todo(""))
}
