// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo

//go.generate echo package libc > ccgo.go
//go:generate go run generate.go
//go:generate go fmt ./...

package libc // import "modernc.org/libc"

import (
	"bufio"
	"os"
	"runtime"
	"unsafe"

	"modernc.org/libc/errno"
	"modernc.org/libc/langinfo"
	"modernc.org/libc/netinet/in"
	"modernc.org/libc/sys/socket"
	"modernc.org/libc/sys/types"
	"modernc.org/libc/termios"
)

/*

#cgo LDFLAGS: -lm -ldl

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <grp.h>
#include <langinfo.h>
#include <locale.h>
#include <math.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>

extern char **environ;

FILE *__ccgo_stdout, *__ccgo_stderr, *__ccgo_stdin;

void __ccgo_init() {
	__ccgo_stdout = stdout;
	__ccgo_stderr = stderr;
	__ccgo_stderr = stderr;
}

int __ccgo_printf(char *s) {
	return printf("%s", s);
}

int __ccgo_fprintf(FILE *stream, char *s) {
	return fprintf(stream, "%s", s);
}

int __ccgo_open64(char *pathname, int flags) {
	return open(pathname, flags);
}

int __ccgo_open64b(char *pathname, int flags, unsigned perm) {
	return open(pathname, flags, perm);
}

int __ccgo_fcntl64(int fd, int cmd) {
	return fcntl(fd, cmd);
}

int __ccgo_fcntl64b(int fd, int cmd, void *p) {
	return fcntl(fd, cmd, p);
}

int __ccgo_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
	return select(nfds, readfds, writefds, exceptfds, timeout);
}

void __ccgo_seterrno(int err) {
	errno = err;
}

const struct in6_addr *__ccgo_in6addr_anyp() {
	return &in6addr_any;
}

*/
import "C"

// Keep these outside of the var block otherwise go generate will miss them.
var Xstderr uintptr
var Xstdin uintptr
var Xstdout uintptr

func init() {
	C.__ccgo_init()
	Xstderr = uintptr(unsafe.Pointer(C.__ccgo_stderr))
	Xstdin = uintptr(unsafe.Pointer(C.__ccgo_stdin))
	Xstdout = uintptr(unsafe.Pointer(C.__ccgo_stdout))
}

func X__ccgo_in6addr_anyp(t *TLS) uintptr {
	return uintptr(unsafe.Pointer(C.__ccgo_in6addr_anyp()))
}

// int printf(const char *format, ...);
func Xprintf(t *TLS, s, args uintptr) int32 {
	b := printf(s, args)
	p := cString(t, string(b))

	defer Xfree(t, p)

	return int32(C.__ccgo_printf((*C.char)(unsafe.Pointer(p))))
}

// int fprintf(FILE *stream, const char *format, ...);
func Xfprintf(t *TLS, stream, format, args uintptr) int32 {
	b := printf(format, args)
	p := cString(t, string(b))

	defer Xfree(t, p)

	return int32(C.__ccgo_fprintf((*C.FILE)(unsafe.Pointer(stream)), (*C.char)(unsafe.Pointer(p))))
}

// int snprintf(char *str, size_t size, const char *format, ...);
func Xsnprintf(t *TLS, str uintptr, size types.Size_t, format, args uintptr) (r int32) {
	b := printf(format, args)
	if len(b) >= int(size) {
		b = b[:size-1]
	}
	r = int32(len(b))
	copy((*RawMem)(unsafe.Pointer(str))[:len(b)], b)
	*(*byte)(unsafe.Pointer(str + uintptr(len(b)))) = 0
	return r
}

func Xabs(t *TLS, j int32) int32                  { return int32(C.abs(C.int(j))) }
func Xacos(t *TLS, x float64) float64             { return float64(C.acos(C.double(x))) }
func Xasin(t *TLS, x float64) float64             { return float64(C.asin(C.double(x))) }
func Xatan(t *TLS, x float64) float64             { return float64(C.atan(C.double(x))) }
func Xatan2(t *TLS, x, y float64) float64         { return float64(C.atan2(C.double(x), C.double(y))) }
func Xceil(t *TLS, x float64) float64             { return float64(C.ceil(C.double(x))) }
func Xcopysign(t *TLS, x, y float64) float64      { return float64(C.copysign(C.double(x), C.double(y))) }
func Xcopysignf(t *TLS, x, y float32) float32     { return float32(C.copysignf(C.float(x), C.float(y))) }
func Xcos(t *TLS, x float64) float64              { return float64(C.cos(C.double(x))) }
func Xcosf(t *TLS, x float32) float32             { return float32(C.cosf(C.float(x))) }
func Xcosh(t *TLS, x float64) float64             { return float64(C.cosh(C.double(x))) }
func Xexp(t *TLS, x float64) float64              { return float64(C.exp(C.double(x))) }
func Xfabs(t *TLS, x float64) float64             { return float64(C.fabs(C.double(x))) }
func Xfabsf(t *TLS, x float32) float32            { return float32(C.fabsf(C.float(x))) }
func Xfloor(t *TLS, x float64) float64            { return float64(C.floor(C.double(x))) }
func Xfmod(t *TLS, x, y float64) float64          { return float64(C.fmod(C.double(x), C.double(y))) }
func Xhypot(t *TLS, x, y float64) float64         { return float64(C.hypot(C.double(x), C.double(y))) }
func Xisnan(t *TLS, x float64) int32              { return int32(C.isnan(C.double(x))) }
func Xisnanf(t *TLS, x float32) int32             { return int32(C.isnanf(C.float(x))) }
func Xisnanl(t *TLS, x float64) int32             { return int32(C.isnan(C.double(x))) } // ccgo has to handle long double as double as Go does not support long double.
func Xldexp(t *TLS, x float64, exp int32) float64 { return float64(C.ldexp(C.double(x), C.int(exp))) }
func Xlog(t *TLS, x float64) float64              { return float64(C.log(C.double(x))) }
func Xlog10(t *TLS, x float64) float64            { return float64(C.log10(C.double(x))) }
func Xpow(t *TLS, x, y float64) float64           { return float64(C.pow(C.double(x), C.double(y))) }
func Xrand(t *TLS) int32                          { return int32(C.rand()) }
func Xround(t *TLS, x float64) float64            { return float64(C.round(C.double(x))) }
func Xsin(t *TLS, x float64) float64              { return float64(C.sin(C.double(x))) }
func Xsinf(t *TLS, x float32) float32             { return float32(C.sinf(C.float(x))) }
func Xsinh(t *TLS, x float64) float64             { return float64(C.sinh(C.double(x))) }
func Xsqrt(t *TLS, x float64) float64             { return float64(C.sqrt(C.double(x))) }
func Xtan(t *TLS, x float64) float64              { return float64(C.tan(C.double(x))) }
func Xtanh(t *TLS, x float64) float64             { return float64(C.tanh(C.double(x))) }

func Xfrexp(t *TLS, x float64, exp uintptr) float64 {
	return float64(C.frexp(C.double(x), (*C.int)(unsafe.Pointer(exp))))
}

func Xmodf(t *TLS, x float64, iptr uintptr) float64 {
	return float64(C.modf(C.double(x), (*C.double)(unsafe.Pointer(iptr))))
}

func Xrealloc(t *TLS, ptr uintptr, size types.Size_t) uintptr {
	return uintptr(C.realloc(unsafe.Pointer(ptr), C.size_t(size)))
}

func Xcalloc(t *TLS, n, size types.Size_t) uintptr {
	return uintptr(C.calloc(C.size_t(n), C.size_t(size)))
}

func Xfree(t *TLS, p uintptr)                { C.free(unsafe.Pointer(p)) }
func Xmalloc(t *TLS, n types.Size_t) uintptr { return uintptr(C.malloc(C.size_t(n))) }
func Xtzset(t *TLS)                          { C.tzset() }

func Xexit(t *TLS, status int32) {
	if len(Covered) != 0 {
		buf := bufio.NewWriter(os.Stdout)
		CoverReport(buf)
		buf.Flush()
	}
	// trc("pid %v exiting with status %v", os.Getpid(), status)
	C.exit(C.int(status))
}

func Start(main func(*TLS, int32, uintptr) int32) {
	runtime.LockOSThread()
	t := NewTLS()
	argv := mustCalloc(t, types.Size_t((len(os.Args)+1)*int(uintptrSize)))
	p := argv
	for _, v := range os.Args {
		s := mustCalloc(t, types.Size_t(len(v)+1))
		copy((*(*[1 << 20]byte)(unsafe.Pointer(s)))[:], v)
		*(*uintptr)(unsafe.Pointer(p)) = s
		p += uintptrSize
	}
	// wd, _ := os.Getwd()
	// trc("pid %v start %d %q, wd %q TCL_LIBRARY %q", os.Getpid(), len(os.Args), os.Args, wd, os.Getenv("TCL_LIBRARY"))
	Xexit(t, main(t, int32(len(os.Args)), argv))
}

// char *strncpy(char *dest, const char *src, size_t n)
func Xstrncpy(t *TLS, dest, src uintptr, n types.Size_t) uintptr {
	return uintptr(unsafe.Pointer(C.strncpy((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)), C.size_t(n))))
}

// int strcmp(const char *s1, const char *s2)
func Xstrcmp(t *TLS, s1, s2 uintptr) int32 {
	return int32(C.strcmp((*C.char)(unsafe.Pointer(s1)), (*C.char)(unsafe.Pointer(s2))))
}

// size_t strlen(const char *s)
func Xstrlen(t *TLS, s uintptr) types.Size_t {
	return types.Size_t(C.strlen((*C.char)(unsafe.Pointer(s))))
}

// char *strcat(char *dest, const char *src)
func Xstrcat(t *TLS, dest, src uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.strcat((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)))))
}

// int strncmp(const char *s1, const char *s2, size_t n)
func Xstrncmp(t *TLS, s1, s2 uintptr, n types.Size_t) int32 {
	return int32(C.strncmp((*C.char)(unsafe.Pointer(s1)), (*C.char)(unsafe.Pointer(s2)), C.size_t(n)))
}

// char *strcpy(char *dest, const char *src)
func Xstrcpy(t *TLS, dest, src uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.strcpy((*C.char)(unsafe.Pointer(dest)), (*C.char)(unsafe.Pointer(src)))))
}

// char *strchr(const char *s, int c)
func Xstrchr(t *TLS, s uintptr, c int32) uintptr {
	return uintptr(unsafe.Pointer(C.strchr((*C.char)(unsafe.Pointer(s)), C.int(c))))
}

// char *strrchr(const char *s, int c)
func Xstrrchr(t *TLS, s uintptr, c int32) uintptr {
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

// void *memchr(const void *s, int c, size_t n);
func Xmemchr(t *TLS, s uintptr, c int32, n types.Size_t) uintptr {
	return uintptr(unsafe.Pointer(C.memchr(unsafe.Pointer(s), C.int(c), C.size_t(n))))
}

// int getrusage(int who, struct rusage *usage);
func Xgetrusage(t *TLS, who int32, usage uintptr) int32 {
	return int32(C.getrusage(C.int(who), (*C.struct_rusage)(unsafe.Pointer(usage))))
}

// const unsigned short * * __ctype_b_loc (void);
func X__ctype_b_loc(t *TLS) uintptr {
	return uintptr(unsafe.Pointer(C.__ctype_b_loc()))
}

// char *fgets(char *s, int size, FILE *stream);
func Xfgets(t *TLS, s uintptr, size int32, stream uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.fgets((*C.char)(unsafe.Pointer(s)), C.int(size), (*C.FILE)(unsafe.Pointer(stream)))))
}

// int fflush(FILE *stream);
func Xfflush(t *TLS, stream uintptr) int32 {
	return int32(C.fflush((*C.FILE)(unsafe.Pointer(stream))))
}

// FILE *fopen(const char *pathname, const char *mode);
func Xfopen(t *TLS, pathname, mode uintptr) uintptr { return Xfopen64(t, pathname, mode) }

// FILE *fopen64(const char *pathname, const char *mode);
func Xfopen64(t *TLS, pathname, mode uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.fopen((*C.char)(unsafe.Pointer(pathname)), (*C.char)(unsafe.Pointer(mode)))))
}

// int fseek(FILE *stream, long offset, int whence);
func Xfseek(t *TLS, stream uintptr, offset long, whence int32) int32 {
	return int32(C.fseek((*C.FILE)(unsafe.Pointer(stream)), C.long(offset), C.int(whence)))
}

// long ftell(FILE *stream);
func Xftell(t *TLS, stream uintptr) long {
	return long(C.ftell((*C.FILE)(unsafe.Pointer(stream))))
}

// void rewind(FILE *stream);
func Xrewind(t *TLS, stream uintptr) {
	C.rewind((*C.FILE)(unsafe.Pointer(stream)))
}

// int fclose(FILE *stream);
func Xfclose(t *TLS, stream uintptr) int32 {
	return int32(C.fclose((*C.FILE)(unsafe.Pointer(stream))))
}

// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
func Xfread(t *TLS, ptr uintptr, size, nmemb types.Size_t, stream uintptr) types.Size_t {
	return types.Size_t(C.fread(unsafe.Pointer(ptr), C.size_t(size), C.size_t(nmemb), (*C.FILE)(unsafe.Pointer(stream))))
}

// int lstat(const char *pathname, struct stat *statbuf);
func Xlstat(t *TLS, pathname, statbuf uintptr) int32 { return Xlstat64(t, pathname, statbuf) }

// int lstat(const char *pathname, struct stat *statbuf);
func Xlstat64(t *TLS, pathname, statbuf uintptr) int32 {
	return int32(C.lstat((*C.char)(unsafe.Pointer(pathname)), (*C.struct_stat)(unsafe.Pointer(statbuf))))
}

// int stat(const char *pathname, struct stat *statbuf);
func Xstat(t *TLS, pathname, statbuf uintptr) int32 { return Xstat64(t, pathname, statbuf) }

// int stat(const char *pathname, struct stat *statbuf);
func Xstat64(t *TLS, pathname, statbuf uintptr) int32 {
	return int32(C.stat((*C.char)(unsafe.Pointer(pathname)), (*C.struct_stat)(unsafe.Pointer(statbuf))))
}

// int mkdir(const char *path, mode_t mode);
func Xmkdir(t *TLS, path uintptr, mode types.Mode_t) int32 {
	return int32(C.mkdir((*C.char)(unsafe.Pointer(path)), C.mode_t(mode)))
}

// int symlink(const char *target, const char *linkpath);
func Xsymlink(t *TLS, target, linkpath uintptr) int32 {
	return int32(C.symlink((*C.char)(unsafe.Pointer(target)), (*C.char)(unsafe.Pointer(linkpath))))
}

// int * __errno_location(void);
func X__errno_location(t *TLS) uintptr {
	return uintptr(unsafe.Pointer(C.__errno_location()))
}

// int chmod(const char *pathname, mode_t mode)
func Xchmod(t *TLS, pathname uintptr, mode types.Mode_t) int32 {
	return int32(C.chmod((*C.char)(unsafe.Pointer(pathname)), C.mode_t(mode)))
}

// size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
func Xfwrite(t *TLS, ptr uintptr, size, nmemb types.Size_t, stream uintptr) types.Size_t {
	return types.Size_t(C.fwrite(unsafe.Pointer(ptr), C.size_t(size), C.size_t(nmemb), (*C.FILE)(unsafe.Pointer(stream))))
}

// time_t time(time_t *tloc);
func Xtime(t *TLS, tloc uintptr) types.Time_t {
	return types.Time_t(C.time((*C.time_t)(unsafe.Pointer(tloc))))
}

// int utimes(const char *filename, const struct timeval times[2]);
func Xutimes(t *TLS, filename, times uintptr) int32 {
	return int32(C.utimes((*C.char)(unsafe.Pointer(filename)), (*C.struct_timeval)(unsafe.Pointer(times))))
}

// int closedir(DIR *dirp);
func Xclosedir(t *TLS, dir uintptr) int32 {
	return int32(C.closedir((*C.DIR)(unsafe.Pointer(dir))))
}

// DIR *opendir(const char *name);
func Xopendir(t *TLS, name uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.opendir((*C.char)(unsafe.Pointer(name)))))
}

// struct dirent *readdir(DIR *dirp);
func Xreaddir64(t *TLS, dirp uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.readdir((*C.DIR)(unsafe.Pointer(dirp)))))
}

// ssize_t readlink(const char *restrict path, char *restrict buf, size_t bufsize);
func Xreadlink(t *TLS, path, buf uintptr, bufsize types.Size_t) types.Ssize_t {
	return types.Ssize_t(C.readlink((*C.char)(unsafe.Pointer(path)), (*C.char)(unsafe.Pointer(buf)), C.size_t(bufsize)))
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

// int system(const char *command);
func Xsystem(t *TLS, command uintptr) int32 {
	return int32(C.system((*C.char)(unsafe.Pointer(command))))
}

// int unlink(const char *pathname);
func Xunlink(t *TLS, pathname uintptr) int32 {
	return int32(C.unlink((*C.char)(unsafe.Pointer(pathname))))
}

// int putc(int c, FILE *stream);
func Xputc(t *TLS, c int32, fp uintptr) int32 { return Xfputc(t, c, fp) }

// int fputc(int c, FILE *stream);
func Xfputc(t *TLS, c int32, stream uintptr) int32 {
	return int32(C.fputc(C.int(c), (*C.FILE)(unsafe.Pointer(stream))))
}

// int atoi(const char *nptr);
func Xatoi(t *TLS, nptr uintptr) int32 {
	return int32(C.atoi((*C.char)(unsafe.Pointer(nptr))))
}

// double atof(const char *nptr);
func Xatof(t *TLS, nptr uintptr) float64 {
	return float64(C.atof((*C.char)(unsafe.Pointer(nptr))))
}

// pid_t getpid(void);
func Xgetpid(t *TLS) int32 {
	return int32(C.getpid())
}

// int fgetc(FILE *stream);
func Xfgetc(t *TLS, stream uintptr) int32 {
	return int32(C.fgetc((*C.FILE)(unsafe.Pointer(stream))))
}

// int access(const char *pathname, int mode);
func Xaccess(t *TLS, pathname uintptr, mode int32) int32 {
	return int32(C.access((*C.char)(unsafe.Pointer(pathname)), C.int(mode)))
}

// int pclose(FILE *stream);
func Xpclose(t *TLS, stream uintptr) int32 {
	return int32(C.pclose((*C.FILE)(unsafe.Pointer(stream))))
}

// int chdir(const char *path);
func Xchdir(t *TLS, path uintptr) int32 {
	return int32(C.chdir((*C.char)(unsafe.Pointer(path))))
}

// FILE *popen(const char *command, const char *type);
func Xpopen(t *TLS, command, type1 uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.popen((*C.char)(unsafe.Pointer(command)), (*C.char)(unsafe.Pointer(type1)))))
}

// long int strtol(const char *nptr, char **endptr, int base);
func Xstrtol(t *TLS, nptr, endptr uintptr, base int32) long {
	return long(C.strtol((*C.char)(unsafe.Pointer(nptr)), (**C.char)(unsafe.Pointer(endptr)), C.int(base)))
}

// unsigned long int strtoul(const char *nptr, char **endptr, int base);
func Xstrtoul(t *TLS, nptr, endptr uintptr, base int32) ulong {
	return ulong(C.strtoul((*C.char)(unsafe.Pointer(nptr)), (**C.char)(unsafe.Pointer(endptr)), C.int(base)))
}

// int tolower(int c);
func Xtolower(t *TLS, c int32) int32 {
	return int32(C.tolower(C.int(c)))
}

// int toupper(int c);
func Xtoupper(t *TLS, c int32) int32 {
	return int32(C.toupper(C.int(c)))
}

// uid_t getuid(void);
func Xgetuid(t *TLS) types.Uid_t {
	return types.Uid_t(C.getuid())
}

// struct passwd *getpwuid(uid_t uid);
func Xgetpwuid(t *TLS, uid types.Uid_t) uintptr {
	return uintptr(unsafe.Pointer(C.getpwuid(C.uid_t(uid))))
}

// int setvbuf(FILE *stream, char *buf, int mode, size_t size);
func Xsetvbuf(t *TLS, stream, buf uintptr, mode int32, size types.Size_t) int32 {
	return int32(C.setvbuf((*C.FILE)(unsafe.Pointer(stream)), (*C.char)(unsafe.Pointer(buf)), C.int(mode), C.size_t(size)))
}

// int isatty(int fd);
func Xisatty(t *TLS, fd int32) int32 {
	return int32(C.isatty(C.int(fd)))
}

// int raise(int sig);
func Xraise(t *TLS, sig int32) int32 {
	return int32(C.raise(C.int(sig)))
}

// char *strdup(const char *s);
func Xstrdup(t *TLS, s uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.strdup((*C.char)(unsafe.Pointer(s)))))
}

// struct tm *localtime(const time_t *timep);
func Xlocaltime(_ *TLS, timep uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.localtime((*C.time_t)(unsafe.Pointer(timep)))))
}

// struct tm *localtime_r(const time_t *timep, struct tm *result);
func Xlocaltime_r(_ *TLS, timep, result uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.localtime_r((*C.time_t)(unsafe.Pointer(timep)), (*C.struct_tm)(unsafe.Pointer(result)))))
}

// int backtrace(void **buffer, int size);
func Xbacktrace(t *TLS, buf uintptr, size int32) int32 {
	panic(todo(""))
}

// void backtrace_symbols_fd(void *const *buffer, int size, int fd);
func Xbacktrace_symbols_fd(t *TLS, buffer uintptr, size, fd int32) {
	panic(todo(""))
}

// int fileno(FILE *stream);
func Xfileno(t *TLS, stream uintptr) int32 {
	return int32(C.fileno((*C.FILE)(unsafe.Pointer(stream))))
}

// int open(const char *pathname, int flags, ...);
func Xopen(t *TLS, pathname uintptr, flags int32, args uintptr) int32 {
	return Xopen64(t, pathname, flags, args)
}

// int open(const char *pathname, int flags, ...);
func Xopen64(t *TLS, pathname uintptr, flags int32, args uintptr) int32 {
	var perm uint32
	if args != 0 {
		perm = *(*uint32)(unsafe.Pointer(args))
		return int32(C.__ccgo_open64b((*C.char)(unsafe.Pointer(pathname)), C.int(flags), C.uint(perm)))
	}

	return int32(C.__ccgo_open64((*C.char)(unsafe.Pointer(pathname)), C.int(flags)))
}

// char *strerror(int errnum);
func Xstrerror(t *TLS, errnum int32) uintptr {
	return uintptr(unsafe.Pointer(C.strerror(C.int(errnum))))
}

// off64_t lseek64(int fd, off64_t offset, int whence);
func Xlseek64(t *TLS, fd int32, offset types.X__off64_t, whence int32) types.X__off64_t {
	return types.X__off64_t(C.lseek(C.int(fd), C.long(offset), C.int(whence)))
}

// off_t lseek(int fd, off_t offset, int whence);
func Xlseek(t *TLS, fd int32, offset types.Off_t, whence int32) types.Off_t {
	return types.Off_t(C.lseek(C.int(fd), C.off_t(offset), C.int(whence)))
}

// int fsync(int fd);
func Xfsync(t *TLS, fd int32) int32 {
	return int32(C.fsync(C.int(fd)))
}

// long sysconf(int name);
func Xsysconf(t *TLS, name int32) long {
	return long(C.sysconf(C.int(name)))
}

// void *dlopen(const char *filename, int flags);
func Xdlopen(t *TLS, filename uintptr, flags int32) uintptr {
	return uintptr(C.dlopen((*C.char)(unsafe.Pointer(filename)), C.int(flags)))
}

// char *dlerror(void);
func Xdlerror(t *TLS) uintptr {
	return uintptr(unsafe.Pointer(C.dlerror()))
}

// int dlclose(void *handle);
func Xdlclose(t *TLS, handle uintptr) int32 {
	return int32(C.dlclose(unsafe.Pointer(handle)))
}

// void *dlsym(void *handle, const char *symbol);
func Xdlsym(t *TLS, handle, symbol uintptr) uintptr {
	panic(todo(""))
}

// int close(int fd);
func Xclose(t *TLS, fd int32) int32 {
	return int32(C.close(C.int(fd)))
}

// char *getcwd(char *buf, size_t size);
func Xgetcwd(t *TLS, buf uintptr, size types.Size_t) uintptr {
	return uintptr(unsafe.Pointer(C.getcwd((*C.char)(unsafe.Pointer(buf)), C.size_t(size))))
}

// int fstat(int fd, struct stat *statbuf);
func Xfstat64(t *TLS, fd int32, statbuf uintptr) int32 {
	return int32(C.fstat(C.int(fd), (*C.struct_stat)(unsafe.Pointer(statbuf))))
}

// int ftruncate(int fd, off_t length);
func Xftruncate64(t *TLS, fd int32, length types.Off_t) int32 {
	return int32(C.ftruncate(C.int(fd), C.off_t(length)))
}

// int fcntl(int fd, int cmd, ... /* arg */ );
func Xfcntl(t *TLS, fd, cmd int32, args uintptr) int32 { return Xfcntl64(t, fd, cmd, args) }

// int fcntl(int fd, int cmd, ... /* arg */ );
func Xfcntl64(t *TLS, fd, cmd int32, args uintptr) int32 {
	var arg uintptr
	if args != 0 {
		arg = *(*uintptr)(unsafe.Pointer(args))
		return int32(C.__ccgo_fcntl64b(C.int(fd), C.int(cmd), unsafe.Pointer(arg)))
	}

	return int32(C.__ccgo_fcntl64(C.int(fd), C.int(cmd)))
}

// ssize_t read(int fd, void *buf, size_t count);
func Xread(t *TLS, fd int32, buf uintptr, count types.Size_t) types.Ssize_t {
	return types.Ssize_t(C.read(C.int(fd), unsafe.Pointer(buf), C.size_t(count)))
}

// ssize_t write(int fd, const void *buf, size_t count);
func Xwrite(t *TLS, fd int32, buf uintptr, count types.Size_t) types.Ssize_t {
	return types.Ssize_t(C.write(C.int(fd), unsafe.Pointer(buf), C.size_t(count)))
}

// int fchmod(int fd, mode_t mode);
func Xfchmod(t *TLS, fd int32, mode types.Mode_t) int32 {
	return int32(C.fchmod(C.int(fd), C.mode_t(mode)))
}

// int rmdir(const char *pathname);
func Xrmdir(t *TLS, pathname uintptr) int32 {
	return int32(C.rmdir((*C.char)(unsafe.Pointer(pathname))))
}

// int fchown(int fd, uid_t owner, gid_t group);
func Xfchown(t *TLS, fd int32, owner types.Uid_t, group types.Gid_t) int32 {
	return int32(C.fchown(C.int(fd), C.uid_t(owner), C.gid_t(group)))
}

// uid_t geteuid(void);
func Xgeteuid(t *TLS) types.Uid_t {
	return types.Uid_t(C.geteuid())
}

// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
func Xmmap64(t *TLS, addr uintptr, length types.Size_t, prot, flags, fd int32, offset types.Off_t) uintptr {
	return uintptr(C.mmap(unsafe.Pointer(addr), C.size_t(length), C.int(prot), C.int(flags), C.int(fd), C.off_t(offset)))
}

// int munmap(void *addr, size_t length);
func Xmunmap(t *TLS, addr uintptr, length types.Size_t) int32 {
	return int32(C.munmap(unsafe.Pointer(addr), C.size_t(length)))
}

// int gettimeofday(struct timeval *tv, struct timezone *tz);
func Xgettimeofday(t *TLS, tv, tz uintptr) int32 {
	return int32(C.gettimeofday((*C.struct_timeval)(unsafe.Pointer(tv)), (*C.struct_timezone)(unsafe.Pointer(tz))))
}

// size_t strcspn(const char *s, const char *reject);
func Xstrcspn(t *TLS, s, reject uintptr) types.Size_t {
	return types.Size_t(C.strcspn((*C.char)(unsafe.Pointer(s)), (*C.char)(unsafe.Pointer(reject))))
}

// void perror(const char *s);
func Xperror(t *TLS, s uintptr) {
	C.perror((*C.char)(unsafe.Pointer(s)))
}

// long atol(const char *nptr);
func Xatol(t *TLS, nptr uintptr) long {
	return long(C.atol((*C.char)(unsafe.Pointer(nptr))))
}

// int fputs(const char *s, FILE *stream);
func Xfputs(t *TLS, s, stream uintptr) int32 {
	return int32(C.fputs((*C.char)(unsafe.Pointer(s)), (*C.FILE)(unsafe.Pointer(stream))))
}

// int putchar(int c);
func Xputchar(t *TLS, c int32) int32 {
	return int32(C.putchar(C.int(c)))
}

// time_t mktime(struct tm *tm);
func Xmktime(t *TLS, tm uintptr) types.Time_t {
	return types.Time_t(C.mktime((*C.struct_tm)(unsafe.Pointer(tm))))
}

// char *strpbrk(const char *s, const char *accept);
func Xstrpbrk(t *TLS, s, accept uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.strpbrk((*C.char)(unsafe.Pointer(s)), (*C.char)(unsafe.Pointer(accept)))))
}

// struct servent *getservbyname(const char *name, const char *proto);
func Xgetservbyname(t *TLS, name, proto uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.getservbyname((*C.char)(unsafe.Pointer(name)), (*C.char)(unsafe.Pointer(proto)))))
}

// int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
func Xgetsockopt(t *TLS, sockfd, level, optname int32, optval, optlen uintptr) int32 {
	return int32(C.getsockopt(C.int(sockfd), C.int(level), C.int(optname), unsafe.Pointer(optval), (*C.socklen_t)(unsafe.Pointer(optlen))))
}

// int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
func Xsetsockopt(t *TLS, sockfd, level, optname int32, optval uintptr, optlen socket.Socklen_t) int32 {
	return int32(C.setsockopt(C.int(sockfd), C.int(level), C.int(optname), unsafe.Pointer(optval), C.socklen_t(optlen)))
}

// int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
func Xgetaddrinfo(t *TLS, node, service, hints, res uintptr) int32 {
	return int32(C.getaddrinfo((*C.char)(unsafe.Pointer(node)), (*C.char)(unsafe.Pointer(service)), (*C.struct_addrinfo)(unsafe.Pointer(hints)), (**C.struct_addrinfo)(unsafe.Pointer(res))))
}

// const char *gai_strerror(int errcode);
func Xgai_strerror(t *TLS, errcode int32) uintptr {
	return uintptr(unsafe.Pointer(C.gai_strerror(C.int(errcode))))
}

// int tcgetattr(int fd, struct termios *termios_p);
func Xtcgetattr(t *TLS, fd int32, termios_p uintptr) int32 {
	return int32(C.tcgetattr(C.int(fd), (*C.struct_termios)(unsafe.Pointer(termios_p))))
}

// int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);
func Xtcsetattr(t *TLS, fd, optional_actions int32, termios_p uintptr) int32 {
	return int32(C.tcsetattr(C.int(fd), C.int(optional_actions), (*C.struct_termios)(unsafe.Pointer(termios_p))))
}

// int ioctl(int fd, unsigned long request, ...);
func Xioctl(t *TLS, fd int32, request ulong, va uintptr) int32 {
	panic(todo(""))
}

// speed_t cfgetospeed(const struct termios *termios_p);
func Xcfgetospeed(t *TLS, termios_p uintptr) termios.Speed_t {
	return termios.Speed_t(C.cfgetospeed((*C.struct_termios)(unsafe.Pointer(termios_p))))
}

// int cfsetospeed(struct termios *termios_p, speed_t speed);
func Xcfsetospeed(t *TLS, termios_p uintptr, speed uint32) int32 {
	return int32(C.cfsetospeed((*C.struct_termios)(unsafe.Pointer(termios_p)), C.speed_t(speed)))
}

// int cfsetispeed(struct termios *termios_p, speed_t speed);
func Xcfsetispeed(t *TLS, termios_p uintptr, speed uint32) int32 {
	return int32(C.cfsetispeed((*C.struct_termios)(unsafe.Pointer(termios_p)), C.uint(speed)))
}

// int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
func Xgetsockname(t *TLS, sockfd int32, addr, addrlen uintptr) int32 {
	return int32(C.getsockname(C.int(sockfd), (*C.struct_sockaddr)(unsafe.Pointer(addr)), (*C.socklen_t)(unsafe.Pointer(addrlen))))
}

// FILE *fdopen(int fd, const char *mode);
func Xfdopen(t *TLS, fd int32, mode uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.fdopen(C.int(fd), (*C.char)(unsafe.Pointer(mode)))))
}

// int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
func Xselect(t *TLS, nfds int32, readfds, writefds, exceptfds, timeout uintptr) int32 {
	return int32(C.__ccgo_select(C.int(nfds), (*C.fd_set)(unsafe.Pointer(readfds)), (*C.fd_set)(unsafe.Pointer(writefds)), (*C.fd_set)(unsafe.Pointer(exceptfds)), (*C.struct_timeval)(unsafe.Pointer(timeout))))
}

// int ftruncate(int fd, off_t length);
func Xftruncate(t *TLS, fd int32, length types.Off_t) int32 {
	return int32(C.ftruncate(C.int(fd), C.off_t(length)))
}

// int rename(const char *oldpath, const char *newpath);
func Xrename(t *TLS, oldpath, newpath uintptr) int32 {
	return int32(C.rename((*C.char)(unsafe.Pointer(oldpath)), (*C.char)(unsafe.Pointer(newpath))))
}

// char *realpath(const char *path, char *resolved_path);
func Xrealpath(t *TLS, path, resolved_path uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.realpath((*C.char)(unsafe.Pointer(path)), (*C.char)(unsafe.Pointer(resolved_path)))))
}

// struct dirent *readdir(DIR *dirp);
func Xreaddir(t *TLS, dirp uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.readdir((*C.DIR)(unsafe.Pointer(dirp)))))
}

// int mknod(const char *pathname, mode_t mode, dev_t dev);
func Xmknod(t *TLS, pathname uintptr, mode types.Mode_t, dev types.Dev_t) int32 {
	return int32(C.mknod((*C.char)(unsafe.Pointer(pathname)), C.mode_t(mode), C.dev_t(dev)))
}

// int mkfifo(const char *pathname, mode_t mode);
func Xmkfifo(t *TLS, pathname uintptr, mode types.Mode_t) int32 {
	return int32(C.mkfifo((*C.char)(unsafe.Pointer(pathname)), C.mode_t(mode)))
}

// mode_t umask(mode_t mask);
func Xumask(t *TLS, mask types.Mode_t) types.Mode_t {
	return types.Mode_t(C.umask(C.mode_t(mask)))
}

// FTS *fts_open(char * const *path_argv, int options, int (*compar)(const FTSENT **, const FTSENT **));
func Xfts_open(t *TLS, path_argv uintptr, options int32, compar uintptr) uintptr {
	if compar != 0 {
		panic(todo(""))
	}

	return uintptr(unsafe.Pointer(C.fts_open((**C.char)(unsafe.Pointer(path_argv)), C.int(options), nil)))
}

// FTSENT *fts_read(FTS *ftsp);
func Xfts_read(t *TLS, ftsp uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.fts_read((*C.FTS)(unsafe.Pointer(ftsp)))))
}

// int fts_close(FTS *ftsp);
func Xfts_close(t *TLS, ftsp uintptr) int32 {
	return int32(C.fts_close((*C.FTS)(unsafe.Pointer(ftsp))))
}

// int utime(const char *filename, const struct utimbuf *times);
func Xutime(t *TLS, filename, times uintptr) int32 {
	return int32(C.utime((*C.char)(unsafe.Pointer(filename)), (*C.struct_utimbuf)(unsafe.Pointer(times))))
}

// int chown(const char *pathname, uid_t owner, gid_t group);
func Xchown(t *TLS, pathname uintptr, owner types.Uid_t, group types.Gid_t) int32 {
	return int32(C.chown((*C.char)(unsafe.Pointer(pathname)), C.uid_t(owner), C.gid_t(group)))
}

// int mkstemps(char *template, int suffixlen);
func Xmkstemps(t *TLS, template uintptr, suffixlen int32) int32 {
	return int32(C.mkstemps((*C.char)(unsafe.Pointer(template)), C.int(suffixlen)))
}

// int mkstemp(char *template);
func Xmkstemp(t *TLS, template uintptr) int32 {
	return int32(C.mkstemp((*C.char)(unsafe.Pointer(template))))
}

// int link(const char *oldpath, const char *newpath);
func Xlink(t *TLS, oldpath, newpath uintptr) int32 {
	return int32(C.link((*C.char)(unsafe.Pointer(oldpath)), (*C.char)(unsafe.Pointer(newpath))))
}

// int pipe(int pipefd[2]);
func Xpipe(t *TLS, pipefd uintptr) int32 {
	return int32(C.pipe((*C.int)(unsafe.Pointer(pipefd))))
}

// pid_t fork(void);
func Xfork(t *TLS) int32 {
	C.__ccgo_seterrno(errno.ENOSYS)
	return -1
}

// int dup2(int oldfd, int newfd);
func Xdup2(t *TLS, oldfd, newfd int32) int32 {
	return int32(C.dup2(C.int(oldfd), C.int(newfd)))
}

// void _exit(int status);
func X_exit(t *TLS, status int32) {
	C._exit(C.int(status))
}

// int execvp(const char *file, char *const argv[]);
func Xexecvp(t *TLS, file, argv uintptr) int32 {
	return int32(C.execvp((*C.char)(unsafe.Pointer(file)), (**C.char)(unsafe.Pointer(argv))))
}

// pid_t waitpid(pid_t pid, int *wstatus, int options);
func Xwaitpid(t *TLS, pid types.Pid_t, wstatus uintptr, optname int32) int32 {
	// trc("waitpid(%d, status %#x, optname %d)", pid, wstatus, optname)
	r := types.Pid_t(C.waitpid(C.pid_t(pid), (*C.int)(unsafe.Pointer(wstatus)), C.int(optname)))
	// var ws int32
	// if wstatus != 0 {
	// 	ws = *(*int32)(unsafe.Pointer(wstatus))
	// }
	// trc("waitpid(%d, status %#x(%d), optname %d): %v", pid, wstatus, ws, optname, r)
	return r
}

// int uname(struct utsname *buf);
func Xuname(t *TLS, buf uintptr) int32 {
	return int32(C.uname((*C.struct_utsname)(unsafe.Pointer(buf))))
}

// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
func Xrecv(t *TLS, sockfd int32, buf uintptr, len types.Size_t, flags int32) types.Ssize_t {
	return types.Ssize_t(C.recv(C.int(sockfd), unsafe.Pointer(buf), C.size_t(len), C.int(flags)))
}

// ssize_t send(int sockfd, const void *buf, size_t len, int flags);
func Xsend(t *TLS, sockfd int32, buf uintptr, len types.Size_t, flags int32) types.Ssize_t {
	return types.Ssize_t(C.send(C.int(sockfd), unsafe.Pointer(buf), C.size_t(len), C.int(flags)))
}

// void freeaddrinfo(struct addrinfo *res);
func Xfreeaddrinfo(t *TLS, res uintptr) {
	C.freeaddrinfo((*C.struct_addrinfo)(unsafe.Pointer(res)))
}

// int shutdown(int sockfd, int how);
func Xshutdown(t *TLS, sockfd, how int32) int32 {
	return int32(C.shutdown(C.int(sockfd), C.int(how)))
}

// uint32_t htonl(uint32_t hostlong);
func Xhtonl(t *TLS, hostlong uint32) uint32 {
	return uint32(C.htonl(C.uint(hostlong)))
}

// int getnameinfo(const struct sockaddr *addr, socklen_t addrlen, char *host, socklen_t hostlen, char *serv, socklen_t servlen, int flags);
func Xgetnameinfo(t *TLS, addr uintptr, addrlen socket.Socklen_t, host uintptr, hostlen socket.Socklen_t, serv uintptr, servlen socket.Socklen_t, flags int32) int32 {
	return int32(C.getnameinfo(
		(*C.struct_sockaddr)(unsafe.Pointer(addr)),
		C.socklen_t(addrlen),
		(*C.char)(unsafe.Pointer(host)),
		C.socklen_t(hostlen),
		(*C.char)(unsafe.Pointer(serv)),
		C.socklen_t(servlen),
		C.int(flags),
	))
}

// int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
func Xgetpeername(t *TLS, sockfd int32, addr uintptr, addrlen uintptr) int32 {
	return int32(C.getpeername(C.int(sockfd), (*C.struct_sockaddr)(unsafe.Pointer(addr)), (*C.socklen_t)(unsafe.Pointer(addrlen))))
}

// int socket(int domain, int type, int protocol);
func Xsocket(t *TLS, domain, type1, protocol int32) int32 {
	return int32(C.socket(C.int(domain), C.int(type1), C.int(protocol)))
}

// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
func Xbind(t *TLS, sockfd int32, addr uintptr, addrlen uint32) int32 {
	return int32(C.bind(C.int(sockfd), (*C.struct_sockaddr)(unsafe.Pointer(addr)), C.socklen_t(addrlen)))
}

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
func Xconnect(t *TLS, sockfd int32, addr uintptr, addrlen uint32) int32 {
	return int32(C.connect(C.int(sockfd), (*C.struct_sockaddr)(unsafe.Pointer(addr)), C.socklen_t(addrlen)))
}

// char *setlocale(int category, const char *locale);
func Xsetlocale(t *TLS, category int32, locale uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.setlocale(C.int(category), (*C.char)(unsafe.Pointer(locale)))))
}

// uint16_t htons(uint16_t hostshort);
func Xhtons(t *TLS, hostshort uint16) uint16 {
	return uint16(C.htons(C.uint16_t(hostshort)))
}

// int listen(int sockfd, int backlog);
func Xlisten(t *TLS, sockfd, backlog int32) int32 {
	return int32(C.listen(C.int(sockfd), C.int(backlog)))
}

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
func Xaccept(t *TLS, sockfd int32, addr uintptr, addrlen uintptr) int32 {
	return int32(C.accept(C.int(sockfd), (*C.struct_sockaddr)(unsafe.Pointer(addr)), (*C.socklen_t)(unsafe.Pointer(addrlen))))
}

// struct tm *gmtime_r(const time_t *timep, struct tm *result);
func Xgmtime_r(t *TLS, timep, result uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.gmtime_r((*C.time_t)(unsafe.Pointer(timep)), (*C.struct_tm)(unsafe.Pointer(result)))))
}

// struct passwd *getpwnam(const char *name);
func Xgetpwnam(t *TLS, name uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.getpwnam((*C.char)(unsafe.Pointer(name)))))
}

// struct group *getgrnam(const char *name);
func Xgetgrnam(t *TLS, name uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.getgrnam((*C.char)(unsafe.Pointer(name)))))
}

// int strcasecmp(const char *s1, const char *s2);
func Xstrcasecmp(t *TLS, s1, s2 uintptr) int32 {
	return int32(C.strcasecmp((*C.char)(unsafe.Pointer(s1)), (*C.char)(unsafe.Pointer(s2))))
}

// char *nl_langinfo(nl_item item);
func Xnl_langinfo(t *TLS, item langinfo.Nl_item) uintptr {
	return uintptr(unsafe.Pointer(C.nl_langinfo(C.nl_item(item))))
}

// char *inet_ntoa(struct in_addr in);
func Xinet_ntoa(t *TLS, in1 in.In_addr) uintptr {
	return uintptr(unsafe.Pointer(C.inet_ntoa(*(*C.struct_in_addr)(unsafe.Pointer(&in1)))))
}

func Xntohs(t *TLS, netshort uint16) uint16 { return uint16(C.ntohs(C.uint16_t(netshort))) }

// struct group *getgrgid(gid_t gid);
func Xgetgrgid(t *TLS, gid types.Gid_t) uintptr {
	return uintptr(unsafe.Pointer(C.getgrgid(C.gid_t(gid))))
}

// struct hostent *gethostbyname(const char *name);
func Xgethostbyname(t *TLS, name uintptr) uintptr {
	return uintptr(unsafe.Pointer(C.gethostbyname((*C.char)(unsafe.Pointer(name)))))
}

// struct hostent *gethostbyaddr(const void *addr, socklen_t len, int type);
func Xgethostbyaddr(t *TLS, addr uintptr, len socket.Socklen_t, type1 int32) uintptr {
	return uintptr(unsafe.Pointer(C.gethostbyaddr(unsafe.Pointer(addr), C.socklen_t(len), C.int(type1))))
}

// int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
func Xsigaction(t *TLS, signum int32, act, oldact uintptr) int32 {
	panic(todo(""))
}

// unsigned int alarm(unsigned int seconds);
func Xalarm(t *TLS, seconds uint32) uint32 {
	return uint32(C.alarm(C.uint(seconds)))
}

// int getrlimit(int resource, struct rlimit *rlim);
func Xgetrlimit(t *TLS, resource int32, rlim uintptr) int32 {
	return int32(C.getrlimit(C.int(resource), (*C.struct_rlimit)(unsafe.Pointer(rlim))))
}

// int setrlimit(int resource, const struct rlimit *rlim);
func Xsetrlimit(t *TLS, resource int32, rlim uintptr) int32 {
	return int32(C.setrlimit(C.int(resource), (*C.struct_rlimit)(unsafe.Pointer(rlim))))
}

func SetErrno(err int32) {
	C.__ccgo_seterrno(C.int(err))
}

// int fstat(int fd, struct stat *statbuf);
func Xfstat(t *TLS, fd int32, statbuf uintptr) int32 {
	return int32(C.fstat(C.int(fd), (*C.struct_stat)(unsafe.Pointer(statbuf))))
}

// int ferror(FILE *stream);
func Xferror(t *TLS, stream uintptr) int32 {
	return int32(C.ferror((*C.FILE)(unsafe.Pointer(stream))))
}

func Environ() uintptr {
	return uintptr(unsafe.Pointer(C.environ))
}

func EnvironP() uintptr {
	return uintptr(unsafe.Pointer(&C.environ))
}
