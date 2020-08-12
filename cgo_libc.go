// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build cgo

//go.generate echo package libc > ccgo.go
//go:generate go run generate.go
//go:generate go fmt ./...

package libc // import "modernc.org/libc"

import (
	"os"
	"unsafe"

	"modernc.org/libc/sys/types"
)

/*

#cgo LDFLAGS: -lm -ldl

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

int myprintf(char *s) {
	return printf("%s", s);
}

int myfprintf(FILE *stream, char *s) {
	return fprintf(stream, "%s", s);
}

int myopen64(char *pathname, int flags) {
	return open(pathname, flags);
}

int myopen64b(char *pathname, int flags, unsigned perm) {
	return open(pathname, flags, perm);
}

int myfcntl64(int fd, int cmd) {
	return fcntl(fd, cmd);
}

int myfcntl64b(int fd, int cmd, void *p) {
	return fcntl(fd, cmd, p);
}

FILE *mystdout, *mystderr, *mystdin;

void myinit() {
	mystdin = stdin;
	mystdout = stdout;
	mystderr = stderr;
}

*/
import "C"

var Xstdin uintptr
var Xstdout uintptr
var Xstderr uintptr

func init() {
	C.myinit()
	Xstdin = uintptr(unsafe.Pointer(C.mystdin))
	Xstdout = uintptr(unsafe.Pointer(C.mystdout))
	Xstderr = uintptr(unsafe.Pointer(C.mystderr))
}

// int printf(const char *format, ...);
func Xprintf(t *TLS, s, args uintptr) int32 {
	b := printf(s, args)
	p := cString(t, string(b))

	defer Xfree(t, p)

	return int32(C.myprintf((*C.char)(unsafe.Pointer(p))))
}

// int fprintf(FILE *stream, const char *format, ...);
func Xfprintf(t *TLS, stream, format, args uintptr) int32 {
	b := printf(format, args)
	p := cString(t, string(b))

	defer Xfree(t, p)

	return int32(C.myfprintf((*C.FILE)(unsafe.Pointer(stream)), (*C.char)(unsafe.Pointer(p))))
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

func Xabort(t *TLS)                           { C.abort() }
func Xabs(t *TLS, j int32) int32              { return int32(C.abs(C.int(j))) }
func Xacos(t *TLS, x float64) float64         { return float64(C.acos(C.double(x))) }
func Xasin(t *TLS, x float64) float64         { return float64(C.asin(C.double(x))) }
func Xatan2(t *TLS, x, y float64) float64     { return float64(C.atan2(C.double(x), C.double(x))) }
func Xceil(t *TLS, x float64) float64         { return float64(C.ceil(C.double(x))) }
func Xcopysign(t *TLS, x, y float64) float64  { return float64(C.copysign(C.double(x), C.double(y))) }
func Xcopysignf(t *TLS, x, y float32) float32 { return float32(C.copysignf(C.float(x), C.float(y))) }
func Xcos(t *TLS, x float64) float64          { return float64(C.cos(C.double(x))) }
func Xcosf(t *TLS, x float32) float32         { return float32(C.cosf(C.float(x))) }
func Xcosh(t *TLS, x float64) float64         { return float64(C.cosh(C.double(x))) }
func Xexit(t *TLS, status int32)              { C.exit(C.int(status)) }
func Xexp(t *TLS, x float64) float64          { return float64(C.exp(C.double(x))) }
func Xfabs(t *TLS, x float64) float64         { return float64(C.fabs(C.double(x))) }
func Xfabsf(t *TLS, x float32) float32        { return float32(C.fabsf(C.float(x))) }
func Xfloor(t *TLS, x float64) float64        { return float64(C.floor(C.double(x))) }
func Xfree(t *TLS, p uintptr)                 { C.free(unsafe.Pointer(p)) }
func Xlog(t *TLS, x float64) float64          { return float64(C.log(C.double(x))) }
func Xlog10(t *TLS, x float64) float64        { return float64(C.log10(C.double(x))) }
func Xmalloc(t *TLS, n types.Size_t) uintptr  { return uintptr(C.malloc(C.size_t(n))) }
func Xpow(t *TLS, x, y float64) float64       { return float64(C.pow(C.double(x), C.double(y))) }
func Xrand(t *TLS) int32                      { return int32(C.rand()) }
func Xround(t *TLS, x float64) float64        { return float64(C.round(C.double(x))) }
func Xsin(t *TLS, x float64) float64          { return float64(C.sin(C.double(x))) }
func Xsinf(t *TLS, x float32) float32         { return float32(C.sinf(C.float(x))) }
func Xsinh(t *TLS, x float64) float64         { return float64(C.sinh(C.double(x))) }
func Xsqrt(t *TLS, x float64) float64         { return float64(C.sqrt(C.double(x))) }
func Xtan(t *TLS, x float64) float64          { return float64(C.tan(C.double(x))) }
func Xtanh(t *TLS, x float64) float64         { return float64(C.tanh(C.double(x))) }
func Xfmod(t *TLS, x, y float64) float64      { return float64(C.fmod(C.double(x), C.double(x))) }

func Xrealloc(t *TLS, ptr uintptr, size types.Size_t) uintptr {
	return uintptr(C.realloc(unsafe.Pointer(ptr), C.size_t(size)))
}

func Xcalloc(t *TLS, n, size types.Size_t) uintptr {
	return uintptr(C.calloc(C.size_t(n), C.size_t(size)))
}

func Start(main func(*TLS, int32, uintptr) int32) {
	t := NewTLS()
	argv := mustCalloc(t, types.Size_t((len(os.Args)+1)*int(uintptrSize)))
	p := argv
	for _, v := range os.Args {
		s := mustCalloc(t, types.Size_t(len(v)+1))
		copy((*(*[1 << 20]byte)(unsafe.Pointer(s)))[:], v)
		*(*uintptr)(unsafe.Pointer(p)) = s
		p += uintptrSize
	}
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
func Xlstat64(t *TLS, pathname, statbuf uintptr) int32 {
	return int32(C.lstat((*C.char)(unsafe.Pointer(pathname)), (*C.struct_stat)(unsafe.Pointer(statbuf))))
}

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
	return int32(C.mkdir((*C.char)(unsafe.Pointer(pathname)), C.mode_t(mode)))
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

// sighandler_t signal(int signum, sighandler_t handler);
func Xsignal(t *TLS, signum int32, handler uintptr) uintptr {
	return 0 //TODO
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
func Xopen64(t *TLS, pathname uintptr, flags int32, args uintptr) int32 {
	var perm uint32
	if args != 0 {
		perm = *(*uint32)(unsafe.Pointer(args))
		return int32(C.myopen64b((*C.char)(unsafe.Pointer(pathname)), C.int(flags), C.uint(perm)))
	}

	return int32(C.myopen64((*C.char)(unsafe.Pointer(pathname)), C.int(flags)))
}

// char *strerror(int errnum);
func Xstrerror(t *TLS, errnum int32) uintptr {
	return uintptr(unsafe.Pointer(C.strerror(C.int(errnum))))
}

// off64_t lseek64(int fd, off64_t offset, int whence);
func Xlseek64(t *TLS, fd int32, offset off64_t, whence int32) off64_t {
	return off64_t(C.lseek(C.int(fd), C.long(offset), C.int(whence)))
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
func Xfcntl64(t *TLS, fd, cmd int32, args uintptr) int32 {
	var arg uintptr
	if args != 0 {
		arg = *(*uintptr)(unsafe.Pointer(args))
		return int32(C.myfcntl64b(C.int(fd), C.int(cmd), unsafe.Pointer(arg)))
	}

	return int32(C.myfcntl64(C.int(fd), C.int(cmd)))
}

// unsigned int sleep(unsigned int seconds);
func Xsleep(t *TLS, seconds uint32) uint32 {
	return uint32(C.sleep(C.uint(seconds)))
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
