// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package libc // import "modernc.org/libc"

//TODO use O_RDONLY etc. from fcntl header

//TODO use t.Alloc/Free where appropriate

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	gosignal "os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	gotime "time"
	"unsafe"

	"github.com/mattn/go-isatty"
	"modernc.org/libc/errno"
	"modernc.org/libc/signal"
	"modernc.org/libc/stdio"
	"modernc.org/libc/sys/types"
	"modernc.org/libc/time"
	"modernc.org/libc/unistd"
	"modernc.org/memory"
)

var (
	allocMu   sync.Mutex
	allocator memory.Allocator
)

// Keep these outside of the var block otherwise go generate will miss them.
var Xenviron uintptr
var Xstdin = newFile(nil, unistd.STDIN_FILENO)
var Xstdout = newFile(nil, unistd.STDOUT_FILENO)
var Xstderr = newFile(nil, unistd.STDERR_FILENO)

func NewTLS() *TLS {
	id := atomic.AddInt32(&tid, 1)
	t := &TLS{ID: id}
	t.errnop = mustCalloc(t, types.Size_t(unsafe.Sizeof(int32(0))))
	return t
}

func (t *TLS) Close() {
	Xfree(t, t.errnop)
}

func (t *TLS) setErrno(err interface{}) {
	// if dmesgs {
	// 	dmesg("%v: %T(%v)\n%s", origin(1), err, err, debug.Stack())
	// }
again:
	switch x := err.(type) {
	case int:
		*(*int32)(unsafe.Pointer(t.errnop)) = int32(x)
	case int32:
		*(*int32)(unsafe.Pointer(t.errnop)) = x
	case *os.PathError:
		err = x.Err
		goto again
	case syscall.Errno:
		*(*int32)(unsafe.Pointer(t.errnop)) = int32(x)
	case *os.SyscallError:
		err = x.Err
		goto again
	default:
		panic(todo("%T", x))
	}
}

func X__builtin_abort(t *TLS)                      { Xabort(t) }
func X__builtin_llabs(t *TLS, j longlong) longlong { return Xllabs(t, j) }

// bool __builtin_add_overflow (type1 a, type2 b, type3 *res)
func X__builtin_add_overflowUint64(t *TLS, a, b uint64, res uintptr) int32 {
	r := a + b
	*(*uint64)(unsafe.Pointer(res)) = r
	return Bool32(r < a)
}

var (
	bigMinInt64 = big.NewInt(math.MinInt64)
	bigMaxInt64 = big.NewInt(math.MaxInt64)
)

func X___errno_location(t *TLS) uintptr {
	return X__errno_location(t)
}

// int * __errno_location(void);
func X__errno_location(t *TLS) uintptr {
	return t.errnop
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

// void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function);
func X__assert_fail(t *TLS, assertion, file uintptr, line uint32, function uintptr) {
	fmt.Fprintf(os.Stderr, "assertion failure: %s:%d.%s: %s\n", GoString(file), line, GoString(function), GoString(assertion))
	os.Stderr.Sync()
	Xexit(t, 1)
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

// void *malloc(size_t size);
func Xmalloc(t *TLS, n types.Size_t) uintptr {
	if n == 0 {
		return 0
	}

	allocMu.Lock()

	defer allocMu.Unlock()

	p, err := allocator.UintptrMalloc(int(n))
	if err != nil {
		t.setErrno(errno.ENOMEM)
		return 0
	}

	return p
}

// void *calloc(size_t nmemb, size_t size);
func Xcalloc(t *TLS, n, size types.Size_t) uintptr {
	rq := int(n * size)
	if rq == 0 {
		return 0
	}

	allocMu.Lock()

	defer allocMu.Unlock()

	p, err := allocator.UintptrCalloc(int(n * size))
	if err != nil {
		t.setErrno(errno.ENOMEM)
		return 0
	}

	return p
}

// void *realloc(void *ptr, size_t size);
func Xrealloc(t *TLS, ptr uintptr, size types.Size_t) uintptr {
	allocMu.Lock()

	defer allocMu.Unlock()

	p, err := allocator.UintptrRealloc(ptr, int(size))
	if err != nil {
		t.setErrno(errno.ENOMEM)
		return 0
	}

	return p
}

// void free(void *ptr);
func Xfree(t *TLS, p uintptr) {
	if p == 0 {
		return
	}

	allocMu.Lock()

	defer allocMu.Unlock()

	allocator.UintptrFree(p)
}

func write(w io.Writer, b []byte) (int, error) {
	if dmesgs {
		dmesg("%v: %s", origin(1), b)
	}
	if _, err := w.Write(b); err != nil {
		return -1, err
	}

	return len(b), nil
}

func Xvfprintf(t *TLS, stream, format, ap uintptr) int32 { return Xfprintf(t, stream, format, ap) }

// int __isoc99_sscanf(const char *str, const char *format, ...);
func X__isoc99_sscanf(t *TLS, str, format, va uintptr) int32 {
	return scanf(strings.NewReader(GoString(str)), format, va)
}

// unsigned int sleep(unsigned int seconds);
func Xsleep(t *TLS, seconds uint32) uint32 {
	gotime.Sleep(gotime.Second * gotime.Duration(seconds))
	return 0
}

// sighandler_t signal(int signum, sighandler_t handler);
func Xsignal(t *TLS, signum int32, handler uintptr) uintptr { //TODO use sigaction?
	signalsMu.Lock()

	defer signalsMu.Unlock()

	r := signals[signum]
	signals[signum] = handler
	switch handler {
	case signal.SIG_DFL:
		panic(todo("%v %#x", syscall.Signal(signum), handler))
	case signal.SIG_IGN:
		switch r {
		case signal.SIG_DFL:
			gosignal.Ignore(syscall.Signal(signum))
		case signal.SIG_IGN:
			panic(todo("%v %#x", syscall.Signal(signum), handler))
		default:
			panic(todo("%v %#x", syscall.Signal(signum), handler))
		}
	default:
		switch r {
		case signal.SIG_DFL:
			c := make(chan os.Signal, 1)
			gosignal.Notify(c, syscall.Signal(signum))
			go func() { //TODO mechanism to stop/cancel
				for {
					<-c
					var f func(*TLS, int32)
					*(*uintptr)(unsafe.Pointer(&f)) = handler
					tls := NewTLS()
					f(tls, signum)
					tls.Close()
				}
			}()
		case signal.SIG_IGN:
			panic(todo("%v %#x", syscall.Signal(signum), handler))
		default:
			panic(todo("%v %#x", syscall.Signal(signum), handler))
		}
	}
	return r
}

// int snprintf(char *str, size_t size, const char *format, ...);
func Xsnprintf(t *TLS, str uintptr, size types.Size_t, format, args uintptr) (r int32) {
	switch size {
	case 0:
		return 0
	case 1:
		*(*byte)(unsafe.Pointer(str)) = 0
		return 0
	}

	b := printf(format, args)
	if len(b)+1 > int(size) {
		b = b[:size-1]
	}
	r = int32(len(b))
	copy((*RawMem)(unsafe.Pointer(str))[:r:r], b)
	*(*byte)(unsafe.Pointer(str + uintptr(r))) = 0
	return r
}

// char *strncpy(char *dest, const char *src, size_t n)
func Xstrncpy(t *TLS, dest, src uintptr, n types.Size_t) (r uintptr) {
	r = dest
	for c := *(*int8)(unsafe.Pointer(src)); c != 0 && n > 0; n-- {
		*(*int8)(unsafe.Pointer(dest)) = c
		dest++
		src++
		c = *(*int8)(unsafe.Pointer(src))
	}
	for ; uintptr(n) > 0; n-- {
		*(*int8)(unsafe.Pointer(dest)) = 0
		dest++
	}
	return r
}

// char *strcat(char *dest, const char *src)
func Xstrcat(t *TLS, dest, src uintptr) (r uintptr) {
	r = dest
	for *(*int8)(unsafe.Pointer(dest)) != 0 {
		dest++
	}
	for {
		c := *(*int8)(unsafe.Pointer(src))
		src++
		*(*int8)(unsafe.Pointer(dest)) = c
		dest++
		if c == 0 {
			return r
		}
	}
}

// void *memchr(const void *s, int c, size_t n);
func Xmemchr(t *TLS, s uintptr, c int32, n types.Size_t) uintptr {
	for ; n != 0; n-- {
		if *(*byte)(unsafe.Pointer(s)) == byte(c) {
			return s
		}

		s++
	}
	return 0
}

// void rewind(FILE *stream);
func Xrewind(t *TLS, stream uintptr) {
	Xfseek(t, stream, 0, stdio.SEEK_SET)
}

var getenvOnce sync.Once

// char *getenv(const char *name);
func Xgetenv(t *TLS, name uintptr) uintptr {
	p := Environ()
	if p == 0 {
		getenvOnce.Do(func() {
			SetEnviron(t, os.Environ())
			p = Environ()
		})
	}

	return getenv(p, GoString(name))
}

func getenv(p uintptr, nm string) uintptr {
	for ; ; p += uintptrSize {
		q := *(*uintptr)(unsafe.Pointer(p))
		if q == 0 {
			return 0
		}

		s := GoString(q)
		a := strings.SplitN(s, "=", 2)
		if len(a) != 2 {
			panic(todo("%q %q %q", nm, s, a))
		}

		if a[0] == nm {
			return q + uintptr(len(nm)) + 1
		}
	}
}

// char *strstr(const char *haystack, const char *needle);
func Xstrstr(t *TLS, haystack, needle uintptr) uintptr {
	hs := GoString(haystack)
	nd := GoString(needle)
	if i := strings.Index(hs, nd); i >= 0 {
		r := haystack + uintptr(i)
		return r
	}

	return 0
}

// int putc(int c, FILE *stream);
func Xputc(t *TLS, c int32, fp uintptr) int32 {
	return Xfputc(t, c, fp)
}

// int atoi(const char *nptr);
func Xatoi(t *TLS, nptr uintptr) int32 {
	_, neg, _, n, _ := strToUint64(t, nptr, 10)
	switch {
	case neg:
		return int32(-n)
	default:
		return int32(n)
	}
}

// double atof(const char *nptr);
func Xatof(t *TLS, nptr uintptr) float64 {
	n, _ := strToFloatt64(t, nptr, 64)
	return n
}

// int tolower(int c);
func Xtolower(t *TLS, c int32) int32 {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}

	return c
}

// int toupper(int c);
func Xtoupper(t *TLS, c int32) int32 {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}

	return c
}

// int isatty(int fd);
func Xisatty(t *TLS, fd int32) int32 {
	return Bool32(isatty.IsTerminal(uintptr(fd)))
}

// char *strdup(const char *s);
func Xstrdup(t *TLS, s uintptr) uintptr {
	panic(todo(""))
}

// long atol(const char *nptr);
func Xatol(t *TLS, nptr uintptr) long {
	_, neg, _, n, _ := strToUint64(t, nptr, 10)
	switch {
	case neg:
		return long(-n)
	default:
		return long(n)
	}
}

// int putchar(int c);
func Xputchar(t *TLS, c int32) int32 {
	if _, err := write(os.Stdout, []byte{byte(c)}); err != nil {
		return stdio.EOF
	}

	return int32(c)
}

// time_t mktime(struct tm *tm);
func Xmktime(t *TLS, ptm uintptr) types.Time_t {
	loc := gotime.Local
	if r := getenv(Environ(), "TZ"); r != 0 {
		zone, off := parseZone(GoString(r))
		loc = gotime.FixedZone(zone, off)
	}
	tt := gotime.Date(
		int((*time.Tm)(unsafe.Pointer(ptm)).Ftm_year+1900),
		gotime.Month((*time.Tm)(unsafe.Pointer(ptm)).Ftm_mon+1),
		int((*time.Tm)(unsafe.Pointer(ptm)).Ftm_mday),
		int((*time.Tm)(unsafe.Pointer(ptm)).Ftm_hour),
		int((*time.Tm)(unsafe.Pointer(ptm)).Ftm_min),
		int((*time.Tm)(unsafe.Pointer(ptm)).Ftm_sec),
		0,
		loc,
	)
	(*time.Tm)(unsafe.Pointer(ptm)).Ftm_wday = int32(tt.Weekday())
	(*time.Tm)(unsafe.Pointer(ptm)).Ftm_yday = int32(tt.YearDay() - 1)
	return types.Time_t(tt.Unix())
}

// char *strpbrk(const char *s, const char *accept);
func Xstrpbrk(t *TLS, s, accept uintptr) uintptr {
	bitset := newBitset(256)
	for {
		b := *(*byte)(unsafe.Pointer(accept))
		if b == 0 {
			break
		}

		bitset.set(int(b))
		accept++
	}
	for {
		b := *(*byte)(unsafe.Pointer(s))
		if b == 0 {
			return 0
		}

		if bitset.has(int(b)) {
			return s
		}

		s++
	}
}

// int strcasecmp(const char *s1, const char *s2);
func Xstrcasecmp(t *TLS, s1, s2 uintptr) int32 {
	for {
		ch1 := *(*byte)(unsafe.Pointer(s1))
		if ch1 >= 'a' && ch1 <= 'z' {
			ch1 = ch1 - ('a' - 'A')
		}
		s1++
		ch2 := *(*byte)(unsafe.Pointer(s2))
		if ch2 >= 'a' && ch2 <= 'z' {
			ch2 = ch2 - ('a' - 'A')
		}
		s2++
		if ch1 != ch2 || ch1 == 0 || ch2 == 0 {
			r := int32(ch1) - int32(ch2)
			return r
		}
	}
}

var __ctype_b_table = [...]uint16{ //TODO use symbolic constants
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
	0x0002, 0x2003, 0x2002, 0x2002, 0x2002, 0x2002, 0x0002, 0x0002,
	0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
	0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002, 0x0002,
	0x6001, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004,
	0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004,
	0xd808, 0xd808, 0xd808, 0xd808, 0xd808, 0xd808, 0xd808, 0xd808,
	0xd808, 0xd808, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004,
	0xc004, 0xd508, 0xd508, 0xd508, 0xd508, 0xd508, 0xd508, 0xc508,
	0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508,
	0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508, 0xc508,
	0xc508, 0xc508, 0xc508, 0xc004, 0xc004, 0xc004, 0xc004, 0xc004,
	0xc004, 0xd608, 0xd608, 0xd608, 0xd608, 0xd608, 0xd608, 0xc608,
	0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608,
	0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608, 0xc608,
	0xc608, 0xc608, 0xc608, 0xc004, 0xc004, 0xc004, 0xc004, 0x0002,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
}

var ptable = uintptr(unsafe.Pointer(&__ctype_b_table[128]))

// const unsigned short * * __ctype_b_loc (void);
func X__ctype_b_loc(t *TLS) uintptr {
	return uintptr(unsafe.Pointer(&ptable))
}

func Xntohs(t *TLS, netshort uint16) uint16 {
	return uint16((*[2]byte)(unsafe.Pointer(&netshort))[0])<<8 | uint16((*[2]byte)(unsafe.Pointer(&netshort))[1])
}

// uint16_t htons(uint16_t hostshort);
func Xhtons(t *TLS, hostshort uint16) uint16 {
	var a [2]byte
	a[0] = byte(hostshort >> 8)
	a[1] = byte(hostshort)
	return *(*uint16)(unsafe.Pointer(&a))
}

// uint32_t htonl(uint32_t hostlong);
func Xhtonl(t *TLS, hostlong uint32) uint32 {
	var a [4]byte
	a[0] = byte(hostlong >> 24)
	a[1] = byte(hostlong >> 16)
	a[2] = byte(hostlong >> 8)
	a[3] = byte(hostlong)
	return *(*uint32)(unsafe.Pointer(&a))
}

// FILE *fopen(const char *pathname, const char *mode);
func Xfopen(t *TLS, pathname, mode uintptr) uintptr {
	return Xfopen64(t, pathname, mode) //TODO 32 bit
}

// int _IO_putc(int __c, _IO_FILE *__fp);
func X_IO_putc(t *TLS, c int32, fp uintptr) int32 {
	return Xputc(t, c, fp)
}

// size_t wcsnlen(const wchar_t *s, size_t maxlen);
func Xwcsnlen(t *TLS, s uintptr, maxlen types.Size_t) types.Size_t {
	panic(todo(""))
}

// int fputc(int c, FILE *stream);
func Xfputc(t *TLS, c int32, stream uintptr) int32 {
	if _, err := fwrite(file(stream).fd(), []byte{byte(c)}); err != nil {
		return stdio.EOF
	}

	return int32(byte(c))
}

// void perror(const char *s);
func Xperror(t *TLS, s uintptr) {
	panic(todo(""))
}

// int fclose(FILE *stream);
func Xfclose(t *TLS, stream uintptr) int32 {
	return file(stream).close(t)
}

// int fflush(FILE *stream);
func Xfflush(t *TLS, stream uintptr) int32 {
	return file(stream).fflush(t)
}

// int fgetc(FILE *stream);
func Xfgetc(t *TLS, stream uintptr) int32 {
	panic(todo(""))
}

// int fprintf(FILE *stream, const char *format, ...);
func Xfprintf(t *TLS, stream, format, args uintptr) int32 {
	n, _ := fwrite(file(stream).fd(), printf(format, args))
	return int32(n)
}

// int printf(const char *format, ...);
func Xprintf(t *TLS, format, args uintptr) int32 {
	n, _ := write(os.Stdout, printf(format, args))
	return int32(n)
}

// void tzset (void);
func Xtzset(t *TLS) {
	//TODO
}
