// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"modernc.org/libc/sys/types"
)

const (
	allocatorPageOverhead = 4 * unsafe.Sizeof(int(0))
	stackHeaderSize       = unsafe.Sizeof(stackHeader{})
	stackSegmentSize      = 1<<12 - allocatorPageOverhead
	uintptrSize           = unsafe.Sizeof(uintptr(0))
)

var (
	tid int32
)

func origin(skip int) string {
	pc, fn, fl, _ := runtime.Caller(skip)
	f := runtime.FuncForPC(pc)
	var fns string
	if f != nil {
		fns = f.Name()
		if x := strings.LastIndex(fns, "."); x > 0 {
			fns = fns[x+1:]
		}
	}
	return fmt.Sprintf("%s:%d:%s", filepath.Base(fn), fl, fns)
}

func trc(s string, args ...interface{}) string { //TODO-
	switch {
	case s == "":
		s = fmt.Sprintf(strings.Repeat("%v ", len(args)), args...)
	default:
		s = fmt.Sprintf(s, args...)
	}
	_, fn, fl, _ := runtime.Caller(1)
	r := fmt.Sprintf("\n%s:%d: TRC %s", fn, fl, s)
	fmt.Fprintf(os.Stdout, "%s\n", r)
	os.Stdout.Sync()
	return r
}

func todo(s string, args ...interface{}) string { //TODO-
	switch {
	case s == "":
		s = fmt.Sprintf(strings.Repeat("%v ", len(args)), args...)
	default:
		s = fmt.Sprintf(s, args...)
	}
	pc, fn, fl, _ := runtime.Caller(1)
	f := runtime.FuncForPC(pc)
	var fns string
	if f != nil {
		fns = f.Name()
		if x := strings.LastIndex(fns, "."); x > 0 {
			fns = fns[x+1:]
		}
	}
	r := fmt.Sprintf("%s:%d:%s: TODOTODO %s", fn, fl, fns, s) //TODOOK
	fmt.Fprintf(os.Stdout, "%s\n", r)
	os.Stdout.Sync()
	return r
}

func X__builtin_abort(t *TLS)                                        { Xabort(t) }
func X__builtin_abs(t *TLS, j int32) int32                           { return Xabs(t, j) }
func X__builtin_copysign(t *TLS, x, y float64) float64               { return Xcopysign(t, x, y) }
func X__builtin_copysignf(t *TLS, x, y float32) float32              { return Xcopysignf(t, x, y) }
func X__builtin_exit(t *TLS, status int32)                           { Xexit(t, status) }
func X__builtin_expect(t *TLS, exp, c long) long                     { return exp }
func X__builtin_fabs(t *TLS, x float64) float64                      { return Xfabs(t, x) }
func X__builtin_free(t *TLS, ptr uintptr)                            { Xfree(t, ptr) }
func X__builtin_malloc(t *TLS, size types.Size_t) uintptr            { return Xmalloc(t, size) }
func X__builtin_memcmp(t *TLS, s1, s2 uintptr, n types.Size_t) int32 { return Xmemcmp(t, s1, s2, n) }
func X__builtin_prefetch(t *TLS, addr, args uintptr)                 {}
func X__builtin_printf(t *TLS, s, args uintptr) int32                { return Xprintf(t, s, args) }
func X__builtin_strchr(t *TLS, s uintptr, c int32) uintptr           { return Xstrchr(t, s, c) }
func X__builtin_strcmp(t *TLS, s1, s2 uintptr) int32                 { return Xstrcmp(t, s1, s2) }
func X__builtin_strcpy(t *TLS, dest, src uintptr) uintptr            { return Xstrcpy(t, dest, src) }
func X__builtin_strlen(t *TLS, s uintptr) types.Size_t               { return Xstrlen(t, s) }
func X__builtin_trap(t *TLS)                                         { Xabort(t) }
func X__isnan(t *TLS, arg float64) int32                             { return Xisnan(t, arg) }
func X__isnanf(t *TLS, arg float32) int32                            { return Xisnanf(t, arg) }
func X__isnanl(t *TLS, arg float64) int32                            { return Xisnanl(t, arg) }
func Xvfprintf(t *TLS, stream, format, ap uintptr) int32             { return Xfprintf(t, stream, format, ap) }

func X__builtin_unreachable(t *TLS) {
	fmt.Fprintf(os.Stderr, "unrechable\n")
	os.Stderr.Sync()
	Xexit(t, 1)
}

func X__builtin_snprintf(t *TLS, str uintptr, size types.Size_t, format, args uintptr) int32 {
	return Xsnprintf(t, str, size, format, args)
}

func X__builtin_sprintf(t *TLS, str, format, args uintptr) (r int32) {
	return Xsprintf(t, str, format, args)
}

func X__builtin_memcpy(t *TLS, dest, src uintptr, n types.Size_t) (r uintptr) {
	return Xmemcpy(t, dest, src, n)
}

func X__builtin_memset(t *TLS, s uintptr, c int32, n types.Size_t) uintptr {
	return Xmemset(t, s, c, n)
}

type TLS struct {
	ID     int32
	errnop uintptr
	stack  stackHeader
}

func NewTLS() *TLS {
	id := atomic.AddInt32(&tid, 1)
	t := &TLS{ID: id}
	t.errnop = mustCalloc(t, types.Size_t(unsafe.Sizeof(int32(0))))
	return t
}

func (t *TLS) Close() {
	Xfree(t, t.errnop)
}

func (t *TLS) Alloc(n int) (r uintptr) {
	n += 15
	n &^= 15
	if t.stack.free >= n {
		r = t.stack.sp
		t.stack.free -= n
		t.stack.sp += uintptr(n)
		return r
	}

	if t.stack.page != 0 {
		*(*stackHeader)(unsafe.Pointer(t.stack.page)) = t.stack
	}
	rq := n + int(stackHeaderSize)
	if rq < int(stackSegmentSize) {
		rq = int(stackSegmentSize)
	}
	t.stack.free = rq - int(stackHeaderSize)
	t.stack.prev = t.stack.page
	rq += 15
	rq &^= 15
	t.stack.page = mustMalloc(t, types.Size_t(rq))
	t.stack.sp = t.stack.page + stackHeaderSize

	r = t.stack.sp
	t.stack.free -= n
	t.stack.sp += uintptr(n)
	return r
}

func (t *TLS) Free(n int) {
	n += 15
	n &^= 15
	t.stack.free += n
	t.stack.sp -= uintptr(n)
	if t.stack.sp != t.stack.page+stackHeaderSize {
		return
	}

	Xfree(t, t.stack.page)
	if t.stack.prev != 0 {
		t.stack = *(*stackHeader)(unsafe.Pointer(t.stack.prev))
		return
	}

	t.stack = stackHeader{}
}

type stackHeader struct {
	free int     // bytes left in page
	page uintptr // stack page
	prev uintptr // prev stack page = prev stack header
	sp   uintptr // next allocation address
}

func cString(t *TLS, s string) uintptr {
	n := len(s)
	p := mustMalloc(t, types.Size_t(n)+1)
	copy((*RawMem)(unsafe.Pointer(p))[:n], s)
	(*RawMem)(unsafe.Pointer(p))[n] = 0
	return p
}

func mustMalloc(t *TLS, n types.Size_t) uintptr {
	if p := Xmalloc(t, n); p != 0 {
		return p
	}

	panic("OOM")
}

// VaList fills a varargs list at p with args and returns uintptr(p).  The list
// must have been allocated by caller and it must not be in Go managed
// memory, ie. it must be pinned. Caller is responsible for freeing the list.
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

func VaInt32(app *uintptr) int32 {
	ap := *(*uintptr)(unsafe.Pointer(app))
	ap = roundup(ap, 8)
	v := *(*int32)(unsafe.Pointer(ap))
	ap += 8
	*(*uintptr)(unsafe.Pointer(app)) = ap
	return v
}

func VaUint32(app *uintptr) uint32 {
	ap := *(*uintptr)(unsafe.Pointer(app))
	ap = roundup(ap, 8)
	v := *(*uint32)(unsafe.Pointer(ap))
	ap += 8
	*(*uintptr)(unsafe.Pointer(app)) = ap
	return v
}

func VaInt64(app *uintptr) int64 {
	ap := *(*uintptr)(unsafe.Pointer(app))
	ap = roundup(ap, 8)
	v := *(*int64)(unsafe.Pointer(ap))
	ap += 8
	*(*uintptr)(unsafe.Pointer(app)) = ap
	return v
}

func VaUint64(app *uintptr) uint64 {
	ap := *(*uintptr)(unsafe.Pointer(app))
	ap = roundup(ap, 8)
	v := *(*uint64)(unsafe.Pointer(ap))
	ap += 8
	*(*uintptr)(unsafe.Pointer(app)) = ap
	return v
}

func VaFloat32(app *uintptr) float32 {
	ap := *(*uintptr)(unsafe.Pointer(app))
	ap = roundup(ap, 8)
	v := *(*float64)(unsafe.Pointer(ap))
	ap += 8
	*(*uintptr)(unsafe.Pointer(app)) = ap
	return float32(v)
}

func VaFloat64(app *uintptr) float64 {
	ap := *(*uintptr)(unsafe.Pointer(app))
	ap = roundup(ap, 8)
	v := *(*float64)(unsafe.Pointer(ap))
	ap += 8
	*(*uintptr)(unsafe.Pointer(app)) = ap
	return v
}

func VaUintptr(app *uintptr) uintptr {
	ap := *(*uintptr)(unsafe.Pointer(app))
	ap = roundup(ap, 8)
	v := *(*uintptr)(unsafe.Pointer(ap))
	ap += 8
	*(*uintptr)(unsafe.Pointer(app)) = ap
	return v
}

func roundup(n, to uintptr) uintptr {
	if r := n % to; r != 0 {
		return n + to - r
	}

	return n
}

func GoString(s uintptr) string {
	if s == 0 {
		return ""
	}

	var buf []byte
	for {
		b := *(*byte)(unsafe.Pointer(s))
		if b == 0 {
			return string(buf)
		}

		buf = append(buf, b)
		s++
	}
}

func mustCalloc(t *TLS, n types.Size_t) uintptr {
	if p := Xcalloc(t, 1, n); p != 0 {
		return p
	}

	panic("OOM")
}

func Bool32(b bool) int32 {
	if b {
		return 1
	}

	return 0
}

func Bool64(b bool) int64 {
	if b {
		return 1
	}

	return 0
}

// int sprintf(char *str, const char *format, ...);
func Xsprintf(t *TLS, str, format, args uintptr) (r int32) {
	b := printf(format, args)
	copy((*RawMem)(unsafe.Pointer(str))[:len(b)], b)
	*(*byte)(unsafe.Pointer(str + uintptr(len(b)))) = 0
	return int32(len(b))
}

type sorter struct {
	len  int
	base uintptr
	sz   uintptr
	f    func(*TLS, uintptr, uintptr) int32
	t    *TLS
}

func (s *sorter) Len() int { return s.len }

func (s *sorter) Less(i, j int) bool {
	return s.f(s.t, s.base+uintptr(i)*s.sz, s.base+uintptr(j)*s.sz) < 0
}

func (s *sorter) Swap(i, j int) {
	p := uintptr(s.base + uintptr(i)*s.sz)
	q := uintptr(s.base + uintptr(j)*s.sz)
	for i := 0; i < int(s.sz); i++ {
		*(*byte)(unsafe.Pointer(p)), *(*byte)(unsafe.Pointer(q)) = *(*byte)(unsafe.Pointer(q)), *(*byte)(unsafe.Pointer(p))
		p++
		q++
	}
}

// void qsort(void *base, size_t nmemb, size_t size, int (*compar)(const void *, const void *));
func Xqsort(t *TLS, base uintptr, nmemb, size types.Size_t, compar uintptr) {
	sort.Sort(&sorter{
		len:  int(nmemb),
		base: base,
		sz:   uintptr(size),
		f: (*struct {
			f func(*TLS, uintptr, uintptr) int32
		})(unsafe.Pointer(&struct{ uintptr }{compar})).f,
		t: t,
	})
}

// void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function);
func X__assert_fail(t *TLS, assertion, file uintptr, line uint32, function uintptr) {
	fmt.Fprintf(os.Stderr, "assertion failure: %s:%d.%s: %s\n", GoString(file), line, GoString(function), GoString(assertion))
	os.Stderr.Sync()
	Xexit(t, 1)
}

// int vprintf(const char *format, va_list ap);
func Xvprintf(t *TLS, s, ap uintptr) int32 { return Xprintf(t, s, ap) }

func CString(s string) (uintptr, error) {
	n := len(s)
	p := Xmalloc(nil, types.Size_t(n)+1)
	if p == 0 {
		return 0, fmt.Errorf("CString: cannot allocate %d bytes", n+1)
	}

	copy((*RawMem)(unsafe.Pointer(p))[:n], s)
	*(*byte)(unsafe.Pointer(p + uintptr(n))) = 0
	return p, nil
}

// int __isoc99_sscanf(const char *str, const char *format, ...);
func X__isoc99_sscanf(t *TLS, str, format, va uintptr) int32 {
	return scanf(strings.NewReader(GoString(str)), format, va)

}

// unsigned int sleep(unsigned int seconds);
func Xsleep(t *TLS, seconds uint32) uint32 {
	time.Sleep(time.Second * time.Duration(seconds))
	return 0
}

// int usleep(useconds_t usec);
func Xusleep(t *TLS, usec types.X__useconds_t) int32 {
	time.Sleep(time.Microsecond * time.Duration(usec))
	return 0
}
