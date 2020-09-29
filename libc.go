// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go.generate echo package libc > ccgo.go
//go:generate go run generate.go
//go:generate go fmt ./...

// Package libc provides run time support for ccgo generated programs and
// implements selected parts of the C standard library.
package libc // import "modernc.org/libc"

import (
	"fmt"
	"math"
	"math/bits"
	"os"
	"sort"
	"unsafe"

	"modernc.org/libc/sys/types"
)

func X__builtin_abs(t *TLS, j int32) int32                           { return Xabs(t, j) }
func X__builtin_copysign(t *TLS, x, y float64) float64               { return Xcopysign(t, x, y) }
func X__builtin_copysignf(t *TLS, x, y float32) float32              { return Xcopysignf(t, x, y) }
func X__builtin_exit(t *TLS, status int32)                           { Xexit(t, status) }
func X__builtin_expect(t *TLS, exp, c long) long                     { return exp }
func X__builtin_fabs(t *TLS, x float64) float64                      { return Xfabs(t, x) }
func X__builtin_free(t *TLS, ptr uintptr)                            { Xfree(t, ptr) }
func X__builtin_inff(t *TLS) float32                                 { return float32(math.Inf(0)) }
func X__builtin_malloc(t *TLS, size types.Size_t) uintptr            { return Xmalloc(t, size) }
func X__builtin_memcmp(t *TLS, s1, s2 uintptr, n types.Size_t) int32 { return Xmemcmp(t, s1, s2, n) }
func X__builtin_prefetch(t *TLS, addr, args uintptr)                 {}
func X__builtin_printf(t *TLS, s, args uintptr) int32                { return Xprintf(t, s, args) }
func X__builtin_strchr(t *TLS, s uintptr, c int32) uintptr           { return Xstrchr(t, s, c) }
func X__builtin_strcmp(t *TLS, s1, s2 uintptr) int32                 { return Xstrcmp(t, s1, s2) }
func X__builtin_strcpy(t *TLS, dest, src uintptr) uintptr            { return Xstrcpy(t, dest, src) }
func X__builtin_strlen(t *TLS, s uintptr) types.Size_t               { return Xstrlen(t, s) }
func X__builtin_trap(t *TLS)                                         { Xabort(t) }

// int vprintf(const char *format, va_list ap);
func Xvprintf(t *TLS, s, ap uintptr) int32 { return Xprintf(t, s, ap) }

func X__builtin_unreachable(t *TLS) {
	fmt.Fprintf(os.Stderr, "unrechable\n")
	os.Stderr.Sync()
	Xexit(t, 1)
}

func X__builtin_sprintf(t *TLS, str, format, args uintptr) (r int32) {
	return Xsprintf(t, str, format, args)
}

func X__builtin_snprintf(t *TLS, str uintptr, size types.Size_t, format, args uintptr) int32 {
	return Xsnprintf(t, str, size, format, args)
}

func X__builtin_memset(t *TLS, s uintptr, c int32, n types.Size_t) uintptr {
	return Xmemset(t, s, c, n)
}

func X__builtin_memcpy(t *TLS, dest, src uintptr, n types.Size_t) (r uintptr) {
	return Xmemcpy(t, dest, src, n)
}

// uint16_t __builtin_bswap16 (uint32_t x)
func X__builtin_bswap16(t *TLS, x uint16) uint16 {
	return x<<8 | x>>8
}

// uint32_t __builtin_bswap32 (uint32_t x)
func X__builtin_bswap32(t *TLS, x uint32) uint32 {
	return x<<24 | x&0xff00<<8 | x&0xff0000>>8 | x>>24
}

// bool __builtin_add_overflow (type1 a, type2 b, type3 *res)
func X__builtin_add_overflowInt64(t *TLS, a, b int64, res uintptr) int32 {
	panic(todo(""))
}

// bool __builtin_add_overflow (type1 a, type2 b, type3 *res)
func X__builtin_add_overflowUint32(t *TLS, a, b uint32, res uintptr) int32 {
	r := a + b
	*(*uint32)(unsafe.Pointer(res)) = r
	return Bool32(r < a)
}

// bool __builtin_sub_overflow (type1 a, type2 b, type3 *res)
func X__builtin_sub_overflowInt64(t *TLS, a, b int64, res uintptr) int32 {
	panic(todo(""))
}

// bool __builtin_mul_overflow (type1 a, type2 b, type3 *res)
func X__builtin_mul_overflowInt64(t *TLS, a, b int64, res uintptr) int32 {
	if a == 0 || b == 0 {
		*(*int64)(unsafe.Pointer(res)) = 0
		return 0
	}

	r := a * b
	*(*int64)(unsafe.Pointer(res)) = r
	return Bool32(r/a != b)
}

// int __builtin_clzll (unsigned long long)
func X__builtin_clzll(t *TLS, x uint64) int32 {
	return int32(bits.LeadingZeros64(x))
}

// int abs(int j);
func Xabs(t *TLS, j int32) int32 {
	if j >= 0 {
		return j
	}

	return -j
}

// long long int llabs(long long int j);
func Xllabs(t *TLS, j longlong) longlong {
	if j >= 0 {
		return j
	}

	return -j
}

func Xacos(t *TLS, x float64) float64             { return math.Acos(x) }
func Xasin(t *TLS, x float64) float64             { return math.Asin(x) }
func Xatan(t *TLS, x float64) float64             { return math.Atan(x) }
func Xatan2(t *TLS, x, y float64) float64         { return math.Atan2(x, y) }
func Xceil(t *TLS, x float64) float64             { return math.Ceil(x) }
func Xcopysign(t *TLS, x, y float64) float64      { return math.Copysign(x, y) }
func Xcopysignf(t *TLS, x, y float32) float32     { return float32(math.Copysign(float64(x), float64(y))) }
func Xcos(t *TLS, x float64) float64              { return math.Cos(x) }
func Xcosf(t *TLS, x float32) float32             { return float32(math.Cos(float64(x))) }
func Xcosh(t *TLS, x float64) float64             { return math.Cosh(x) }
func Xexp(t *TLS, x float64) float64              { return math.Exp(x) }
func Xfabs(t *TLS, x float64) float64             { return math.Abs(x) }
func Xfabsf(t *TLS, x float32) float32            { return float32(math.Abs(float64(x))) }
func Xfloor(t *TLS, x float64) float64            { return math.Floor(x) }
func Xfmod(t *TLS, x, y float64) float64          { return math.Mod(x, y) }
func Xhypot(t *TLS, x, y float64) float64         { return math.Hypot(x, y) }
func Xisnan(t *TLS, x float64) int32              { return Bool32(math.IsNaN(x)) }
func Xisnanf(t *TLS, x float32) int32             { return Bool32(math.IsNaN(float64(x))) }
func Xisnanl(t *TLS, x float64) int32             { return Bool32(math.IsNaN(x)) } // ccgo has to handle long double as double as Go does not support long double.
func Xldexp(t *TLS, x float64, exp int32) float64 { return math.Ldexp(x, int(exp)) }
func Xlog(t *TLS, x float64) float64              { return math.Log(x) }
func Xlog10(t *TLS, x float64) float64            { return math.Log10(x) }
func Xround(t *TLS, x float64) float64            { return math.Round(x) }
func Xsin(t *TLS, x float64) float64              { return math.Sin(x) }
func Xsinf(t *TLS, x float32) float32             { return float32(math.Sin(float64(x))) }
func Xsinh(t *TLS, x float64) float64             { return math.Sinh(x) }
func Xsqrt(t *TLS, x float64) float64             { return math.Sqrt(x) }
func Xtan(t *TLS, x float64) float64              { return math.Tan(x) }
func Xtanh(t *TLS, x float64) float64             { return math.Tanh(x) }

var nextRand = uint64(1)

// int rand(void);
func Xrand(t *TLS) int32 {
	nextRand = nextRand*1103515245 + 12345
	return int32(uint32(nextRand / (math.MaxUint32 + 1) % math.MaxInt32))
}

func Xpow(t *TLS, x, y float64) float64 {
	r := math.Pow(x, y)
	if x > 0 && r == 1 && y >= -1.0000000000000000715e-18 && y < -1e-30 {
		r = 0.9999999999999999
	}
	return r
}

func Xfrexp(t *TLS, x float64, exp uintptr) float64 {
	f, e := math.Frexp(x)
	*(*int32)(unsafe.Pointer(exp)) = int32(e)
	return f
}

func Xmodf(t *TLS, x float64, iptr uintptr) float64 {
	i, f := math.Modf(x)
	*(*float64)(unsafe.Pointer(iptr)) = i
	return f
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

func AtomicLoadNUint16(ptr uintptr, memorder int16) uint16 {
	panic(todo(""))
}

func AtomicLoadNInt16(ptr uintptr, memorder int16) uint16 {
	panic(todo(""))
}

func AtomicStoreNInt16(ptr uintptr, val int16, memorder int32) {
	panic(todo(""))
}

func AtomicStoreNUint16(ptr uintptr, val uint16, memorder int32) {
	panic(todo(""))
}
