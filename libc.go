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
	"math"
	"math/bits"
	"sort"
	"unsafe"

	"modernc.org/libc/sys/types"
)

func X__builtin_inff(t *TLS) float32 { return float32(math.Inf(0)) }

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
