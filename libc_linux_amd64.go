// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

type (
	RawMem [1<<50 - 1]byte
	long   = int64
	ulong  = uint64
)
