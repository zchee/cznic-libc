// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"modernc.org/libc/sys/types"
)

type (
	RawMem  [1<<50 - 1]byte
	long    = int64
	off64_t = types.Off_t
	ulong   = uint64
)
