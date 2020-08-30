// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE-GO file.

// Modifications Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc/errno"
)

// Random number state.
// We generate random temporary file names so that there's a good
// chance the file doesn't exist yet - keeps the number of tries in
// TempFile to a minimum.
var rand uint32
var randmu sync.Mutex

func reseed() uint32 {
	return uint32(time.Now().UnixNano() + int64(os.Getpid()))
}

func nextRandom(x uintptr) {
	randmu.Lock()
	r := rand
	if r == 0 {
		r = reseed()
	}
	r = r*1664525 + 1013904223 // constants from Numerical Recipes
	rand = r
	randmu.Unlock()
	copy((*RawMem)(unsafe.Pointer(x))[:6:6], fmt.Sprintf("%06d", int(1e9+r%1e9)%1e6))
}

func tempFile(s, x uintptr) (fd, err int) {
	const maxTry = 10000
	nconflict := 0
	for i := 0; i < maxTry; i++ {
		nextRandom(x)
		n, _, err := unix.Syscall(unix.SYS_OPEN, s, uintptr(os.O_RDWR|os.O_CREATE|os.O_EXCL), 0600)
		if err == 0 {
			return int(n), 0
		}

		if err != errno.EEXIST {
			return -1, int(err)
		}

		if nconflict++; nconflict > 10 {
			randmu.Lock()
			rand = reseed()
			nconflict = 0
			randmu.Unlock()
		}
	}
	return -1, errno.EEXIST
}
