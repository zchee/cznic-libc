// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build 386

package libc // import "modernc.org/libc"

import (
	"golang.org/x/sys/unix"
	"unsafe"

	"modernc.org/libc/signal"
	"modernc.org/libc/sys/stat"
	"modernc.org/libc/sys/types"
)

// int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
func Xsigaction(t *TLS, signum int32, act, oldact uintptr) int32 {
	// 	musl/arch/x32/ksigaction.h
	//
	//	struct k_sigaction {
	//		void (*handler)(int);
	//		unsigned long flags;
	//		void (*restorer)(void);
	//		unsigned mask[2];
	//	};
	type k_sigaction struct {
		handler  uintptr
		flags    ulong
		restorer uintptr
		mask     [2]uint32
	}

	var kact, koldact uintptr
	if act != 0 {
		kact = t.Alloc(int(unsafe.Sizeof(k_sigaction{})))
		defer Xfree(t, kact)
		*(*k_sigaction)(unsafe.Pointer(kact)) = k_sigaction{
			handler:  (*signal.Sigaction)(unsafe.Pointer(act)).F__sigaction_handler.Fsa_handler,
			flags:    ulong((*signal.Sigaction)(unsafe.Pointer(act)).Fsa_flags),
			restorer: (*signal.Sigaction)(unsafe.Pointer(act)).Fsa_restorer,
		}
		Xmemcpy(t, kact+unsafe.Offsetof(k_sigaction{}.mask), act+unsafe.Offsetof(signal.Sigaction{}.Fsa_mask), types.Size_t(unsafe.Sizeof(k_sigaction{}.mask)))
	}
	if oldact != 0 {
		panic(todo(""))
	}

	if _, _, err := unix.Syscall6(unix.SYS_RT_SIGACTION, uintptr(signal.SIGABRT), kact, koldact, unsafe.Sizeof(k_sigaction{}.mask), 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	if oldact != 0 {
		panic(todo(""))
	}

	return 0
}

// int fcntl(int fd, int cmd, ... /* arg */ );
func Xfcntl64(t *TLS, fd, cmd int32, args uintptr) int32 {
	var arg uintptr
	if args != 0 {
		arg = *(*uintptr)(unsafe.Pointer(args))
	}
	n, _, err := unix.Syscall(unix.SYS_FCNTL64, uintptr(fd), uintptr(cmd), arg)
	if err != 0 {
		if dmesgs {
			dmesg("%v: fd %v cmd %v", origin(1), fcntlCmdStr(fd), cmd)
		}
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %d %s %#x: %d", origin(1), fd, fcntlCmdStr(cmd), arg, n)
	}
	return int32(n)
}

// int lstat(const char *pathname, struct stat *statbuf);
func Xlstat64(t *TLS, pathname, statbuf uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_LSTAT64, pathname, statbuf, 0); err != 0 {
		if dmesgs {
			dmesg("%v: %q: %v", origin(1), GoString(pathname), err)
		}
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %q: ok", origin(1), GoString(pathname))
	}
	return 0
}

// int stat(const char *pathname, struct stat *statbuf);
func Xstat64(t *TLS, pathname, statbuf uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_STAT64, pathname, statbuf, 0); err != 0 {
		if dmesgs {
			dmesg("%v: %q: %v", origin(1), GoString(pathname), err)
		}
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %q: ok", origin(1), GoString(pathname))
	}
	return 0
}

// int fstat(int fd, struct stat *statbuf);
func Xfstat64(t *TLS, fd int32, statbuf uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_FSTAT64, uintptr(fd), statbuf, 0); err != 0 {
		if dmesgs {
			dmesg("%v: fd %d: %v", origin(1), fd, err)
		}
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %d, size %#x: ok\n%+v", origin(1), fd, (*stat.Stat64)(unsafe.Pointer(statbuf)).Fst_size, (*stat.Stat64)(unsafe.Pointer(statbuf)))
	}
	return 0
}

// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
func Xmmap64(t *TLS, addr uintptr, length types.Size_t, prot, flags, fd int32, offset types.Off_t) uintptr {
	data, _, err := unix.Syscall6(unix.SYS_MMAP2, addr, uintptr(length), uintptr(prot), uintptr(flags), uintptr(fd), uintptr(offset>>12))
	if err != 0 {
		if dmesgs {
			dmesg("%v: %v", origin(1), err)
		}
		t.setErrno(err)
		return ^uintptr(0) // (void*)-1
	}

	if dmesgs {
		dmesg("%v: %#x", origin(1), data)
	}
	return data
}

// int ftruncate(int fd, off_t length);
func Xftruncate64(t *TLS, fd int32, length types.Off_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_FTRUNCATE64, uintptr(fd), uintptr(length), uintptr(length>>32)); err != 0 {
		if dmesgs {
			dmesg("%v: fd %d: %v", origin(1), fd, err)
		}
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %d %#x: ok", origin(1), fd, length)
	}
	return 0
}

// off64_t lseek64(int fd, off64_t offset, int whence);
func Xlseek64(t *TLS, fd int32, offset types.Off_t, whence int32) types.Off64_t {
	bp := t.Alloc(int(unsafe.Sizeof(types.X__loff_t(0))))
	defer t.Free(int(unsafe.Sizeof(types.X__loff_t(0))))
	if _, _, err := unix.Syscall6(unix.SYS__LLSEEK, uintptr(fd), uintptr(offset>>32), uintptr(offset), bp, uintptr(whence), 0); err != 0 {
		if dmesgs {
			dmesg("%v: fd %v, off %#x, whence %v: %v", origin(1), fd, offset, whenceStr(whence), err)
		}
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: fd %v, off %#x, whence %v: %#x", origin(1), fd, offset, whenceStr(whence), *(*types.Off64_t)(unsafe.Pointer(bp)))
	}
	return *(*types.Off64_t)(unsafe.Pointer(bp))
}
