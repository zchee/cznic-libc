// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc/errno"
	"modernc.org/libc/fcntl"
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
	if cmd == fcntl.F_SETFL {
		arg |= unix.O_LARGEFILE
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
		dmesg("%v: %d, size %#x: ok\n%+v", origin(1), fd, (*stat.Stat)(unsafe.Pointer(statbuf)).Fst_size, (*stat.Stat)(unsafe.Pointer(statbuf)))
	}
	return 0
}

// void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);
func Xmremap(t *TLS, old_address uintptr, old_size, new_size types.Size_t, flags int32, args uintptr) uintptr {
	var arg uintptr
	if args != 0 {
		arg = *(*uintptr)(unsafe.Pointer(args))
	}
	data, _, err := unix.Syscall6(unix.SYS_MREMAP, old_address, uintptr(old_size), uintptr(new_size), uintptr(flags), arg, 0)
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

func Xmmap(t *TLS, addr uintptr, length types.Size_t, prot, flags, fd int32, offset types.Off_t) uintptr {
	return Xmmap64(t, addr, length, prot, flags, fd, offset)
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
func Xlseek64(t *TLS, fd int32, offset types.Off_t, whence int32) types.Off_t {
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
		dmesg("%v: fd %v, off %#x, whence %v: %#x", origin(1), fd, offset, whenceStr(whence), *(*types.Off_t)(unsafe.Pointer(bp)))
	}
	return *(*types.Off_t)(unsafe.Pointer(bp))
}

// int utime(const char *filename, const struct utimbuf *times);
func Xutime(t *TLS, filename, times uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_UTIME, filename, times, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// unsigned int alarm(unsigned int seconds);
func Xalarm(t *TLS, seconds uint32) uint32 {
	n, _, err := unix.Syscall(unix.SYS_ALARM, uintptr(seconds), 0, 0)
	if err != 0 {
		panic(todo(""))
	}

	return uint32(n)
}

// int getrlimit(int resource, struct rlimit *rlim);
func Xgetrlimit64(t *TLS, resource int32, rlim uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_GETRLIMIT, uintptr(resource), uintptr(rlim), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// time_t time(time_t *tloc);
func Xtime(t *TLS, tloc uintptr) types.Time_t {
	n, _, err := unix.Syscall(unix.SYS_TIME, tloc, 0, 0)
	if err != 0 {
		t.setErrno(err)
		return types.Time_t(-1)
	}

	if tloc != 0 {
		*(*types.Time_t)(unsafe.Pointer(tloc)) = types.Time_t(n)
	}
	return types.Time_t(n)
}

// int mkdir(const char *path, mode_t mode);
func Xmkdir(t *TLS, path uintptr, mode types.Mode_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_MKDIR, path, uintptr(mode), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %q: ok", origin(1), GoString(path))
	}
	return 0
}

// int symlink(const char *target, const char *linkpath);
func Xsymlink(t *TLS, target, linkpath uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_SYMLINK, target, linkpath, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %q %q: ok", origin(1), GoString(target), GoString(linkpath))
	}
	return 0
}

// int chmod(const char *pathname, mode_t mode)
func Xchmod(t *TLS, pathname uintptr, mode types.Mode_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_CHMOD, pathname, uintptr(mode), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %q %#o: ok", origin(1), GoString(pathname), mode)
	}
	return 0
}

// int utimes(const char *filename, const struct timeval times[2]);
func Xutimes(t *TLS, filename, times uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_UTIMES, filename, times, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %q: ok", origin(1), GoString(filename))
	}
	return 0
}

// int unlink(const char *pathname);
func Xunlink(t *TLS, pathname uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_UNLINK, pathname, 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %q: ok", origin(1), GoString(pathname))
	}
	return 0
}

// int access(const char *pathname, int mode);
func Xaccess(t *TLS, pathname uintptr, mode int32) int32 {
	if _, _, err := unix.Syscall(unix.SYS_ACCESS, pathname, uintptr(mode), 0); err != 0 {
		if dmesgs {
			dmesg("%v: %q: %v", origin(1), GoString(pathname), err)
		}
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %q %#o: ok", origin(1), GoString(pathname), mode)
	}
	return 0
}

// int rmdir(const char *pathname);
func Xrmdir(t *TLS, pathname uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_RMDIR, pathname, 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	if dmesgs {
		dmesg("%v: %q: ok", origin(1), GoString(pathname))
	}
	return 0
}

// int rename(const char *oldpath, const char *newpath);
func Xrename(t *TLS, oldpath, newpath uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_RENAME, oldpath, newpath, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int mknod(const char *pathname, mode_t mode, dev_t dev);
func Xmknod(t *TLS, pathname uintptr, mode types.Mode_t, dev types.Dev_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_MKNOD, pathname, uintptr(mode), uintptr(dev)); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int chown(const char *pathname, uid_t owner, gid_t group);
func Xchown(t *TLS, pathname uintptr, owner types.Uid_t, group types.Gid_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_CHOWN, pathname, uintptr(owner), uintptr(group)); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int link(const char *oldpath, const char *newpath);
func Xlink(t *TLS, oldpath, newpath uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_LINK, oldpath, newpath, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int pipe(int pipefd[2]);
func Xpipe(t *TLS, pipefd uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_PIPE, pipefd, 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int dup2(int oldfd, int newfd);
func Xdup2(t *TLS, oldfd, newfd int32) int32 {
	n, _, err := unix.Syscall(unix.SYS_DUP2, uintptr(oldfd), uintptr(newfd), 0)
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return int32(n)
}

// ssize_t readlink(const char *restrict path, char *restrict buf, size_t bufsize);
func Xreadlink(t *TLS, path, buf uintptr, bufsize types.Size_t) types.Ssize_t {
	n, _, err := unix.Syscall(unix.SYS_READLINK, path, buf, uintptr(bufsize))
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return types.Ssize_t(n)
}

// FILE *fopen64(const char *pathname, const char *mode);
func Xfopen64(t *TLS, pathname, mode uintptr) uintptr {
	m := strings.ReplaceAll(GoString(mode), "b", "")
	var flags int
	switch m {
	case "r":
		flags = os.O_RDONLY
	case "r+":
		flags = os.O_RDWR
	case "w":
		flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	case "w+":
		flags = os.O_RDWR | os.O_CREATE | os.O_TRUNC
	case "a":
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	case "a+":
		flags = os.O_RDWR | os.O_CREATE | os.O_APPEND
	default:
		panic(m)
	}
	//TODO- flags |= fcntl.O_LARGEFILE
	fd, _, err := unix.Syscall(unix.SYS_OPEN, pathname, uintptr(flags|unix.O_LARGEFILE), 0666)
	if err != 0 {
		t.setErrno(err)
		return 0
	}

	if p := newFile(t, int32(fd)); p != 0 {
		return p
	}

	Xclose(t, int32(fd))
	t.setErrno(errno.ENOMEM)
	return 0
}
