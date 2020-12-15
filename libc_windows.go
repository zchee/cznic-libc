// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	gotime "time"
	"unsafe"

	"modernc.org/libc/errno"
	"modernc.org/libc/limits"
	"modernc.org/libc/sys/stat"
	"modernc.org/libc/sys/types"
	"modernc.org/libc/time"
)

// Keep these outside of the var block otherwise go generate will miss them.
var X__imp__environ uintptr //TODO must initialize

type (
	long  = int32
	ulong = uint32
)

type file uintptr

func (f file) fd() int32 {
	panic(todo(""))
}

func (f file) setFd(fd int32) {
	panic(todo(""))
}

func (f file) err() bool {
	panic(todo(""))
}

func (f file) setErr() {
	panic(todo(""))
}

func (f file) close(t *TLS) int32 {
	panic(todo(""))
	// r := Xclose(t, f.fd())
	// Xfree(t, uintptr(f))
	// if r < 0 {
	// 	return stdio.EOF
	// }
	// return 0
}

func newFile(t *TLS, fd int32) uintptr {
	panic(todo(""))
	// p := Xcalloc(t, 1, types.Size_t(unsafe.Sizeof(stdio.FILE{})))
	// if p == 0 {
	// 	return 0
	// }
	// file(p).setFd(fd)
	// return p
}

func fwrite(fd int32, b []byte) (int, error) {
	panic(todo(""))
	// if fd == unistd.STDOUT_FILENO {
	// 	return write(b)
	// }

	// if dmesgs {
	// 	dmesg("%v: fd %v: %s", origin(1), fd, b)
	// }
	// return unix.Write(int(fd), b) //TODO use Xwrite
}

// int fprintf(FILE *stream, const char *format, ...);
func Xfprintf(t *TLS, stream, format, args uintptr) int32 {
	panic(todo(""))
	// 	n, _ := fwrite((*stdio.FILE)(unsafe.Pointer(stream)).F_fileno, printf(format, args))
	// 	return int32(n)
}

// int usleep(useconds_t usec);
func Xusleep(t *TLS, usec types.Useconds_t) int32 {
	gotime.Sleep(gotime.Microsecond * gotime.Duration(usec))
	return 0
}

// int getrusage(int who, struct rusage *usage);
func Xgetrusage(t *TLS, who int32, usage uintptr) int32 {
	panic(todo(""))
	// if _, _, err := unix.Syscall(unix.SYS_GETRUSAGE, uintptr(who), usage, 0); err != 0 {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// return 0
}

// char *fgets(char *s, int size, FILE *stream);
func Xfgets(t *TLS, s uintptr, size int32, stream uintptr) uintptr {
	panic(todo(""))
	// fd := int((*stdio.FILE)(unsafe.Pointer(stream)).F_fileno)
	// var b []byte
	// buf := [1]byte{}
	// for ; size > 0; size-- {
	// 	n, err := unix.Read(fd, buf[:])
	// 	if n != 0 {
	// 		b = append(b, buf[0])
	// 		if buf[0] == '\n' {
	// 			b = append(b, 0)
	// 			copy((*RawMem)(unsafe.Pointer(s))[:len(b):len(b)], b)
	// 			return s
	// 		}

	// 		continue
	// 	}

	// 	switch {
	// 	case n == 0 && err == nil && len(b) == 0:
	// 		return 0
	// 	default:
	// 		panic(todo(""))
	// 	}

	// 	// if err == nil {
	// 	// 	panic("internal error")
	// 	// }

	// 	// if len(b) != 0 {
	// 	// 		b = append(b, 0)
	// 	// 		copy((*RawMem)(unsafe.Pointer(s)[:len(b)]), b)
	// 	// 		return s
	// 	// }

	// 	// t.setErrno(err)
	// }
	// panic(todo(""))
}

// int lstat(const char *pathname, struct stat *statbuf);
func Xlstat(t *TLS, pathname, statbuf uintptr) int32 {
	return Xlstat64(t, pathname, statbuf)
}

// int stat(const char *pathname, struct stat *statbuf);
func Xstat(t *TLS, pathname, statbuf uintptr) int32 {
	return Xstat64(t, pathname, statbuf)
}

// int chdir(const char *path);
func Xchdir(t *TLS, path uintptr) int32 {
	panic(todo(""))
	// if _, _, err := unix.Syscall(unix.SYS_CHDIR, path, 0, 0); err != 0 {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// if dmesgs {
	// 	dmesg("%v: %q: ok", origin(1), GoString(path))
	// }
	// return 0
}

var localtime time.Tm

// struct tm *localtime(const time_t *timep);
func Xlocaltime(_ *TLS, timep uintptr) uintptr {
	panic(todo(""))
	// loc := gotime.Local
	// if r := getenv(Environ(), "TZ"); r != 0 {
	// 	zone, off := parseZone(GoString(r))
	// 	loc = gotime.FixedZone(zone, -off)
	// }
	// ut := *(*unix.Time_t)(unsafe.Pointer(timep))
	// t := gotime.Unix(int64(ut), 0).In(loc)
	// localtime.Ftm_sec = int32(t.Second())
	// localtime.Ftm_min = int32(t.Minute())
	// localtime.Ftm_hour = int32(t.Hour())
	// localtime.Ftm_mday = int32(t.Day())
	// localtime.Ftm_mon = int32(t.Month() - 1)
	// localtime.Ftm_year = int32(t.Year() - 1900)
	// localtime.Ftm_wday = int32(t.Weekday())
	// localtime.Ftm_yday = int32(t.YearDay())
	// localtime.Ftm_isdst = Bool32(isTimeDST(t))
	// return uintptr(unsafe.Pointer(&localtime))
}

// struct tm *localtime_r(const time_t *timep, struct tm *result);
func Xlocaltime_r(_ *TLS, timep, result uintptr) uintptr {
	panic(todo(""))
	// loc := gotime.Local
	// if r := getenv(Environ(), "TZ"); r != 0 {
	// 	zone, off := parseZone(GoString(r))
	// 	loc = gotime.FixedZone(zone, -off)
	// }
	// ut := *(*unix.Time_t)(unsafe.Pointer(timep))
	// t := gotime.Unix(int64(ut), 0).In(loc)
	// (*time.Tm)(unsafe.Pointer(result)).Ftm_sec = int32(t.Second())
	// (*time.Tm)(unsafe.Pointer(result)).Ftm_min = int32(t.Minute())
	// (*time.Tm)(unsafe.Pointer(result)).Ftm_hour = int32(t.Hour())
	// (*time.Tm)(unsafe.Pointer(result)).Ftm_mday = int32(t.Day())
	// (*time.Tm)(unsafe.Pointer(result)).Ftm_mon = int32(t.Month() - 1)
	// (*time.Tm)(unsafe.Pointer(result)).Ftm_year = int32(t.Year() - 1900)
	// (*time.Tm)(unsafe.Pointer(result)).Ftm_wday = int32(t.Weekday())
	// (*time.Tm)(unsafe.Pointer(result)).Ftm_yday = int32(t.YearDay())
	// (*time.Tm)(unsafe.Pointer(result)).Ftm_isdst = Bool32(isTimeDST(t))
	// return result
}

// int open(const char *pathname, int flags, ...);
func Xopen(t *TLS, pathname uintptr, flags int32, args uintptr) int32 {
	return Xopen64(t, pathname, flags, args)
}

// int open(const char *pathname, int flags, ...);
func Xopen64(t *TLS, pathname uintptr, flags int32, args uintptr) int32 {
	panic(todo(""))
	// var mode types.Mode_t
	// if args != 0 {
	// 	mode = *(*types.Mode_t)(unsafe.Pointer(args))
	// }
	// fdcwd := fcntl.AT_FDCWD
	// n, _, err := unix.Syscall6(unix.SYS_OPENAT, uintptr(fdcwd), pathname, uintptr(flags), uintptr(mode), 0, 0)
	// if err != 0 {
	// 	if dmesgs {
	// 		dmesg("%v: %q %#x: %v", origin(1), GoString(pathname), flags, err)
	// 	}
	// 	t.setErrno(err)
	// 	return -1
	// }

	// if dmesgs {
	// 	dmesg("%v: %q flags %#x mode %#o: fd %v", origin(1), GoString(pathname), flags, mode, n)
	// }
	// return int32(n)
}

// off_t lseek(int fd, off_t offset, int whence);
func Xlseek(t *TLS, fd int32, offset types.Off_t, whence int32) types.Off_t {
	return types.Off_t(Xlseek64(t, fd, offset, whence))
}

func whenceStr(whence int32) string {
	panic(todo(""))
	// 	switch whence {
	// 	case fcntl.SEEK_CUR:
	// 		return "SEEK_CUR"
	// 	case fcntl.SEEK_END:
	// 		return "SEEK_END"
	// 	case fcntl.SEEK_SET:
	// 		return "SEEK_SET"
	// 	default:
	// 		return fmt.Sprintf("whence(%d)", whence)
	// 	}
}

var fsyncStatbuf stat.Stat

// int fsync(int fd);
func Xfsync(t *TLS, fd int32) int32 {
	panic(todo(""))
	// if noFsync {
	// 	// Simulate -DSQLITE_NO_SYNC for sqlite3 testfixture, see function full_sync in sqlite3.c
	// 	return Xfstat(t, fd, uintptr(unsafe.Pointer(&fsyncStatbuf)))
	// }

	// if _, _, err := unix.Syscall(unix.SYS_FSYNC, uintptr(fd), 0, 0); err != 0 {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// if dmesgs {
	// 	dmesg("%v: %d: ok", origin(1), fd)
	// }
	// return 0
}

// long sysconf(int name);
func Xsysconf(t *TLS, name int32) long {
	panic(todo(""))
	// switch name {
	// case unistd.X_SC_PAGESIZE:
	// 	return long(unix.Getpagesize())
	// }

	// panic(todo(""))
}

// int close(int fd);
func Xclose(t *TLS, fd int32) int32 {
	panic(todo(""))
	// if _, _, err := unix.Syscall(unix.SYS_CLOSE, uintptr(fd), 0, 0); err != 0 {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// if dmesgs {
	// 	dmesg("%v: %d: ok", origin(1), fd)
	// }
	// return 0
}

// char *getcwd(char *buf, size_t size);
func Xgetcwd(t *TLS, buf uintptr, size types.Size_t) uintptr {
	panic(todo(""))
	// n, _, err := unix.Syscall(unix.SYS_GETCWD, buf, uintptr(size), 0)
	// if err != 0 {
	// 	t.setErrno(err)
	// 	return 0
	// }

	// if dmesgs {
	// 	dmesg("%v: %q: ok", origin(1), GoString(buf))
	// }
	// return n
}

// int fstat(int fd, struct stat *statbuf);
func Xfstat(t *TLS, fd int32, statbuf uintptr) int32 {
	return Xfstat64(t, fd, statbuf)
}

// int ftruncate(int fd, off_t length);
func Xftruncate(t *TLS, fd int32, length types.Off_t) int32 {
	return Xftruncate64(t, fd, length)
}

// int fcntl(int fd, int cmd, ... /* arg */ );
func Xfcntl(t *TLS, fd, cmd int32, args uintptr) int32 {
	return Xfcntl64(t, fd, cmd, args)
}

// ssize_t read(int fd, void *buf, size_t count);
func Xread(t *TLS, fd int32, buf uintptr, count types.Size_t) types.Ssize_t {
	panic(todo(""))
	// n, _, err := unix.Syscall(unix.SYS_READ, uintptr(fd), buf, uintptr(count))
	// if err != 0 {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// if dmesgs {
	// 	// dmesg("%v: %d %#x: %#x\n%s", origin(1), fd, count, n, hex.Dump(GoBytes(buf, int(n))))
	// 	dmesg("%v: %d %#x: %#x", origin(1), fd, count, n)
	// }
	// return types.Ssize_t(n)
}

// ssize_t write(int fd, const void *buf, size_t count);
func Xwrite(t *TLS, fd int32, buf uintptr, count types.Size_t) types.Ssize_t {
	panic(todo(""))
	// n, _, err := unix.Syscall(unix.SYS_WRITE, uintptr(fd), buf, uintptr(count))
	// if err != 0 {
	// 	if dmesgs {
	// 		dmesg("%v: fd %v, count %#x: %v", origin(1), fd, count, err)
	// 	}
	// 	t.setErrno(err)
	// 	return -1
	// }

	// if dmesgs {
	// 	// dmesg("%v: %d %#x: %#x\n%s", origin(1), fd, count, n, hex.Dump(GoBytes(buf, int(n))))
	// 	dmesg("%v: %d %#x: %#x", origin(1), fd, count, n)
	// }
	// return types.Ssize_t(n)
}

// int fchmod(int fd, mode_t mode);
func Xfchmod(t *TLS, fd int32, mode types.Mode_t) int32 {
	panic(todo(""))
	// if _, _, err := unix.Syscall(unix.SYS_FCHMOD, uintptr(fd), uintptr(mode), 0); err != 0 {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// if dmesgs {
	// 	dmesg("%v: %d %#o: ok", origin(1), fd, mode)
	// }
	// return 0
}

// // int fchown(int fd, uid_t owner, gid_t group);
// func Xfchown(t *TLS, fd int32, owner types.Uid_t, group types.Gid_t) int32 {
// 	if _, _, err := unix.Syscall(unix.SYS_FCHOWN, uintptr(fd), uintptr(owner), uintptr(group)); err != 0 {
// 		t.setErrno(err)
// 		return -1
// 	}
//
// 	return 0
// }

// // uid_t geteuid(void);
// func Xgeteuid(t *TLS) types.Uid_t {
// 	n, _, _ := unix.Syscall(unix.SYS_GETEUID, 0, 0, 0)
// 	return types.Uid_t(n)
// }

// int munmap(void *addr, size_t length);
func Xmunmap(t *TLS, addr uintptr, length types.Size_t) int32 {
	panic(todo(""))
	// if _, _, err := unix.Syscall(unix.SYS_MUNMAP, addr, uintptr(length), 0); err != 0 {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// return 0
}

// int gettimeofday(struct timeval *tv, struct timezone *tz);
func Xgettimeofday(t *TLS, tv, tz uintptr) int32 {
	panic(todo(""))
	// if tz != 0 {
	// 	panic(todo(""))
	// }

	// var tvs unix.Timeval
	// err := unix.Gettimeofday(&tvs)
	// if err != nil {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// *(*unix.Timeval)(unsafe.Pointer(tv)) = tvs
	// return 0
}

// int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
func Xgetsockopt(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
	// if _, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(sockfd), uintptr(level), uintptr(optname), optval, optlen, 0); err != 0 {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// return 0
}

// // int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
func Xsetsockopt(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// int ioctl(int fd, unsigned long request, ...);
func Xioctl(t *TLS, fd int32, request ulong, va uintptr) int32 {
	panic(todo(""))
	// var argp uintptr
	// if va != 0 {
	// 	argp = VaUintptr(&va)
	// }
	// n, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), argp)
	// if err != 0 {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// return int32(n)
}

// int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
func Xgetsockname(t *TLS, sockfd int32, addr, addrlen uintptr) int32 {
	panic(todo(""))
	// if _, _, err := unix.Syscall(unix.SYS_GETSOCKNAME, uintptr(sockfd), addr, addrlen); err != 0 {
	// 	if dmesgs {
	// 		dmesg("%v: fd %v: %v", origin(1), sockfd, err)
	// 	}
	// 	t.setErrno(err)
	// 	return -1
	// }

	// return 0
}

// int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
func Xselect(t *TLS, nfds int32, readfds, writefds, exceptfds, timeout uintptr) int32 {
	panic(todo(""))
	// n, err := unix.Select(
	// 	int(nfds),
	// 	(*unix.FdSet)(unsafe.Pointer(readfds)),
	// 	(*unix.FdSet)(unsafe.Pointer(writefds)),
	// 	(*unix.FdSet)(unsafe.Pointer(exceptfds)),
	// 	(*unix.Timeval)(unsafe.Pointer(timeout)),
	// )
	// if err != nil {
	// 	t.setErrno(err)
	// 	return -1
	// }

	// return int32(n)
}

// int mkfifo(const char *pathname, mode_t mode);
func Xmkfifo(t *TLS, pathname uintptr, mode types.Mode_t) int32 {
	panic(todo(""))
	// 	if err := unix.Mkfifo(GoString(pathname), mode); err != nil {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return 0
}

// mode_t umask(mode_t mask);
func Xumask(t *TLS, mask types.Mode_t) types.Mode_t {
	panic(todo(""))
	// 	n, _, _ := unix.Syscall(unix.SYS_UMASK, uintptr(mask), 0, 0)
	// 	return types.Mode_t(n)
}

// int execvp(const char *file, char *const argv[]);
func Xexecvp(t *TLS, file, argv uintptr) int32 {
	panic(todo(""))
	// 	if _, _, err := unix.Syscall(unix.SYS_EXECVE, file, argv, Environ()); err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return 0
}

// pid_t waitpid(pid_t pid, int *wstatus, int options);
func Xwaitpid(t *TLS, pid types.Pid_t, wstatus uintptr, optname int32) types.Pid_t {
	panic(todo(""))
	// 	n, _, err := unix.Syscall6(unix.SYS_WAIT4, uintptr(pid), wstatus, uintptr(optname), 0, 0, 0)
	// 	if err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return types.Pid_t(n)
}

// int uname(struct utsname *buf);
func Xuname(t *TLS, buf uintptr) int32 {
	panic(todo(""))
	// 	if _, _, err := unix.Syscall(unix.SYS_UNAME, buf, 0, 0); err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return 0
}

// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
func Xrecv(t *TLS, sockfd int32, buf uintptr, len types.Size_t, flags int32) types.Ssize_t {
	panic(todo(""))
	// 	n, _, err := unix.Syscall6(unix.SYS_RECVFROM, uintptr(sockfd), buf, uintptr(len), uintptr(flags), 0, 0)
	// 	if err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return types.Ssize_t(n)
}

// ssize_t send(int sockfd, const void *buf, size_t len, int flags);
func Xsend(t *TLS, sockfd int32, buf uintptr, len types.Size_t, flags int32) types.Ssize_t {
	panic(todo(""))
	// 	n, _, err := unix.Syscall6(unix.SYS_SENDTO, uintptr(sockfd), buf, uintptr(len), uintptr(flags), 0, 0)
	// 	if err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return types.Ssize_t(n)
}

// int shutdown(int sockfd, int how);
func Xshutdown(t *TLS, sockfd, how int32) int32 {
	panic(todo(""))
	// 	if _, _, err := unix.Syscall(unix.SYS_SHUTDOWN, uintptr(sockfd), uintptr(how), 0); err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return 0
}

// int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
func Xgetpeername(t *TLS, sockfd int32, addr uintptr, addrlen uintptr) int32 {
	panic(todo(""))
	// 	if _, _, err := unix.Syscall(unix.SYS_GETPEERNAME, uintptr(sockfd), addr, uintptr(addrlen)); err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return 0
}

// int socket(int domain, int type, int protocol);
func Xsocket(t *TLS, domain, type1, protocol int32) int32 {
	panic(todo(""))
	// 	n, _, err := unix.Syscall(unix.SYS_SOCKET, uintptr(domain), uintptr(type1), uintptr(protocol))
	// 	if err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return int32(n)
}

// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
func Xbind(t *TLS, sockfd int32, addr uintptr, addrlen uint32) int32 {
	panic(todo(""))
	// 	n, _, err := unix.Syscall(unix.SYS_BIND, uintptr(sockfd), addr, uintptr(addrlen))
	// 	if err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return int32(n)
}

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
func Xconnect(t *TLS, sockfd int32, addr uintptr, addrlen uint32) int32 {
	panic(todo(""))
	// 	if _, _, err := unix.Syscall(unix.SYS_CONNECT, uintptr(sockfd), addr, uintptr(addrlen)); err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return 0
}

// int listen(int sockfd, int backlog);
func Xlisten(t *TLS, sockfd, backlog int32) int32 {
	panic(todo(""))
	// 	if _, _, err := unix.Syscall(unix.SYS_LISTEN, uintptr(sockfd), uintptr(backlog), 0); err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return 0
}

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
func Xaccept(t *TLS, sockfd int32, addr uintptr, addrlen uintptr) int32 {
	panic(todo(""))
	// 	n, _, err := unix.Syscall6(unix.SYS_ACCEPT4, uintptr(sockfd), addr, uintptr(addrlen), 0, 0, 0)
	// 	if err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return int32(n)
}

// int getrlimit(int resource, struct rlimit *rlim);
func Xgetrlimit(t *TLS, resource int32, rlim uintptr) int32 {
	return Xgetrlimit64(t, resource, rlim)
}

// int setrlimit(int resource, const struct rlimit *rlim);
func Xsetrlimit(t *TLS, resource int32, rlim uintptr) int32 {
	return Xsetrlimit64(t, resource, rlim)
}

// int setrlimit(int resource, const struct rlimit *rlim);
func Xsetrlimit64(t *TLS, resource int32, rlim uintptr) int32 {
	panic(todo(""))
	// 	if _, _, err := unix.Syscall(unix.SYS_SETRLIMIT, uintptr(resource), uintptr(rlim), 0); err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return 0
}

// // uid_t getuid(void);
// func Xgetuid(t *TLS) types.Uid_t {
// 	return types.Uid_t(os.Getuid())
// }

// pid_t getpid(void);
func Xgetpid(t *TLS) int32 {
	return int32(os.Getpid())
}

// int system(const char *command);
func Xsystem(t *TLS, command uintptr) int32 {
	s := GoString(command)
	if command == 0 {
		panic(todo(""))
	}

	cmd := exec.Command("sh", "-c", s)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		ps := err.(*exec.ExitError)
		return int32(ps.ExitCode())
	}

	return 0
}

// var staticGetpwuid pwd.Passwd
//
// func init() {
// 	atExit = append(atExit, func() { closePasswd(&staticGetpwuid) })
// }
//
// func closePasswd(p *pwd.Passwd) {
// 	Xfree(nil, p.Fpw_name)
// 	Xfree(nil, p.Fpw_passwd)
// 	Xfree(nil, p.Fpw_gecos)
// 	Xfree(nil, p.Fpw_dir)
// 	Xfree(nil, p.Fpw_shell)
// 	*p = pwd.Passwd{}
// }

// struct passwd *getpwuid(uid_t uid);
func Xgetpwuid(t *TLS, uid uint32) uintptr {
	panic(todo(""))
	// 	f, err := os.Open("/etc/passwd")
	// 	if err != nil {
	// 		panic(todo("", err))
	// 	}
	//
	// 	defer f.Close()
	//
	// 	sid := strconv.Itoa(int(uid))
	// 	sc := bufio.NewScanner(f)
	// 	for sc.Scan() {
	// 		// eg. "root:x:0:0:root:/root:/bin/bash"
	// 		a := strings.Split(sc.Text(), ":")
	// 		if len(a) < 7 {
	// 			panic(todo(""))
	// 		}
	//
	// 		if a[2] == sid {
	// 			uid, err := strconv.Atoi(a[2])
	// 			if err != nil {
	// 				panic(todo(""))
	// 			}
	//
	// 			gid, err := strconv.Atoi(a[3])
	// 			if err != nil {
	// 				panic(todo(""))
	// 			}
	//
	// 			closePasswd(&staticGetpwuid)
	// 			gecos := a[4]
	// 			if strings.Contains(gecos, ",") {
	// 				a := strings.Split(gecos, ",")
	// 				gecos = a[0]
	// 			}
	// 			initPasswd(t, &staticGetpwuid, a[0], a[1], uint32(uid), uint32(gid), gecos, a[5], a[6])
	// 			return uintptr(unsafe.Pointer(&staticGetpwuid))
	// 		}
	// 	}
	//
	// 	if sc.Err() != nil {
	// 		panic(todo(""))
	// 	}
	//
	// 	return 0
}

// func initPasswd(t *TLS, p *pwd.Passwd, name, pwd string, uid, gid uint32, gecos, dir, shell string) {
// 	p.Fpw_name = cString(t, name)
// 	p.Fpw_passwd = cString(t, pwd)
// 	p.Fpw_uid = uid
// 	p.Fpw_gid = gid
// 	p.Fpw_gecos = cString(t, gecos)
// 	p.Fpw_dir = cString(t, dir)
// 	p.Fpw_shell = cString(t, shell)
// }

// int setvbuf(FILE *stream, char *buf, int mode, size_t size);
func Xsetvbuf(t *TLS, stream, buf uintptr, mode int32, size types.Size_t) int32 {
	return 0 //TODO
}

// int raise(int sig);
func Xraise(t *TLS, sig int32) int32 {
	panic(todo(""))
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
	panic(todo(""))
	// 	if stream == 0 {
	// 		t.setErrno(errno.EBADF)
	// 		return -1
	// 	}
	//
	// 	if fd := (*stdio.FILE)(unsafe.Pointer(stream)).F_fileno; fd >= 0 {
	// 		return fd
	// 	}
	//
	// 	t.setErrno(errno.EBADF)
	// 	return -1
}

// var staticGetpwnam pwd.Passwd
//
// func init() {
// 	atExit = append(atExit, func() { closePasswd(&staticGetpwnam) })
// }
//
// // struct passwd *getpwnam(const char *name);
// func Xgetpwnam(t *TLS, name uintptr) uintptr {
// 	f, err := os.Open("/etc/passwd")
// 	if err != nil {
// 		panic(todo("", err))
// 	}
//
// 	defer f.Close()
//
// 	sname := GoString(name)
// 	sc := bufio.NewScanner(f)
// 	for sc.Scan() {
// 		// eg. "root:x:0:0:root:/root:/bin/bash"
// 		a := strings.Split(sc.Text(), ":")
// 		if len(a) < 7 {
// 			panic(todo(""))
// 		}
//
// 		if a[0] == sname {
// 			uid, err := strconv.Atoi(a[2])
// 			if err != nil {
// 				panic(todo(""))
// 			}
//
// 			gid, err := strconv.Atoi(a[3])
// 			if err != nil {
// 				panic(todo(""))
// 			}
//
// 			closePasswd(&staticGetpwnam)
// 			gecos := a[4]
// 			if strings.Contains(gecos, ",") {
// 				a := strings.Split(gecos, ",")
// 				gecos = a[0]
// 			}
// 			initPasswd(t, &staticGetpwnam, a[0], a[1], uint32(uid), uint32(gid), gecos, a[5], a[6])
// 			return uintptr(unsafe.Pointer(&staticGetpwnam))
// 		}
// 	}
//
// 	if sc.Err() != nil {
// 		panic(todo(""))
// 	}
//
// 	return 0
// }
//
// var staticGetgrnam grp.Group
//
// func init() {
// 	atExit = append(atExit, func() { closeGroup(&staticGetgrnam) })
// }
//
// // struct group *getgrnam(const char *name);
// func Xgetgrnam(t *TLS, name uintptr) uintptr {
// 	f, err := os.Open("/etc/group")
// 	if err != nil {
// 		panic(todo(""))
// 	}
//
// 	defer f.Close()
//
// 	sname := GoString(name)
// 	sc := bufio.NewScanner(f)
// 	for sc.Scan() {
// 		// eg. "root:x:0:"
// 		a := strings.Split(sc.Text(), ":")
// 		if len(a) < 4 {
// 			panic(todo(""))
// 		}
//
// 		if a[0] == sname {
// 			closeGroup(&staticGetgrnam)
// 			gid, err := strconv.Atoi(a[2])
// 			if err != nil {
// 				panic(todo(""))
// 			}
//
// 			var names []string
// 			if a[3] != "" {
// 				names = strings.Split(a[3], ",")
// 			}
// 			initGroup(t, &staticGetgrnam, a[0], a[1], uint32(gid), names)
// 			return uintptr(unsafe.Pointer(&staticGetgrnam))
// 		}
// 	}
//
// 	if sc.Err() != nil {
// 		panic(todo(""))
// 	}
//
// 	return 0
// }
//
// func closeGroup(p *grp.Group) {
// 	Xfree(nil, p.Fgr_name)
// 	Xfree(nil, p.Fgr_passwd)
// 	if p.Fgr_mem != 0 {
// 		panic(todo(""))
// 	}
//
// 	*p = grp.Group{}
// }
//
// func initGroup(t *TLS, p *grp.Group, name, pwd string, gid uint32, names []string) {
// 	p.Fgr_name = cString(t, name)
// 	p.Fgr_passwd = cString(t, pwd)
// 	p.Fgr_gid = gid
// 	p.Fgr_mem = 0
// 	if len(names) != 0 {
// 		panic(todo("%q %q %v %q %v", name, pwd, gid, names, len(names)))
// 	}
// }
//
// func init() {
// 	atExit = append(atExit, func() { closeGroup(&staticGetgrgid) })
// }
//
// var staticGetgrgid grp.Group
//
// // struct group *getgrgid(gid_t gid);
// func Xgetgrgid(t *TLS, gid uint32) uintptr {
// 	f, err := os.Open("/etc/group")
// 	if err != nil {
// 		panic(todo(""))
// 	}
//
// 	defer f.Close()
//
// 	sid := strconv.Itoa(int(gid))
// 	sc := bufio.NewScanner(f)
// 	for sc.Scan() {
// 		// eg. "root:x:0:"
// 		a := strings.Split(sc.Text(), ":")
// 		if len(a) < 4 {
// 			panic(todo(""))
// 		}
//
// 		if a[2] == sid {
// 			closeGroup(&staticGetgrgid)
// 			var names []string
// 			if a[3] != "" {
// 				names = strings.Split(a[3], ",")
// 			}
// 			initGroup(t, &staticGetgrgid, a[0], a[1], gid, names)
// 			return uintptr(unsafe.Pointer(&staticGetgrgid))
// 		}
// 	}
//
// 	if sc.Err() != nil {
// 		panic(todo(""))
// 	}
//
// 	return 0
// }

// int mkstemps(char *template, int suffixlen);
func Xmkstemps(t *TLS, template uintptr, suffixlen int32) int32 {
	return Xmkstemps64(t, template, suffixlen)
}

// int mkstemps(char *template, int suffixlen);
func Xmkstemps64(t *TLS, template uintptr, suffixlen int32) int32 {
	panic(todo(""))
	// 	len := uintptr(Xstrlen(t, template))
	// 	x := template + uintptr(len-6) - uintptr(suffixlen)
	// 	for i := uintptr(0); i < 6; i++ {
	// 		if *(*byte)(unsafe.Pointer(x + i)) != 'X' {
	// 			t.setErrno(errno.EINVAL)
	// 			return -1
	// 		}
	// 	}
	//
	// 	fd, err := tempFile(template, x)
	// 	if err != 0 {
	// 		t.setErrno(err)
	// 		return -1
	// 	}
	//
	// 	return int32(fd)
}

// int mkstemp(char *template);
func Xmkstemp64(t *TLS, template uintptr) int32 {
	return Xmkstemps64(t, template, 0)
}

// func newFtsent(t *TLS, info int, path string, stat *unix.Stat_t, err syscall.Errno) (r *fts.FTSENT) {
// 	var statp uintptr
// 	if stat != nil {
// 		statp = mustMalloc(t, types.Size_t(unsafe.Sizeof(unix.Stat_t{})))
// 		*(*unix.Stat_t)(unsafe.Pointer(statp)) = *stat
// 	}
// 	return &fts.FTSENT{
// 		Ffts_info:    uint16(info),
// 		Ffts_path:    mustCString(path),
// 		Ffts_pathlen: uint16(len(path)),
// 		Ffts_statp:   statp,
// 		Ffts_errno:   int32(err),
// 	}
// }
//
// func newCFtsent(t *TLS, info int, path string, stat *unix.Stat_t, err syscall.Errno) uintptr {
// 	p := mustCalloc(t, types.Size_t(unsafe.Sizeof(fts.FTSENT{})))
// 	*(*fts.FTSENT)(unsafe.Pointer(p)) = *newFtsent(t, info, path, stat, err)
// 	return p
// }
//
// func ftsentClose(t *TLS, p uintptr) {
// 	Xfree(t, (*fts.FTSENT)(unsafe.Pointer(p)).Ffts_path)
// 	Xfree(t, (*fts.FTSENT)(unsafe.Pointer(p)).Ffts_statp)
// }

type ftstream struct {
	s []uintptr
	x int
}

// func (f *ftstream) close(t *TLS) {
// 	for _, p := range f.s {
// 		ftsentClose(t, p)
// 		Xfree(t, p)
// 	}
// 	*f = ftstream{}
// }
//
// // FTS *fts_open(char * const *path_argv, int options, int (*compar)(const FTSENT **, const FTSENT **));
// func Xfts_open(t *TLS, path_argv uintptr, options int32, compar uintptr) uintptr {
// 	return Xfts64_open(t, path_argv, options, compar)
// }

// FTS *fts_open(char * const *path_argv, int options, int (*compar)(const FTSENT **, const FTSENT **));
func Xfts64_open(t *TLS, path_argv uintptr, options int32, compar uintptr) uintptr {
	panic(todo(""))
	// 	f := &ftstream{}
	//
	// 	var walk func(string)
	// 	walk = func(path string) {
	// 		var fi os.FileInfo
	// 		var err error
	// 		switch {
	// 		case options&fts.FTS_LOGICAL != 0:
	// 			fi, err = os.Stat(path)
	// 		case options&fts.FTS_PHYSICAL != 0:
	// 			fi, err = os.Lstat(path)
	// 		default:
	// 			panic(todo(""))
	// 		}
	//
	// 		if err != nil {
	// 			panic(todo(""))
	// 		}
	//
	// 		var statp *unix.Stat_t
	// 		if options&fts.FTS_NOSTAT == 0 {
	// 			var stat unix.Stat_t
	// 			switch {
	// 			case options&fts.FTS_LOGICAL != 0:
	// 				if err := unix.Stat(path, &stat); err != nil {
	// 					panic(todo(""))
	// 				}
	// 			case options&fts.FTS_PHYSICAL != 0:
	// 				if err := unix.Lstat(path, &stat); err != nil {
	// 					panic(todo(""))
	// 				}
	// 			default:
	// 				panic(todo(""))
	// 			}
	//
	// 			statp = &stat
	// 		}
	//
	// 	out:
	// 		switch {
	// 		case fi.IsDir():
	// 			f.s = append(f.s, newCFtsent(t, fts.FTS_D, path, statp, 0))
	// 			g, err := os.Open(path)
	// 			switch x := err.(type) {
	// 			case nil:
	// 				// ok
	// 			case *os.PathError:
	// 				f.s = append(f.s, newCFtsent(t, fts.FTS_DNR, path, statp, errno.EACCES))
	// 				break out
	// 			default:
	// 				panic(todo("%q: %v %T", path, x, x))
	// 			}
	//
	// 			names, err := g.Readdirnames(-1)
	// 			g.Close()
	// 			if err != nil {
	// 				panic(todo(""))
	// 			}
	//
	// 			for _, name := range names {
	// 				walk(path + "/" + name)
	// 				if f == nil {
	// 					break out
	// 				}
	// 			}
	//
	// 			f.s = append(f.s, newCFtsent(t, fts.FTS_DP, path, statp, 0))
	// 		default:
	// 			info := fts.FTS_F
	// 			if fi.Mode()&os.ModeSymlink != 0 {
	// 				info = fts.FTS_SL
	// 			}
	// 			switch {
	// 			case statp != nil:
	// 				f.s = append(f.s, newCFtsent(t, info, path, statp, 0))
	// 			case options&fts.FTS_NOSTAT != 0:
	// 				f.s = append(f.s, newCFtsent(t, fts.FTS_NSOK, path, nil, 0))
	// 			default:
	// 				panic(todo(""))
	// 			}
	// 		}
	// 	}
	//
	// 	for {
	// 		p := *(*uintptr)(unsafe.Pointer(path_argv))
	// 		if p == 0 {
	// 			if f == nil {
	// 				return 0
	// 			}
	//
	// 			if compar != 0 {
	// 				panic(todo(""))
	// 			}
	//
	// 			return addObject(f)
	// 		}
	//
	// 		walk(GoString(p))
	// 		path_argv += unsafe.Sizeof(uintptr(0))
	// 	}
}

// FTSENT *fts_read(FTS *ftsp);
func Xfts_read(t *TLS, ftsp uintptr) uintptr {
	return Xfts64_read(t, ftsp)
}

// FTSENT *fts_read(FTS *ftsp);
func Xfts64_read(t *TLS, ftsp uintptr) uintptr {
	panic(todo(""))
	// 	f := getObject(ftsp).(*ftstream)
	// 	if f.x == len(f.s) {
	// 		t.setErrno(0)
	// 		return 0
	// 	}
	//
	// 	r := f.s[f.x]
	// 	if e := (*fts.FTSENT)(unsafe.Pointer(r)).Ffts_errno; e != 0 {
	// 		t.setErrno(e)
	// 	}
	// 	f.x++
	// 	return r
}

// int fts_close(FTS *ftsp);
func Xfts_close(t *TLS, ftsp uintptr) int32 {
	return Xfts64_close(t, ftsp)
}

// int fts_close(FTS *ftsp);
func Xfts64_close(t *TLS, ftsp uintptr) int32 {
	panic(todo(""))
	// 	getObject(ftsp).(*ftstream).close(t)
	// 	removeObject(ftsp)
	// 	return 0
}

// void tzset (void);
func Xtzset(t *TLS) {
	//TODO
}

// char *strerror(int errnum);
func Xstrerror(t *TLS, errnum int32) uintptr {
	panic(todo(""))
}

// void *dlopen(const char *filename, int flags);
func Xdlopen(t *TLS, filename uintptr, flags int32) uintptr {
	panic(todo(""))
}

// char *dlerror(void);
func Xdlerror(t *TLS) uintptr {
	panic(todo(""))
}

// int dlclose(void *handle);
func Xdlclose(t *TLS, handle uintptr) int32 {
	panic(todo(""))
}

// void *dlsym(void *handle, const char *symbol);
func Xdlsym(t *TLS, handle, symbol uintptr) uintptr {
	panic(todo(""))
}

// void perror(const char *s);
func Xperror(t *TLS, s uintptr) {
	panic(todo(""))
}

// int pclose(FILE *stream);
func Xpclose(t *TLS, stream uintptr) int32 {
	panic(todo(""))
}

var gai_strerrorBuf [100]byte

// const char *gai_strerror(int errcode);
func Xgai_strerror(t *TLS, errcode int32) uintptr {
	copy(gai_strerrorBuf[:], fmt.Sprintf("gai error %d\x00", errcode))
	return uintptr(unsafe.Pointer(&gai_strerrorBuf))
}

// int tcgetattr(int fd, struct termios *termios_p);
func Xtcgetattr(t *TLS, fd int32, termios_p uintptr) int32 {
	panic(todo(""))
}

// int tcsetattr(int fd, int optional_actions, const struct termios *termios_p);
func Xtcsetattr(t *TLS, fd, optional_actions int32, termios_p uintptr) int32 {
	panic(todo(""))
}

// // speed_t cfgetospeed(const struct termios *termios_p);
// func Xcfgetospeed(t *TLS, termios_p uintptr) termios.Speed_t {
// 	panic(todo(""))
// }

// int cfsetospeed(struct termios *termios_p, speed_t speed);
func Xcfsetospeed(t *TLS, termios_p uintptr, speed uint32) int32 {
	panic(todo(""))
}

// int cfsetispeed(struct termios *termios_p, speed_t speed);
func Xcfsetispeed(t *TLS, termios_p uintptr, speed uint32) int32 {
	panic(todo(""))
}

// pid_t fork(void);
func Xfork(t *TLS) int32 {
	t.setErrno(errno.ENOSYS)
	return -1
}

// char *setlocale(int category, const char *locale);
func Xsetlocale(t *TLS, category int32, locale uintptr) uintptr {
	return 0 //TODO
}

// // char *nl_langinfo(nl_item item);
// func Xnl_langinfo(t *TLS, item langinfo.Nl_item) uintptr {
// 	panic(todo(""))
// }

// FILE *popen(const char *command, const char *type);
func Xpopen(t *TLS, command, type1 uintptr) uintptr {
	panic(todo(""))
}

// char *realpath(const char *path, char *resolved_path);
func Xrealpath(t *TLS, path, resolved_path uintptr) uintptr {
	s, err := filepath.EvalSymlinks(GoString(path))
	if err != nil {
		if os.IsNotExist(err) {
			if dmesgs {
				dmesg("%v: %q: %v", origin(1), GoString(path), err)
			}
			t.setErrno(errno.ENOENT)
			return 0
		}

		panic(todo("", err))
	}

	if resolved_path == 0 {
		panic(todo(""))
	}

	if len(s) >= limits.PATH_MAX {
		s = s[:limits.PATH_MAX-1]
	}

	copy((*RawMem)(unsafe.Pointer(resolved_path))[:len(s):len(s)], s)
	(*RawMem)(unsafe.Pointer(resolved_path))[len(s)] = 0
	return resolved_path
}

// struct tm *gmtime_r(const time_t *timep, struct tm *result);
func Xgmtime_r(t *TLS, timep, result uintptr) uintptr {
	panic(todo(""))
}

// // char *inet_ntoa(struct in_addr in);
// func Xinet_ntoa(t *TLS, in1 in.In_addr) uintptr {
// 	panic(todo(""))
// }

// func X__ccgo_in6addr_anyp(t *TLS) uintptr {
// 	return uintptr(unsafe.Pointer(&in6_addr_any))
// }

func Xabort(t *TLS) {
	panic(todo(""))
	// 	if dmesgs {
	// 		dmesg("%v:\n%s", origin(1), debug.Stack())
	// 	}
	// 	p := mustMalloc(t, types.Size_t(unsafe.Sizeof(signal.Sigaction{})))
	// 	*(*signal.Sigaction)(unsafe.Pointer(p)) = signal.Sigaction{
	// 		F__sigaction_handler: struct{ Fsa_handler signal.X__sighandler_t }{Fsa_handler: signal.SIG_DFL},
	// 	}
	// 	Xsigaction(t, signal.SIGABRT, p, 0)
	// 	Xfree(t, p)
	// 	unix.Kill(unix.Getpid(), syscall.Signal(signal.SIGABRT))
	// 	panic(todo("unrechable"))
}

// int fflush(FILE *stream);
func Xfflush(t *TLS, stream uintptr) int32 {
	return 0 //TODO
}

// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);
func Xfread(t *TLS, ptr uintptr, size, nmemb types.Size_t, stream uintptr) types.Size_t {
	panic(todo(""))
	// 	m, _, err := unix.Syscall(unix.SYS_READ, uintptr(file(stream).fd()), ptr, uintptr(size*nmemb))
	// 	if err != 0 {
	// 		file(stream).setErr()
	// 		return 0
	// 	}
	//
	// 	if dmesgs {
	// 		// dmesg("%v: %d %#x x %#x: %#x\n%s", origin(1), file(stream).fd(), size, nmemb, types.Size_t(m)/size, hex.Dump(GoBytes(ptr, int(m))))
	// 		dmesg("%v: %d %#x x %#x: %#x\n%s", origin(1), file(stream).fd(), size, nmemb, types.Size_t(m)/size)
	// 	}
	// 	return types.Size_t(m) / size
}

// size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
func Xfwrite(t *TLS, ptr uintptr, size, nmemb types.Size_t, stream uintptr) types.Size_t {
	panic(todo(""))
	// 	m, _, err := unix.Syscall(unix.SYS_WRITE, uintptr(file(stream).fd()), ptr, uintptr(size*nmemb))
	// 	if err != 0 {
	// 		file(stream).setErr()
	// 		return 0
	// 	}
	//
	// 	if dmesgs {
	// 		// dmesg("%v: %d %#x x %#x: %#x\n%s", origin(1), file(stream).fd(), size, nmemb, types.Size_t(m)/size, hex.Dump(GoBytes(ptr, int(m))))
	// 		dmesg("%v: %d %#x x %#x: %#x\n%s", origin(1), file(stream).fd(), size, nmemb, types.Size_t(m)/size)
	// 	}
	// 	return types.Size_t(m) / size
}

// int fclose(FILE *stream);
func Xfclose(t *TLS, stream uintptr) int32 {
	return file(stream).close(t)
}

// int fputc(int c, FILE *stream);
func Xfputc(t *TLS, c int32, stream uintptr) int32 {
	panic(todo(""))
	// 	if _, err := fwrite(file(stream).fd(), []byte{byte(c)}); err != nil {
	// 		return stdio.EOF
	// 	}
	//
	// 	return int32(byte(c))
}

// int fseek(FILE *stream, long offset, int whence);
func Xfseek(t *TLS, stream uintptr, offset long, whence int32) int32 {
	if n := Xlseek(t, int32(file(stream).fd()), types.Off_t(offset), whence); n < 0 {
		if dmesgs {
			dmesg("%v: fd %v, off %#x, whence %v: %v", origin(1), file(stream).fd(), offset, whenceStr(whence), n)
		}
		file(stream).setErr()
		return -1
	}

	if dmesgs {
		dmesg("%v: fd %v, off %#x, whence %v: ok", origin(1), file(stream).fd(), offset, whenceStr(whence))
	}
	return 0
}

// long ftell(FILE *stream);
func Xftell(t *TLS, stream uintptr) long {
	panic(todo(""))
	// 	n := Xlseek(t, file(stream).fd(), 0, stdio.SEEK_CUR)
	// 	if n < 0 {
	// 		file(stream).setErr()
	// 		return -1
	// 	}
	//
	// 	if dmesgs {
	// 		dmesg("%v: fd %v, n %#x: ok %#x", origin(1), file(stream).fd(), n, long(n))
	// 	}
	// 	return long(n)
}

// int ferror(FILE *stream);
func Xferror(t *TLS, stream uintptr) int32 {
	return Bool32(file(stream).err())
}

// int fgetc(FILE *stream);
func Xfgetc(t *TLS, stream uintptr) int32 {
	panic(todo(""))
}

// int getc(FILE *stream);
func Xgetc(t *TLS, stream uintptr) int32 {
	return Xfgetc(t, stream)
}

// int ungetc(int c, FILE *stream);
func Xungetc(t *TLS, c int32, stream uintptr) int32 {
	panic(todo(""))
}

// int fscanf(FILE *stream, const char *format, ...);
func Xfscanf(t *TLS, stream, format, va uintptr) int32 {
	panic(todo(""))
}

// FILE *fdopen(int fd, const char *mode);
func Xfdopen(t *TLS, fd int32, mode uintptr) uintptr {
	panic(todo(""))
}

// int fputs(const char *s, FILE *stream);
func Xfputs(t *TLS, s, stream uintptr) int32 {
	panic(todo(""))
	// 	if _, _, err := unix.Syscall(unix.SYS_WRITE, uintptr(file(stream).fd()), s, uintptr(Xstrlen(t, s))); err != 0 {
	// 		return -1
	// 	}
	//
	// 	return 0
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

// void _exit(int status);
func X_exit(t *TLS, status int32) {
	os.Exit(int(status))
}

// var getservbynameStaticResult netdb.Servent
//
// // struct servent *getservbyname(const char *name, const char *proto);
// func Xgetservbyname(t *TLS, name, proto uintptr) uintptr {
// 	var protoent *gonetdb.Protoent
// 	if proto != 0 {
// 		protoent = gonetdb.GetProtoByName(GoString(proto))
// 	}
// 	servent := gonetdb.GetServByName(GoString(name), protoent)
// 	if servent == nil {
// 		if dmesgs {
// 			dmesg("%q %q: nil (protoent %+v)", GoString(name), GoString(proto), protoent)
// 		}
// 		return 0
// 	}
//
// 	Xfree(t, (*netdb.Servent)(unsafe.Pointer(&getservbynameStaticResult)).Fs_name)
// 	if v := (*netdb.Servent)(unsafe.Pointer(&getservbynameStaticResult)).Fs_aliases; v != 0 {
// 		for {
// 			p := *(*uintptr)(unsafe.Pointer(v))
// 			if p == 0 {
// 				break
// 			}
//
// 			Xfree(t, p)
// 			v += unsafe.Sizeof(uintptr(0))
// 		}
// 		Xfree(t, v)
// 	}
// 	Xfree(t, (*netdb.Servent)(unsafe.Pointer(&getservbynameStaticResult)).Fs_proto)
// 	cname, err := CString(servent.Name)
// 	if err != nil {
// 		getservbynameStaticResult = netdb.Servent{}
// 		return 0
// 	}
//
// 	var protoname uintptr
// 	if protoent != nil {
// 		if protoname, err = CString(protoent.Name); err != nil {
// 			Xfree(t, cname)
// 			getservbynameStaticResult = netdb.Servent{}
// 			return 0
// 		}
// 	}
// 	var a []uintptr
// 	for _, v := range servent.Aliases {
// 		cs, err := CString(v)
// 		if err != nil {
// 			for _, v := range a {
// 				Xfree(t, v)
// 			}
// 			return 0
// 		}
//
// 		a = append(a, cs)
// 	}
// 	v := Xcalloc(t, types.Size_t(len(a)+1), types.Size_t(unsafe.Sizeof(uintptr(0))))
// 	if v == 0 {
// 		Xfree(t, cname)
// 		Xfree(t, protoname)
// 		for _, v := range a {
// 			Xfree(t, v)
// 		}
// 		getservbynameStaticResult = netdb.Servent{}
// 		return 0
// 	}
// 	for _, p := range a {
// 		*(*uintptr)(unsafe.Pointer(v)) = p
// 		v += unsafe.Sizeof(uintptr(0))
// 	}
//
// 	getservbynameStaticResult = netdb.Servent{
// 		Fs_name:    cname,
// 		Fs_aliases: v,
// 		Fs_port:    int32(servent.Port),
// 		Fs_proto:   protoname,
// 	}
// 	return uintptr(unsafe.Pointer(&getservbynameStaticResult))
// }

// func Xreaddir64(t *TLS, dir uintptr) uintptr {
// 	return Xreaddir(t, dir)
// }

// func fcntlCmdStr(cmd int32) string {
// 	switch cmd {
// 	case fcntl.F_GETOWN:
// 		return "F_GETOWN"
// 	case fcntl.F_SETLK:
// 		return "F_SETLK"
// 	case fcntl.F_GETLK:
// 		return "F_GETLK"
// 	case fcntl.F_SETFD:
// 		return "F_SETFD"
// 	case fcntl.F_GETFD:
// 		return "F_GETFD"
// 	default:
// 		return fmt.Sprintf("cmd(%d)", cmd)
// 	}
// }

// _CRTIMP extern int *__cdecl _errno(void); // /usr/share/mingw-w64/include/errno.h:17:
func X_errno(t *TLS) uintptr {
	panic(todo(""))
}

// int vfscanf(FILE * restrict stream, const char * restrict format, va_list arg);
func X__ms_vfscanf(t *TLS, stream, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsscanf(const char *str, const char *format, va_list ap);
func X__ms_vsscanf(t *TLS, str, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vscanf(const char *format, va_list ap);
func X__ms_vscanf(t *TLS, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vsnprintf(char *str, size_t size, const char *format, va_list ap);
func X__ms_vsnprintf(t *TLS, str uintptr, size types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vfwscanf(FILE *stream, const wchar_t *format, va_list argptr;);
func X__ms_vfwscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vwscanf(const wchar_t * restrict format, va_list arg);
func X__ms_vwscanf(t *TLS, format, ap uintptr) int32 {
	panic(todo(""))
}

// int _vsnwprintf(wchar_t *buffer, size_t count, const wchar_t *format, va_list argptr);
func X_vsnwprintf(t *TLS, buffer uintptr, count types.Size_t, format, ap uintptr) int32 {
	panic(todo(""))
}

// int vswscanf(const wchar_t *buffer, const wchar_t *format, va_list arglist);
func X__ms_vswscanf(t *TLS, stream uintptr, format, ap uintptr) int32 {
	panic(todo(""))
}

// __acrt_iob_func
func X__acrt_iob_func(t *TLS, fd uint32) uintptr {
	panic(todo(""))
}

// unsigned long int strtoul(const char *nptr, char **endptr, int base);
func Xstrtoul(t *TLS, nptr, endptr uintptr, base int32) ulong {
	panic(todo(""))
}

// BOOL SetEvent(
//   HANDLE hEvent
// );
func XSetEvent(t *TLS, hEvent uintptr) int32 {
	panic(todo(""))
}

// long int strtol(const char *nptr, char **endptr, int base);
func Xstrtol(t *TLS, nptr, endptr uintptr, base int32) long {
	panic(todo(""))
}

// int _stricmp(
//    const char *string1,
//    const char *string2
// );
func X_stricmp(t *TLS, string1, string2 uintptr) int32 {
	panic(todo(""))
}

// int putenv(
//    const char *envstring
// );
func Xputenv(t *TLS, envstring uintptr) int32 {
	panic(todo(""))
}

// BOOL HeapFree(
//   HANDLE                 hHeap,
//   DWORD                  dwFlags,
//   _Frees_ptr_opt_ LPVOID lpMem
// );
func XHeapFree(t *TLS, hHeap uintptr, dwFlags uint32, lpMem uintptr) int32 {
	panic(todo(""))
}

// HANDLE GetProcessHeap();
func XGetProcessHeap(t *TLS) uintptr {
	panic(todo(""))
}

// LPVOID HeapAlloc(
//   HANDLE hHeap,
//   DWORD  dwFlags,
//   SIZE_T dwBytes
// );
func XHeapAlloc(t *TLS, hHeap uintptr, dwFlags uint32, dwBytes types.Size_t) uintptr {
	panic(todo(""))
}

// WCHAR * gai_strerrorW(
//   int ecode
// );
func Xgai_strerrorW(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

// servent * getservbyname(
//   const char *name,
//   const char *proto
// );
func Xgetservbyname(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

// INT WSAAPI getaddrinfo(
//   PCSTR           pNodeName,
//   PCSTR           pServiceName,
//   const ADDRINFOA *pHints,
//   PADDRINFOA      *ppResult
// );
func XWspiapiGetAddrInfo(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// int wcscmp(
//    const wchar_t *string1,
//    const wchar_t *string2
// );
func Xwcscmp(t *TLS, string1, string2 uintptr) int32 {
	panic(todo(""))
}

// BOOL IsDebuggerPresent();
func XIsDebuggerPresent(t *TLS) int32 {
	panic(todo(""))
}

func XExitProcess(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL GetVersionExW(
//   LPOSVERSIONINFOW lpVersionInformation
// );
func XGetVersionExW(t *TLS, lpVersionInformation uintptr) int32 {
	panic(todo(""))
}

// BOOL GetVolumeNameForVolumeMountPointW(
//   LPCWSTR lpszVolumeMountPoint,
//   LPWSTR  lpszVolumeName,
//   DWORD   cchBufferLength
// );
func XGetVolumeNameForVolumeMountPointW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// size_t wcslen(
//    const wchar_t *str
// );
func Xwcslen(t *TLS, str uintptr) types.Size_t {
	panic(todo(""))
}

// HANDLE WINAPI GetStdHandle(
//   _In_ DWORD nStdHandle
// );
func XGetStdHandle(t *TLS, nStdHandle uint32) uintptr {
	panic(todo(""))
}

// BOOL CloseHandle(
//   HANDLE hObject
// );
func XCloseHandle(t *TLS, hObject uintptr) int32 {
	panic(todo(""))
}

// DWORD GetLastError();
func XGetLastError(t *TLS) uint32 {
	panic(todo(""))
}

// DWORD SetFilePointer(
//   HANDLE hFile,
//   LONG   lDistanceToMove,
//   PLONG  lpDistanceToMoveHigh,
//   DWORD  dwMoveMethod
// );
func XSetFilePointer(t *TLS, hFile uintptr, lDistanceToMove long, lpDistanceToMoveHigh uintptr, dwMoveMethod uint32) uint32 {
	panic(todo(""))
}

// BOOL SetEndOfFile(
//   HANDLE hFile
// );
func XSetEndOfFile(t *TLS, hFile uintptr) int32 {
	panic(todo(""))
}

// BOOL ReadFile(
//   HANDLE       hFile,
//   LPVOID       lpBuffer,
//   DWORD        nNumberOfBytesToRead,
//   LPDWORD      lpNumberOfBytesRead,
//   LPOVERLAPPED lpOverlapped
// );
func XReadFile(t *TLS, hFile, lpBuffer uintptr, nNumberOfBytesToRead uint32, lpNumberOfBytesRead, lpOverlapped uintptr) int32 {
	panic(todo(""))
}

// BOOL WriteFile(
//   HANDLE       hFile,
//   LPCVOID      lpBuffer,
//   DWORD        nNumberOfBytesToWrite,
//   LPDWORD      lpNumberOfBytesWritten,
//   LPOVERLAPPED lpOverlapped
// );
func XWriteFile(t *TLS, hFile, lpBuffer uintptr, nNumberOfBytesToWrite uint32, lpNumberOfBytesWritten, lpOverlapped uintptr) int32 {
	panic(todo(""))
}

// DWORD GetFileAttributesW(
//   LPCWSTR lpFileName
// );
func XGetFileAttributesW(t *TLS, lpFileName uintptr) uint32 {
	panic(todo(""))
}

// HANDLE CreateFileW(
//   LPCWSTR               lpFileName,
//   DWORD                 dwDesiredAccess,
//   DWORD                 dwShareMode,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//   DWORD                 dwCreationDisposition,
//   DWORD                 dwFlagsAndAttributes,
//   HANDLE                hTemplateFile
// );
func XCreateFileW(t *TLS, lpFileName uintptr, dwDesiredAccess, dwShareMode uint32, lpSecurityAttributes uintptr, dwCreationDisposition, dwFlagsAndAttributes uint32, hTemplateFile uintptr) uintptr {
	panic(todo(""))
}

// BOOL DuplicateHandle(
//   HANDLE   hSourceProcessHandle,
//   HANDLE   hSourceHandle,
//   HANDLE   hTargetProcessHandle,
//   LPHANDLE lpTargetHandle,
//   DWORD    dwDesiredAccess,
//   BOOL     bInheritHandle,
//   DWORD    dwOptions
// );
func XDuplicateHandle(t *TLS, hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle uintptr, dwDesiredAccess uint32, bInheritHandle int32, dwOptions uint32) int32 {
	panic(todo(""))
}

// HANDLE GetCurrentProcess();
func XGetCurrentProcess(t *TLS) uintptr {
	panic(todo(""))
}

// BOOL FlushFileBuffers(
//   HANDLE hFile
// );
func XFlushFileBuffers(t *TLS, hFile uintptr) int32 {
	panic(todo(""))
}

// DWORD GetFileType(
//   HANDLE hFile
// );
func XGetFileType(t *TLS, hFile uintptr) uint32 {
	panic(todo(""))
}

// BOOL WINAPI GetConsoleMode(
//   _In_  HANDLE  hConsoleHandle,
//   _Out_ LPDWORD lpMode
// );
func XGetConsoleMode(t *TLS, hConsoleHandle, lpMode uintptr) int32 {
	panic(todo(""))
}

// BOOL GetCommState(
//   HANDLE hFile,
//   LPDCB  lpDCB
// );
func XGetCommState(t *TLS, hFile, lpDCB uintptr) int32 {
	panic(todo(""))
}

// int _wcsnicmp(
//    const wchar_t *string1,
//    const wchar_t *string2,
//    size_t count
// );
func X_wcsnicmp(t *TLS, string1, string2 uintptr, count types.Size_t) int32 {
	panic(todo(""))
}

// BOOL WINAPI ReadConsole(
//   _In_     HANDLE  hConsoleInput,
//   _Out_    LPVOID  lpBuffer,
//   _In_     DWORD   nNumberOfCharsToRead,
//   _Out_    LPDWORD lpNumberOfCharsRead,
//   _In_opt_ LPVOID  pInputControl
// );
func XReadConsoleW(t *TLS, hConsoleInput, lpBuffer uintptr, nNumberOfCharsToRead uint32, lpNumberOfCharsRead, pInputControl uintptr) int32 {
	panic(todo(""))
}

// BOOL WINAPI WriteConsoleW(
//   _In_             HANDLE  hConsoleOutput,
//   _In_       const VOID    *lpBuffer,
//   _In_             DWORD   nNumberOfCharsToWrite,
//   _Out_opt_        LPDWORD lpNumberOfCharsWritten,
//   _Reserved_       LPVOID  lpReserved
// );
func XWriteConsoleW(t *TLS, hConsoleOutput, lpBuffer uintptr, nNumberOfCharsToWrite uint32, lpNumberOfCharsWritten, lpReserved uintptr) int32 {
	panic(todo(""))
}

// DWORD WaitForSingleObject(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds
// );
func XWaitForSingleObject(t *TLS, hHandle uintptr, dwMilliseconds uint32) uint32 {
	panic(todo(""))
}

// BOOL ResetEvent(
//   HANDLE hEvent
// );
func XResetEvent(t *TLS, hEvent uintptr) int32 {
	panic(todo(""))
}

// BOOL WINAPI PeekConsoleInput(
//   _In_  HANDLE        hConsoleInput,
//   _Out_ PINPUT_RECORD lpBuffer,
//   _In_  DWORD         nLength,
//   _Out_ LPDWORD       lpNumberOfEventsRead
// );
func XPeekConsoleInputW(t *TLS, hConsoleInput, lpBuffer uintptr, nLength uint32, lpNumberOfEventsRead uintptr) int32 {
	panic(todo(""))
}

// int WINAPIV wsprintfA(
//   LPSTR  ,
//   LPCSTR ,
//   ...
// );
func XwsprintfA(t *TLS, a, b, va uintptr) int32 {
	panic(todo(""))
}

// UINT WINAPI GetConsoleCP(void);
func XGetConsoleCP(t *TLS) uint32 {
	panic(todo(""))
}

// HANDLE CreateEventW(
//   LPSECURITY_ATTRIBUTES lpEventAttributes,
//   BOOL                  bManualReset,
//   BOOL                  bInitialState,
//   LPCWSTR               lpName
// );
func XCreateEventW(t *TLS, lpEventAttributes uintptr, bManualReset, bInitialState int32, lpName uintptr) uintptr {
	panic(todo(""))
}

// HANDLE CreateThread(
//   LPSECURITY_ATTRIBUTES   lpThreadAttributes,
//   SIZE_T                  dwStackSize,
//   LPTHREAD_START_ROUTINE  lpStartAddress,
//   __drv_aliasesMem LPVOID lpParameter,
//   DWORD                   dwCreationFlags,
//   LPDWORD                 lpThreadId
// );
func XCreateThread(t *TLS, lpThreadAttributes uintptr, dwStackSize types.Size_t, lpStartAddress, lpParameter uintptr, dwCreationFlags uint32, lpThreadId uintptr) uintptr {
	panic(todo(""))
}

// BOOL SetThreadPriority(
//   HANDLE hThread,
//   int    nPriority
// );
func XSetThreadPriority(t *TLS, hThread uintptr, nPriority int32) int32 {
	panic(todo(""))
}

// BOOL WINAPI SetConsoleMode(
//   _In_ HANDLE hConsoleHandle,
//   _In_ DWORD  dwMode
// );
func XSetConsoleMode(t *TLS, hConsoleHandle uintptr, dwMode uint32) int32 {
	panic(todo(""))
}

func XPurgeComm(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XClearCommError(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// void DeleteCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XDeleteCriticalSection(t *TLS, lpCriticalSection uintptr) {
	panic(todo(""))
}

func XGetOverlappedResult(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// void EnterCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XEnterCriticalSection(t *TLS, lpCriticalSection uintptr) {
	panic(todo(""))
}

// void LeaveCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XLeaveCriticalSection(t *TLS, lpCriticalSection uintptr) {
	panic(todo(""))
}

func XSetupComm(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetCommTimeouts(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// void InitializeCriticalSection(
//   LPCRITICAL_SECTION lpCriticalSection
// );
func XInitializeCriticalSection(t *TLS, lpCriticalSection uintptr) {
	panic(todo(""))
}

func XBuildCommDCBW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetCommState(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_strnicmp(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XEscapeCommFunction(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGetCommModemStatus(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL MoveFileW(
//   LPCWSTR lpExistingFileName,
//   LPCWSTR lpNewFileName
// );
func XMoveFileW(t *TLS, lpExistingFileName, lpNewFileName uintptr) int32 {
	panic(todo(""))
}

// DWORD GetFullPathNameW(
//   LPCWSTR lpFileName,
//   DWORD   nBufferLength,
//   LPWSTR  lpBuffer,
//   LPWSTR  *lpFilePart
// );
func XGetFullPathNameW(t *TLS, lpFileName uintptr, nBufferLength uint32, lpBuffer, lpFilePart uintptr) uint32 {
	panic(todo(""))
}

// LPWSTR CharLowerW(
//   LPWSTR lpsz
// );
func XCharLowerW(t *TLS, lpsz uintptr) uintptr {
	panic(todo(""))
}

// BOOL CreateDirectoryW(
//   LPCWSTR                lpPathName,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes
// );
func XCreateDirectoryW(t *TLS, lpPathName, lpSecurityAttributes uintptr) int32 {
	panic(todo(""))
}

// BOOL SetFileAttributesW(
//   LPCWSTR lpFileName,
//   DWORD   dwFileAttributes
// );
func XSetFileAttributesW(t *TLS, lpFileName uintptr, dwFileAttributes uint32) int32 {
	panic(todo(""))
}

// UINT GetTempFileNameW(
//   LPCWSTR lpPathName,
//   LPCWSTR lpPrefixString,
//   UINT    uUnique,
//   LPWSTR  lpTempFileName
// );
func XGetTempFileNameW(t *TLS, lpPathName, lpPrefixString uintptr, uUnique uint32, lpTempFileName uintptr) uint32 {
	panic(todo(""))
}

// BOOL CopyFileW(
//   LPCWSTR lpExistingFileName,
//   LPCWSTR lpNewFileName,
//   BOOL    bFailIfExists
// );
func XCopyFileW(t *TLS, lpExistingFileName, lpNewFileName uintptr, bFailIfExists int32) int32 {
	panic(todo(""))
}

// BOOL DeleteFileW(
//   LPCWSTR lpFileName
// );
func XDeleteFileW(t *TLS, lpFileName uintptr) int32 {
	panic(todo(""))
}

// BOOL RemoveDirectoryW(
//   LPCWSTR lpPathName
// );
func XRemoveDirectoryW(t *TLS, lpPathName uintptr) int32 {
	panic(todo(""))
}

// HANDLE FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
func XFindFirstFileW(t *TLS, lpFileName, lpFindFileData uintptr) uintptr {
	panic(todo(""))
}

// BOOL FindClose(HANDLE hFindFile);
func XFindClose(t *TLS, hFindFile uintptr) int32 {
	panic(todo(""))
}

// BOOL FindNextFileW(
//   HANDLE             hFindFile,
//   LPWIN32_FIND_DATAW lpFindFileData
// );
func XFindNextFileW(t *TLS, hFindFile, lpFindFileData uintptr) int32 {
	panic(todo(""))
}

// DWORD GetLogicalDriveStringsA(
//   DWORD nBufferLength,
//   LPSTR lpBuffer
// );
func XGetLogicalDriveStringsA(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	panic(todo(""))
}

// BOOL GetVolumeInformationA(
//   LPCSTR  lpRootPathName,
//   LPSTR   lpVolumeNameBuffer,
//   DWORD   nVolumeNameSize,
//   LPDWORD lpVolumeSerialNumber,
//   LPDWORD lpMaximumComponentLength,
//   LPDWORD lpFileSystemFlags,
//   LPSTR   lpFileSystemNameBuffer,
//   DWORD   nFileSystemNameSize
// );
func XGetVolumeInformationA(t *TLS, lpRootPathName, lpVolumeNameBuffer uintptr, nVolumeNameSize uint32, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer uintptr, nFileSystemNameSize uint32) int32 {
	panic(todo(""))
}

// BOOL CreateHardLinkW(
//   LPCWSTR               lpFileName,
//   LPCWSTR               lpExistingFileName,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes
// );
func XCreateHardLinkW(t *TLS, lpFileName, lpExistingFileName, lpSecurityAttributes uintptr) int32 {
	panic(todo(""))
}

// BOOL DeviceIoControl(
//   HANDLE       hDevice,
//   DWORD        dwIoControlCode,
//   LPVOID       lpInBuffer,
//   DWORD        nInBufferSize,
//   LPVOID       lpOutBuffer,
//   DWORD        nOutBufferSize,
//   LPDWORD      lpBytesReturned,
//   LPOVERLAPPED lpOverlapped
// );
func XDeviceIoControl(t *TLS, hDevice uintptr, dwIoControlCode uint32, lpInBuffer uintptr, nInBufferSize uint32, lpOutBuffer uintptr, nOutBufferSize uint32, lpBytesReturned, lpOverlapped uintptr) int32 {
	panic(todo(""))
}

// int wcsncmp(
//    const wchar_t *string1,
//    const wchar_t *string2,
//    size_t count
// );
func Xwcsncmp(t *TLS, string1, string2 uintptr, count types.Size_t) int32 {
	panic(todo(""))
}

// int MultiByteToWideChar(
//   UINT                              CodePage,
//   DWORD                             dwFlags,
//   _In_NLS_string_(cbMultiByte)LPCCH lpMultiByteStr,
//   int                               cbMultiByte,
//   LPWSTR                            lpWideCharStr,
//   int                               cchWideChar
// );
func XMultiByteToWideChar(t *TLS, CodePage uint32, dwFlags uint32, lpMultiByteStr uintptr, cbMultiByte int32, lpWideCharStr uintptr, cchWideChar int32) int32 {
	panic(todo(""))
}

// void OutputDebugStringW(
//   LPCWSTR lpOutputString
// );
func XOutputDebugStringW(t *TLS, lpOutputString uintptr) {
	panic(todo(""))
}

func XMessageBeep(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

//====

// long _InterlockedCompareExchange(
//    long volatile * Destination,
//    long Exchange,
//    long Comparand
// );
func X_InterlockedCompareExchange(t *TLS, Destination uintptr, Exchange, Comparand long) long {
	panic(todo(""))
}

// int rename(const char *oldpath, const char *newpath);
func Xrename(t *TLS, oldpath, newpath uintptr) int32 {
	panic(todo(""))
}

// BOOL AreFileApisANSI();
func XAreFileApisANSI(t *TLS) int32 {
	panic(todo(""))
}

// HANDLE CreateFileA(
//   LPCSTR                lpFileName,
//   DWORD                 dwDesiredAccess,
//   DWORD                 dwShareMode,
//   LPSECURITY_ATTRIBUTES lpSecurityAttributes,
//   DWORD                 dwCreationDisposition,
//   DWORD                 dwFlagsAndAttributes,
//   HANDLE                hTemplateFile
// );
func XCreateFileA(t *TLS, lpFileName uintptr, dwDesiredAccess, dwShareMode uint32, lpSecurityAttributes uintptr, dwCreationDisposition, dwFlagsAndAttributes uint32, hTemplateFile uintptr) uintptr {
	panic(todo(""))
}

// HANDLE CreateFileMappingA(
//   HANDLE                hFile,
//   LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
//   DWORD                 flProtect,
//   DWORD                 dwMaximumSizeHigh,
//   DWORD                 dwMaximumSizeLow,
//   LPCSTR                lpName
// );
func XCreateFileMappingA(t *TLS, hFile, lpFileMappingAttributes uintptr, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow uint32, lpName uintptr) uintptr {
	panic(todo(""))
}

// HANDLE CreateFileMappingW(
//   HANDLE                hFile,
//   LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
//   DWORD                 flProtect,
//   DWORD                 dwMaximumSizeHigh,
//   DWORD                 dwMaximumSizeLow,
//   LPCWSTR               lpName
// );
func XCreateFileMappingW(t *TLS, hFile, lpFileMappingAttributes uintptr, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow uint32, lpName uintptr) uintptr {
	panic(todo(""))
}

// HANDLE CreateMutexW(
//   LPSECURITY_ATTRIBUTES lpMutexAttributes,
//   BOOL                  bInitialOwner,
//   LPCWSTR               lpName
// );
func XCreateMutexW(t *TLS, lpMutexAttributes uintptr, bInitialOwner int32, lpName uintptr) uintptr {
	panic(todo(""))
}

// BOOL DeleteFileA(
//   LPCSTR lpFileName
// );
func XDeleteFileA(t *TLS, lpFileName uintptr) int32 {
	panic(todo(""))
}

// DWORD FormatMessageA(
//   DWORD   dwFlags,
//   LPCVOID lpSource,
//   DWORD   dwMessageId,
//   DWORD   dwLanguageId,
//   LPSTR   lpBuffer,
//   DWORD   nSize,
//   va_list *Arguments
// );
func XFormatMessageA(t *TLS, dwFlagsAndAttributes uint32, lpSource uintptr, dwMessageId, dwLanguageId uint32, lpBuffer uintptr, nSize uint32, Arguments uintptr) uint32 {
	panic(todo(""))
}

// DWORD FormatMessageW(
//   DWORD   dwFlags,
//   LPCVOID lpSource,
//   DWORD   dwMessageId,
//   DWORD   dwLanguageId,
//   LPWSTR  lpBuffer,
//   DWORD   nSize,
//   va_list *Arguments
// );
func XFormatMessageW(t *TLS, dwFlags uint32, lpSource uintptr, dwMessageId, dwLanguageId uint32, lpBuffer uintptr, nSize uint32, Arguments uintptr) uint32 {
	panic(todo(""))
}

// BOOL FreeLibrary(HMODULE hLibModule);
func XFreeLibrary(t *TLS, hLibModule uintptr) int32 {
	panic(todo(""))
}

// DWORD GetCurrentProcessId();
func XGetCurrentProcessId(t *TLS) uint32 {
	panic(todo(""))
}

// BOOL GetDiskFreeSpaceA(
//   LPCSTR  lpRootPathName,
//   LPDWORD lpSectorsPerCluster,
//   LPDWORD lpBytesPerSector,
//   LPDWORD lpNumberOfFreeClusters,
//   LPDWORD lpTotalNumberOfClusters
// );
func XGetDiskFreeSpaceA(t *TLS, lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters uintptr) int32 {
	panic(todo(""))
}

// BOOL GetDiskFreeSpaceW(
//   LPCWSTR lpRootPathName,
//   LPDWORD lpSectorsPerCluster,
//   LPDWORD lpBytesPerSector,
//   LPDWORD lpNumberOfFreeClusters,
//   LPDWORD lpTotalNumberOfClusters
// );
func XGetDiskFreeSpaceW(t *TLS, lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters uintptr) int32 {
	panic(todo(""))
}

// DWORD GetFileAttributesA(
//   LPCSTR lpFileName
// );
func XGetFileAttributesA(t *TLS, lpFileName uintptr) uint32 {
	panic(todo(""))
}

// BOOL GetFileAttributesExW(
//   LPCWSTR                lpFileName,
//   GET_FILEEX_INFO_LEVELS fInfoLevelId,
//   LPVOID                 lpFileInformation
// );
func XGetFileAttributesExW(t *TLS, lpFileName uintptr, fInfoLevelId uint32, lpFileInformation uintptr) int32 {
	panic(todo(""))
}

// DWORD GetFileSize(
//   HANDLE  hFile,
//   LPDWORD lpFileSizeHigh
// );
func XGetFileSize(t *TLS, hFile, lpFileSizeHigh uintptr) uint32 {
	panic(todo(""))
}

// DWORD GetFullPathNameA(
//   LPCSTR lpFileName,
//   DWORD  nBufferLength,
//   LPSTR  lpBuffer,
//   LPSTR  *lpFilePart
// );
func XGetFullPathNameA(t *TLS, lpFileName uintptr, nBufferLength uint32, lpBuffer, lpFilePart uintptr) uint32 {
	panic(todo(""))
}

// FARPROC GetProcAddress(HMODULE hModule, LPCSTR  lpProcName);
func XGetProcAddress(t *TLS, hModule, lpProcName uintptr) uintptr {
	panic(todo(""))
}

// NTSYSAPI NTSTATUS RtlGetVersion( // ntdll.dll
//   PRTL_OSVERSIONINFOW lpVersionInformation
// );
func XRtlGetVersion(t *TLS, lpVersionInformation uintptr) uintptr {
	panic(todo(""))
}

// void GetSystemInfo(
//   LPSYSTEM_INFO lpSystemInfo
// );
func XGetSystemInfo(t *TLS, lpSystemInfo uintptr) {
	panic(todo(""))
}

// void GetSystemTime(LPSYSTEMTIME lpSystemTime);
func XGetSystemTime(t *TLS, lpSystemTime uintptr) {
	panic(todo(""))
}

// void GetSystemTimeAsFileTime(
//   LPFILETIME lpSystemTimeAsFileTime
// );
func XGetSystemTimeAsFileTime(t *TLS, lpSystemTimeAsFileTime uintptr) {
	panic(todo(""))
}

// DWORD GetTempPathA(
//   DWORD nBufferLength,
//   LPSTR lpBuffer
// );
func XGetTempPathA(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	panic(todo(""))
}

// DWORD GetTempPathW(
//   DWORD  nBufferLength,
//   LPWSTR lpBuffer
// );
func XGetTempPathW(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	panic(todo(""))
}

// DWORD GetTickCount();
func XGetTickCount(t *TLS) uint32 {
	panic(todo(""))
}

// BOOL GetVersionExA(
//   LPOSVERSIONINFOA lpVersionInformation
// );
func XGetVersionExA(t *TLS, lpVersionInformation uintptr) int32 {
	panic(todo(""))
}

// HANDLE HeapCreate(
//   DWORD  flOptions,
//   SIZE_T dwInitialSize,
//   SIZE_T dwMaximumSize
// );
func XHeapCreate(t *TLS, flOptions uint32, dwInitialSize, dwMaximumSize types.Size_t) uintptr {
	panic(todo(""))
}

// BOOL HeapDestroy(
//   HANDLE hHeap
// );
func XHeapDestroy(t *TLS, hHeap uintptr) int32 {
	panic(todo(""))
}

// LPVOID HeapReAlloc(
//   HANDLE                 hHeap,
//   DWORD                  dwFlags,
//   _Frees_ptr_opt_ LPVOID lpMem,
//   SIZE_T                 dwBytes
// );
func XHeapReAlloc(t *TLS, hHeap uintptr, dwFlags uint32, lpMem uintptr, dwBytes types.Size_t) uintptr {
	panic(todo(""))
}

// SIZE_T HeapSize(
//   HANDLE  hHeap,
//   DWORD   dwFlags,
//   LPCVOID lpMem
// );
func XHeapSize(t *TLS, hHeap uintptr, dwFlags uint32, lpMem uintptr) types.Size_t {
	panic(todo(""))
}

// BOOL HeapValidate(
//   HANDLE  hHeap,
//   DWORD   dwFlags,
//   LPCVOID lpMem
// );
func XHeapValidate(t *TLS, hHeap uintptr, dwFlags uint32, lpMem uintptr) int32 {
	panic(todo(""))
}

// SIZE_T HeapCompact(
//   HANDLE hHeap,
//   DWORD  dwFlags
// );
func XHeapCompact(t *TLS, hHeap uintptr, dwFlags uint32) types.Size_t {
	panic(todo(""))
}

// HMODULE LoadLibraryA(LPCSTR lpLibFileName);
func XLoadLibraryA(t *TLS, lpLibFileName uintptr) uintptr {
	panic(todo(""))
}

// HMODULE LoadLibraryW(
//   LPCWSTR lpLibFileName
// );
func XLoadLibraryW(t *TLS, lpLibFileName uintptr) uintptr {
	panic(todo(""))
}

// HLOCAL LocalFree(
//   HLOCAL hMem
// );
func XLocalFree(t *TLS, hMem uintptr) uintptr {
	panic(todo(""))
}

// BOOL LockFile(
//   HANDLE hFile,
//   DWORD  dwFileOffsetLow,
//   DWORD  dwFileOffsetHigh,
//   DWORD  nNumberOfBytesToLockLow,
//   DWORD  nNumberOfBytesToLockHigh
// );
func XLockFile(t *TLS, hFile uintptr, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh uint32) int32 {
	panic(todo(""))
}

// BOOL LockFileEx(
//   HANDLE       hFile,
//   DWORD        dwFlags,
//   DWORD        dwReserved,
//   DWORD        nNumberOfBytesToLockLow,
//   DWORD        nNumberOfBytesToLockHigh,
//   LPOVERLAPPED lpOverlapped
// );
func XLockFileEx(t *TLS, hFile uintptr, dwFlags, dwReserved, nNumberOfBytesToLockLow, nNumberOfBytesToLockHigh uint32, lpOverlapped uintptr) int32 {
	panic(todo(""))
}

// LPVOID MapViewOfFile(
//   HANDLE hFileMappingObject,
//   DWORD  dwDesiredAccess,
//   DWORD  dwFileOffsetHigh,
//   DWORD  dwFileOffsetLow,
//   SIZE_T dwNumberOfBytesToMap
// );
func XMapViewOfFile(t *TLS, hFileMappingObject uintptr, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow uint32, dwNumberOfBytesToMap types.Size_t) uintptr {
	panic(todo(""))
}

// BOOL QueryPerformanceCounter(
//   LARGE_INTEGER *lpPerformanceCount
// );
func XQueryPerformanceCounter(t *TLS, lpPerformanceCount uintptr) int32 {
	panic(todo(""))
}

// void Sleep(
//   DWORD dwMilliseconds
// );
func XSleep(t *TLS, dwMilliseconds uint32) {
	panic(todo(""))
}

// BOOL SystemTimeToFileTime(const SYSTEMTIME *lpSystemTime, LPFILETIME lpFileTime);
func XSystemTimeToFileTime(t *TLS, lpSystemTime, lpFileTime uintptr) int32 {
	panic(todo(""))
}

// BOOL UnlockFile(
//   HANDLE hFile,
//   DWORD  dwFileOffsetLow,
//   DWORD  dwFileOffsetHigh,
//   DWORD  nNumberOfBytesToUnlockLow,
//   DWORD  nNumberOfBytesToUnlockHigh
// );
func XUnlockFile(t *TLS, hFile uintptr, dwFileOffsetLow, dwFileOffsetHigh, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh uint32) int32 {
	panic(todo(""))
}

// BOOL UnlockFileEx(
//   HANDLE       hFile,
//   DWORD        dwReserved,
//   DWORD        nNumberOfBytesToUnlockLow,
//   DWORD        nNumberOfBytesToUnlockHigh,
//   LPOVERLAPPED lpOverlapped
// );
func XUnlockFileEx(t *TLS, hFile uintptr, dwReserved, nNumberOfBytesToUnlockLow, nNumberOfBytesToUnlockHigh uint32, lpOverlapped uintptr) int32 {
	panic(todo(""))
}

// BOOL UnmapViewOfFile(
//   LPCVOID lpBaseAddress
// );
func XUnmapViewOfFile(t *TLS, lpBaseAddress uintptr) int32 {
	panic(todo(""))
}

// int WideCharToMultiByte(
//   UINT                               CodePage,
//   DWORD                              dwFlags,
//   _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
//   int                                cchWideChar,
//   LPSTR                              lpMultiByteStr,
//   int                                cbMultiByte,
//   LPCCH                              lpDefaultChar,
//   LPBOOL                             lpUsedDefaultChar
// );
func XWideCharToMultiByte(t *TLS, CodePage uint32, dwFlags uint32, lpWideCharStr uintptr, cchWideChar int32, lpMultiByteStr uintptr, cbMultiByte int32, lpDefaultChar, lpUsedDefaultChar uintptr) int32 {
	panic(todo(""))
}

// void OutputDebugStringA(
//   LPCSTR lpOutputString
// )
func XOutputDebugStringA(t *TLS, lpOutputString uintptr) {
	panic(todo(""))
}

// BOOL FlushViewOfFile(
//   LPCVOID lpBaseAddress,
//   SIZE_T  dwNumberOfBytesToFlush
// );
func XFlushViewOfFile(t *TLS, lpBaseAddress uintptr, dwNumberOfBytesToFlush types.Size_t) int32 {
	panic(todo(""))
}

// int _stat64(const char *path, struct __stat64 *buffer);
func X_stat64(t *TLS, path, buffer uintptr) int32 {
	panic(todo(""))
}

// int _chsize(
//    int fd,
//    long size
// );
func X_chsize(t *TLS, fd int32, size long) int32 {
	panic(todo(""))
}

// int _snprintf(char *str, size_t size, const char *format, ...);
func X_snprintf(t *TLS, str uintptr, size types.Size_t, format, args uintptr) int32 {
	panic(todo(""))
}

// intptr_t _findfirst64i32(
//    const char *filespec,
//    struct _finddata64i32_t *fileinfo
// );
func X_findfirst64i32(t *TLS, filespec, fileinfo uintptr) types.Intptr_t {
	panic(todo(""))
}

// int _findnext64i32(
//    intptr_t handle,
//    struct _finddata64i32_t *fileinfo
// );
func X_findnext64i32(t *TLS, handle types.Intptr_t, fileinfo uintptr) int32 {
	panic(todo(""))
}

// int _findclose(
//    intptr_t handle
// );
func X_findclose(t *TLS, handle types.Intptr_t) int32 {
	panic(todo(""))
}

// DWORD GetEnvironmentVariableA(
//   LPCSTR lpName,
//   LPSTR  lpBuffer,
//   DWORD  nSize
// );
func XGetEnvironmentVariableA(t *TLS, lpName, lpBuffer uintptr, nSize uint32) uint32 {
	panic(todo(""))
}

// int _fstat64(
//    int fd,
//    struct __stat64 *buffer
// );
func X_fstat64(t *TLS, fd int32, buffer uintptr) int32 {
	panic(todo(""))
}

// HANDLE CreateEventA(
//   LPSECURITY_ATTRIBUTES lpEventAttributes,
//   BOOL                  bManualReset,
//   BOOL                  bInitialState,
//   LPCSTR                lpName
// );
func XCreateEventA(t *TLS, lpEventAttributes uintptr, bManualReset, bInitialState int32, lpName uintptr) uintptr {
	panic(todo(""))
}

// BOOL WINAPI CancelSynchronousIo(
//   _In_ HANDLE hThread
// );
func XCancelSynchronousIo(t *TLS, hThread uintptr) int32 {
	panic(todo(""))
}

func X_endthreadex(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_beginthread(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// uintptr_t _beginthreadex( // NATIVE CODE
//    void *security,
//    unsigned stack_size,
//    unsigned ( __stdcall *start_address )( void * ),
//    void *arglist,
//    unsigned initflag,
//    unsigned *thrdaddr
// );
func X_beginthreadex(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD GetCurrentThreadId();
func XGetCurrentThreadId(t *TLS) uint32 {
	panic(todo(""))
}

// BOOL GetExitCodeThread(
//   HANDLE  hThread,
//   LPDWORD lpExitCode
// );
func XGetExitCodeThread(t *TLS, hThread, lpExitCode uintptr) int32 {
	panic(todo(""))
}

// DWORD WaitForSingleObjectEx(
//   HANDLE hHandle,
//   DWORD  dwMilliseconds,
//   BOOL   bAlertable
// );
func XWaitForSingleObjectEx(t *TLS, hHandle uintptr, dwMilliseconds uint32, bAlertable int32) uint32 {
	panic(todo(""))
}

// DWORD MsgWaitForMultipleObjectsEx(
//   DWORD        nCount,
//   const HANDLE *pHandles,
//   DWORD        dwMilliseconds,
//   DWORD        dwWakeMask,
//   DWORD        dwFlags
// );
func XMsgWaitForMultipleObjectsEx(t *TLS, nCount uint32, pHandles uintptr, dwMilliseconds, dwWakeMask, dwFlags uint32) uint32 {
	panic(todo(""))
}

func XMessageBoxW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD GetModuleFileNameW(
//   HMODULE hModule,
//   LPWSTR  lpFileName,
//   DWORD   nSize
// );
func XGetModuleFileNameW(t *TLS, hModule, lpFileName uintptr, nSize uint32) uint32 {
	panic(todo(""))
}

// HANDLE FindFirstFileExW(
//   LPCWSTR            lpFileName,
//   FINDEX_INFO_LEVELS fInfoLevelId,
//   LPVOID             lpFindFileData,
//   FINDEX_SEARCH_OPS  fSearchOp,
//   LPVOID             lpSearchFilter,
//   DWORD              dwAdditionalFlags
// );
func XFindFirstFileExW(t *TLS, lpFileName uintptr, fInfoLevelId int32, lpFindFileData uintptr, fSearchOp int32, lpSearchFilter uintptr, dwAdditionalFlags uint32) uintptr {
	panic(todo(""))
}

// NET_API_STATUS NET_API_FUNCTION NetGetDCName(
//   LPCWSTR ServerName,
//   LPCWSTR DomainName,
//   LPBYTE  *Buffer
// );
func XNetGetDCName(t *TLS, ServerName, DomainName, Buffer uintptr) int32 {
	panic(todo(""))
}

// NET_API_STATUS NET_API_FUNCTION NetUserGetInfo(
//   LPCWSTR servername,
//   LPCWSTR username,
//   DWORD   level,
//   LPBYTE  *bufptr
// );
func XNetUserGetInfo(t *TLS, servername, username uintptr, level uint32, bufptr uintptr) uint32 {
	panic(todo(""))
}

func XlstrlenW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGetProfilesDirectoryW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XNetApiBufferFree(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD GetPrivateProfileStringA(
//   LPCSTR lpAppName,
//   LPCSTR lpKeyName,
//   LPCSTR lpDefault,
//   LPSTR  lpReturnedString,
//   DWORD  nSize,
//   LPCSTR lpFileName
// );
func XGetPrivateProfileStringA(t *TLS, lpAppName, lpKeyName, lpDefault, lpReturnedString uintptr, nSize uint32, lpFileName uintptr) uint32 {
	panic(todo(""))
}

func XGetWindowsDirectoryA(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL GetFileSecurityW(
//   LPCSTR               lpFileName,
//   SECURITY_INFORMATION RequestedInformation,
//   PSECURITY_DESCRIPTOR pSecurityDescriptor,
//   DWORD                nLength,
//   LPDWORD              lpnLengthNeeded
// );
func XGetFileSecurityW(t *TLS, lpFileName uintptr, RequestedInformation uint32, pSecurityDescriptor uintptr, nLength uint32, lpnLengthNeeded uintptr) int32 {
	panic(todo(""))
}

// BOOL GetSecurityDescriptorOwner(
//   PSECURITY_DESCRIPTOR pSecurityDescriptor,
//   PSID                 *pOwner,
//   LPBOOL               lpbOwnerDefaulted
// );
func XGetSecurityDescriptorOwner(t *TLS, pSecurityDescriptor, pOwner, lpbOwnerDefaulted uintptr) int32 {
	panic(todo(""))
}

// PSID_IDENTIFIER_AUTHORITY GetSidIdentifierAuthority(
//   PSID pSid
// );
func XGetSidIdentifierAuthority(t *TLS, pSid uintptr) uintptr {
	panic(todo(""))
}

// BOOL ImpersonateSelf(
//   SECURITY_IMPERSONATION_LEVEL ImpersonationLevel
// );
func XImpersonateSelf(t *TLS, ImpersonationLevel int32) int32 {
	panic(todo(""))
}

// BOOL OpenThreadToken(
//   HANDLE  ThreadHandle,
//   DWORD   DesiredAccess,
//   BOOL    OpenAsSelf,
//   PHANDLE TokenHandle
// );
func XOpenThreadToken(t *TLS, ThreadHandle uintptr, DesiredAccess uint32, OpenAsSelf int32, TokenHandle uintptr) int32 {
	panic(todo(""))
}

// HANDLE GetCurrentThread();
func XGetCurrentThread(t *TLS) uintptr {
	panic(todo(""))
}

// BOOL RevertToSelf();
func XRevertToSelf(t *TLS) int32 {
	panic(todo(""))
}

// BOOL AccessCheck(
//   PSECURITY_DESCRIPTOR pSecurityDescriptor,
//   HANDLE               ClientToken,
//   DWORD                DesiredAccess,
//   PGENERIC_MAPPING     GenericMapping,
//   PPRIVILEGE_SET       PrivilegeSet,
//   LPDWORD              PrivilegeSetLength,
//   LPDWORD              GrantedAccess,
//   LPBOOL               AccessStatus
// );
func XAccessCheck(t *TLS, pSecurityDescriptor, ClientToken uintptr, DesiredAccess uint32, GenericMapping, PrivilegeSet, PrivilegeSetLength, GrantedAccess, AccessStatus uintptr) int32 {
	panic(todo(""))
}

// int _wcsicmp(
//    const wchar_t *string1,
//    const wchar_t *string2
// );
func Xwcsicmp(t *TLS, string1, string2 uintptr) int32 {
	panic(todo(""))
}

// BOOL SetCurrentDirectoryW(
//   LPCTSTR lpPathName
// );
func XSetCurrentDirectoryW(t *TLS, lpPathName uintptr) int32 {
	panic(todo(""))
}

// DWORD GetCurrentDirectory(
//   DWORD  nBufferLength,
//   LPWTSTR lpBuffer
// );
func XGetCurrentDirectoryW(t *TLS, nBufferLength uint32, lpBuffer uintptr) uint32 {
	panic(todo(""))
}

// BOOL GetFileInformationByHandle(
//   HANDLE                       hFile,
//   LPBY_HANDLE_FILE_INFORMATION lpFileInformation
// );
func XGetFileInformationByHandle(t *TLS, hFile, lpFileInformation uintptr) int32 {
	panic(todo(""))
}

// BOOL GetVolumeInformationW(
//   LPCWSTR lpRootPathName,
//   LPWSTR  lpVolumeNameBuffer,
//   DWORD   nVolumeNameSize,
//   LPDWORD lpVolumeSerialNumber,
//   LPDWORD lpMaximumComponentLength,
//   LPDWORD lpFileSystemFlags,
//   LPWSTR  lpFileSystemNameBuffer,
//   DWORD   nFileSystemNameSize
// );
func XGetVolumeInformationW(t *TLS, lpRootPathName, lpVolumeNameBuffer uintptr, nVolumeNameSize uint32, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer uintptr, nFileSystemNameSize uint32) int32 {
	panic(todo(""))
}

// wchar_t *wcschr(
//    const wchar_t *str,
//    wchar_t c
// );
func Xwcschr(t *TLS, str uintptr, c wchar_t) uintptr {
	panic(todo(""))
}

// BOOL SetFileTime(
//   HANDLE         hFile,
//   const FILETIME *lpCreationTime,
//   const FILETIME *lpLastAccessTime,
//   const FILETIME *lpLastWriteTime
// );
func XSetFileTime(t *TLS, hFile uintptr, lpCreationTime, lpLastAccessTime, lpLastWriteTime uintptr) int32 {
	panic(todo(""))
}

// DWORD GetNamedSecurityInfoW(
//   LPCWSTR              pObjectName,
//   SE_OBJECT_TYPE       ObjectType,
//   SECURITY_INFORMATION SecurityInfo,
//   PSID                 *ppsidOwner,
//   PSID                 *ppsidGroup,
//   PACL                 *ppDacl,
//   PACL                 *ppSacl,
//   PSECURITY_DESCRIPTOR *ppSecurityDescriptor
// );
func XGetNamedSecurityInfoW(t *TLS, pObjectName uintptr, ObjectType, SecurityInfo uint32, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor uintptr) uint32 {
	panic(todo(""))
}

// BOOL OpenProcessToken(
//   HANDLE  ProcessHandle,
//   DWORD   DesiredAccess,
//   PHANDLE TokenHandle
// );
func XOpenProcessToken(t *TLS, ProcessHandle uintptr, DesiredAccess uint32, TokenHandle uintptr) int32 {
	panic(todo(""))
}

// BOOL GetTokenInformation(
//   HANDLE                  TokenHandle,
//   TOKEN_INFORMATION_CLASS TokenInformationClass,
//   LPVOID                  TokenInformation,
//   DWORD                   TokenInformationLength,
//   PDWORD                  ReturnLength
// );
func XGetTokenInformation(t *TLS, TokenHandle uintptr, TokenInformationClass uint32, TokenInformation uintptr, TokenInformationLength uint32, ReturnLength uintptr) int32 {
	panic(todo(""))
}

// BOOL EqualSid(
//   PSID pSid1,
//   PSID pSid2
// );
func XEqualSid(t *TLS, pSid1, pSid2 uintptr) int32 {
	panic(todo(""))
}

// int WSAStartup(
//   WORD      wVersionRequired,
//   LPWSADATA lpWSAData
// );
func XWSAStartup(t *TLS, wVersionRequired uint16, lpWSAData uintptr) int32 {
	panic(todo(""))
}

// HMODULE GetModuleHandleW(
//   LPCWSTR lpModuleName
// );
func XGetModuleHandleW(t *TLS, lpModuleName uintptr) uintptr {
	panic(todo(""))
}

// DWORD GetEnvironmentVariableW(
//   LPCWSTR lpName,
//   LPWSTR  lpBuffer,
//   DWORD   nSize
// );
func XGetEnvironmentVariableW(t *TLS, lpName, lpBuffer uintptr, nSize uint32) uint32 {
	panic(todo(""))
}

// int lstrcmpiA(
//   LPCSTR lpString1,
//   LPCSTR lpString2
// );
func XlstrcmpiA(t *TLS, lpString1, lpString2 uintptr) int32 {
	panic(todo(""))
}

func XGetModuleFileNameA(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// UINT GetACP();
func XGetACP(t *TLS) uint32 {
	panic(todo(""))
}

// BOOL GetUserNameW(
//   LPWSTR  lpBuffer,
//   LPDWORD pcbBuffer
// );
func XGetUserNameW(t *TLS, lpBuffer, pcbBuffer uintptr) int32 {
	panic(todo(""))
}

// HMODULE LoadLibraryExW(
//   LPCWSTR lpLibFileName,
//   HANDLE  hFile,
//   DWORD   dwFlags
// );
func XLoadLibraryExW(t *TLS, lpLibFileName, hFile uintptr, dwFlags uint32) uintptr {
	panic(todo(""))
}

func Xwcscpy(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XwsprintfW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// ATOM RegisterClassW(
//   const WNDCLASSW *lpWndClass
// );
func XRegisterClassW(t *TLS, lpWndClass uintptr) int32 {
	panic(todo(""))
}

func XKillTimer(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDestroyWindow(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL UnregisterClassW(
//   LPCWSTR   lpClassName,
//   HINSTANCE hInstance
// );
func XUnregisterClassW(t *TLS, lpClassName, hInstance uintptr) int32 {
	panic(todo(""))
}

func XPostMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetTimer(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// HWND CreateWindowExW(
//   DWORD     dwExStyle,
//   LPCWSTR   lpClassName,
//   LPCWSTR   lpWindowName,
//   DWORD     dwStyle,
//   int       X,
//   int       Y,
//   int       nWidth,
//   int       nHeight,
//   HWND      hWndParent,
//   HMENU     hMenu,
//   HINSTANCE hInstance,
//   LPVOID    lpParam
// );
func XCreateWindowExW(t *TLS, dwExStyle uint32, lpClassName, lpWindowName uintptr, dwStyle uint32, x, y, nWidth, nHeight int32, hWndParent, hMenu, hInstance, lpParam uintptr) uintptr {
	panic(todo(""))
}

// LRESULT LRESULT DefWindowProcW(
//   HWND   hWnd,
//   UINT   Msg,
//   WPARAM wParam,
//   LPARAM lParam
// );
func XDefWindowProcW(t *TLS, _ ...interface{}) int64 {
	panic(todo(""))
}

// BOOL PeekMessageW(
//   LPMSG lpMsg,
//   HWND  hWnd,
//   UINT  wMsgFilterMin,
//   UINT  wMsgFilterMax,
//   UINT  wRemoveMsg
// );
func XPeekMessageW(t *TLS, lpMsg, hWnd uintptr, wMsgFilterMin, wMsgFilterMax, wRemoveMsg uint32) int32 {
	panic(todo(""))
}

func XGetMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XPostQuitMessage(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XTranslateMessage(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDispatchMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// DWORD SleepEx(
//   DWORD dwMilliseconds,
//   BOOL  bAlertable
// );
func XSleepEx(t *TLS, dwMilliseconds uint32, bAlertable int32) uint32 {
	panic(todo(""))
}

// BOOL CreatePipe(
//   PHANDLE               hReadPipe,
//   PHANDLE               hWritePipe,
//   LPSECURITY_ATTRIBUTES lpPipeAttributes,
//   DWORD                 nSize
// );
func XCreatePipe(t *TLS, hReadPipe, hWritePipe, lpPipeAttributes uintptr, nSize uint32) int32 {
	panic(todo(""))
}

// BOOL CreateProcessW(
//   LPCWSTR               lpApplicationName,
//   LPWSTR                lpCommandLine,
//   LPSECURITY_ATTRIBUTES lpProcessAttributes,
//   LPSECURITY_ATTRIBUTES lpThreadAttributes,
//   BOOL                  bInheritHandles,
//   DWORD                 dwCreationFlags,
//   LPVOID                lpEnvironment,
//   LPCWSTR               lpCurrentDirectory,
//   LPSTARTUPINFOW        lpStartupInfo,
//   LPPROCESS_INFORMATION lpProcessInformation
// );
func XCreateProcessW(t *TLS, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes uintptr, bInheritHandles int32, dwCreationFlags uint32, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation uintptr) int32 {
	panic(todo(""))
}

// DWORD WaitForInputIdle(
//   HANDLE hProcess,
//   DWORD  dwMilliseconds
// );
func XWaitForInputIdle(t *TLS, hProcess uintptr, dwMilliseconds uint32) int32 {
	panic(todo(""))
}

// DWORD SearchPathW(
//   LPCWSTR lpPath,
//   LPCWSTR lpFileName,
//   LPCWSTR lpExtension,
//   DWORD   nBufferLength,
//   LPWSTR  lpBuffer,
//   LPWSTR  *lpFilePart
// );
func XSearchPathW(t *TLS, lpPath, lpFileName, lpExtension uintptr, nBufferLength uint32, lpBuffer, lpFilePart uintptr) int32 {
	panic(todo(""))
}

func XGetShortPathNameW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL GetExitCodeProcess(
//   HANDLE  hProcess,
//   LPDWORD lpExitCode
// );
func XGetExitCodeProcess(t *TLS, hProcess, lpExitCode uintptr) int32 {
	panic(todo(""))
}

// BOOL PeekNamedPipe(
//   HANDLE  hNamedPipe,
//   LPVOID  lpBuffer,
//   DWORD   nBufferSize,
//   LPDWORD lpBytesRead,
//   LPDWORD lpTotalBytesAvail,
//   LPDWORD lpBytesLeftThisMessage
// );
func XPeekNamedPipe(t *TLS, hNamedPipe, lpBuffer uintptr, nBufferSize uint32, lpBytesRead, lpTotalBytesAvail, lpBytesLeftThisMessage uintptr) int32 {
	panic(todo(""))
}

// long _InterlockedExchange(
//    long volatile * Target,
//    long Value
// );
func X_InterlockedExchange(t *TLS, Target uintptr, Value long) long {
	panic(todo(""))
}

func XTerminateThread(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// BOOL GetComputerNameW(
//   LPWSTR  lpBuffer,
//   LPDWORD nSize
// );
func XGetComputerNameW(t *TLS, lpBuffer, nSize uintptr) int32 {
	panic(todo(""))
}

func Xgethostname(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSendMessageW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWSAGetLastError(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xclosesocket(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWspiapiFreeAddrInfo(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWspiapiGetNameInfo(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XIN6_ADDR_EQUAL(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X__ccgo_in6addr_anyp(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XIN6_IS_ADDR_V4MAPPED(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetHandleInformation(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xioctlsocket(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGetWindowLongPtrW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSetWindowLongPtrW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XWSAAsyncSelect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func Xinet_ntoa(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func X_controlfp(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

// BOOL QueryPerformanceFrequency(
//   LARGE_INTEGER *lpFrequency
// );
func XQueryPerformanceFrequency(t *TLS, lpFrequency uintptr) int32 {
	panic(todo(""))
}

// void _ftime( struct _timeb *timeptr );
func X_ftime(t *TLS, timeptr uintptr) {
	panic(todo(""))
}

func Xgmtime(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeInitializeW(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

func XDdeCreateStringHandleW(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeNameService(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_snwprintf(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeQueryStringW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func X_wcsicmp(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeCreateDataHandle(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeAccessData(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeUnaccessData(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeUninitialize(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeConnect(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeFreeStringHandle(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegisterClassExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGlobalGetAtomNameW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XSendMessageTimeoutW(t *TLS, _ ...interface{}) int64 {
	panic(todo(""))
}

func XGlobalAddAtomW(t *TLS, _ ...interface{}) uint16 {
	panic(todo(""))
}

func XEnumWindows(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XIsWindow(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XGlobalDeleteAtom(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeGetLastError(t *TLS, _ ...interface{}) uint32 {
	panic(todo(""))
}

func XDdeClientTransaction(t *TLS, _ ...interface{}) uintptr {
	panic(todo(""))
}

func XDdeAbandonTransaction(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeFreeDataHandle(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeGetData(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XDdeDisconnect(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegCloseKey(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegDeleteValueW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegEnumKeyExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegQueryValueExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegEnumValueW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegConnectRegistryW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegCreateKeyExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegOpenKeyExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegDeleteKeyW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

func XRegSetValueExW(t *TLS, _ ...interface{}) int32 {
	panic(todo(""))
}

// int _vsnwprintf(
//    wchar_t *buffer,
//    size_t count,
//    const wchar_t *format,
//    va_list argptr
// );
func X__mingw_vsnwprintf(t *TLS, buffer uintptr, count types.Size_t, format, va uintptr) int32 {
	panic(todo(""))
}
