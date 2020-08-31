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
	"strconv"
	"strings"
	"syscall"
	gotime "time"
	"unsafe"

	"golang.org/x/sys/unix"
	asmsignal "modernc.org/libc/asm/signal"
	"modernc.org/libc/errno"
	"modernc.org/libc/fts"
	"modernc.org/libc/grp"
	"modernc.org/libc/langinfo"
	"modernc.org/libc/limits"
	"modernc.org/libc/netinet/in"
	"modernc.org/libc/pwd"
	"modernc.org/libc/signal"
	"modernc.org/libc/stdio"
	"modernc.org/libc/sys/socket"
	"modernc.org/libc/sys/stat"
	"modernc.org/libc/sys/types"
	"modernc.org/libc/termios"
	"modernc.org/libc/time"
	"modernc.org/libc/unistd"
)

var (
	in6_addr_any in.In6_addr
)

type (
	long  = types.X__syscall_slong_t
	ulong = types.X__syscall_ulong_t
)

func fwrite(fd int32, b []byte) (int, error) {
	if fd == unistd.STDOUT_FILENO {
		return write(b)
	}

	return unix.Write(int(fd), b) //TODO use Xwrite
}

// int getrusage(int who, struct rusage *usage);
func Xgetrusage(t *TLS, who int32, usage uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_GETRUSAGE, uintptr(who), usage, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// char *fgets(char *s, int size, FILE *stream);
func Xfgets(t *TLS, s uintptr, size int32, stream uintptr) uintptr {
	fd := int((*stdio.FILE)(unsafe.Pointer(stream)).F_fileno)
	var b []byte
	buf := [1]byte{}
	for ; size > 0; size-- {
		n, err := unix.Read(fd, buf[:])
		if n != 0 {
			b = append(b, buf[0])
			if buf[0] == '\n' {
				b = append(b, 0)
				copy((*RawMem)(unsafe.Pointer(s))[:len(b):len(b)], b)
				return s
			}

			continue
		}

		switch {
		case n == 0 && err == nil && len(b) == 0:
			return 0
		default:
			panic(todo(""))
		}

		// if err == nil {
		// 	panic("internal error")
		// }

		// if len(b) != 0 {
		// 		b = append(b, 0)
		// 		copy((*RawMem)(unsafe.Pointer(s)[:len(b)]), b)
		// 		return s
		// }

		// t.setErrno(err)
	}
	panic(todo(""))
}

// int lstat(const char *pathname, struct stat *statbuf);
func Xlstat(t *TLS, pathname, statbuf uintptr) int32 {
	return Xlstat64(t, pathname, statbuf)
}

// int lstat(const char *pathname, struct stat *statbuf);
func Xlstat64(t *TLS, pathname, statbuf uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_LSTAT, pathname, statbuf, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int stat(const char *pathname, struct stat *statbuf);
func Xstat(t *TLS, pathname, statbuf uintptr) int32 {
	return Xstat64(t, pathname, statbuf)
}

// int stat(const char *pathname, struct stat *statbuf);
func Xstat64(t *TLS, pathname, statbuf uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_STAT, pathname, statbuf, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int mkdir(const char *path, mode_t mode);
func Xmkdir(t *TLS, path uintptr, mode types.Mode_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_MKDIR, path, uintptr(mode), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int symlink(const char *target, const char *linkpath);
func Xsymlink(t *TLS, target, linkpath uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_SYMLINK, target, linkpath, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int chmod(const char *pathname, mode_t mode)
func Xchmod(t *TLS, pathname uintptr, mode types.Mode_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_CHMOD, pathname, uintptr(mode), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int utimes(const char *filename, const struct timeval times[2]);
func Xutimes(t *TLS, filename, times uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_UTIMES, filename, times, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int unlink(const char *pathname);
func Xunlink(t *TLS, pathname uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_UNLINK, pathname, 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int access(const char *pathname, int mode);
func Xaccess(t *TLS, pathname uintptr, mode int32) int32 {
	if _, _, err := unix.Syscall(unix.SYS_ACCESS, pathname, uintptr(mode), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int chdir(const char *path);
func Xchdir(t *TLS, path uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_CHDIR, path, 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

var localtime time.Tm

// struct tm *localtime(const time_t *timep);
func Xlocaltime(_ *TLS, timep uintptr) uintptr {
	loc := gotime.Local
	if r := getenv(Environ(), "TZ"); r != 0 {
		zone, off := parseZone(GoString(r))
		loc = gotime.FixedZone(zone, -off)
	}
	ut := *(*unix.Time_t)(unsafe.Pointer(timep))
	t := gotime.Unix(int64(ut), 0).In(loc)
	localtime.Ftm_sec = int32(t.Second())
	localtime.Ftm_min = int32(t.Minute())
	localtime.Ftm_hour = int32(t.Hour())
	localtime.Ftm_mday = int32(t.Day())
	localtime.Ftm_mon = int32(t.Month() - 1)
	localtime.Ftm_year = int32(t.Year() - 1900)
	localtime.Ftm_wday = int32(t.Weekday())
	localtime.Ftm_yday = int32(t.YearDay())
	localtime.Ftm_isdst = Bool32(isTimeDST(t))
	return uintptr(unsafe.Pointer(&localtime))
}

// struct tm *localtime_r(const time_t *timep, struct tm *result);
func Xlocaltime_r(_ *TLS, timep, result uintptr) uintptr {
	loc := gotime.Local
	if r := getenv(Environ(), "TZ"); r != 0 {
		zone, off := parseZone(GoString(r))
		loc = gotime.FixedZone(zone, -off)
	}
	ut := *(*unix.Time_t)(unsafe.Pointer(timep))
	t := gotime.Unix(int64(ut), 0).In(loc)
	(*time.Tm)(unsafe.Pointer(result)).Ftm_sec = int32(t.Second())
	(*time.Tm)(unsafe.Pointer(result)).Ftm_min = int32(t.Minute())
	(*time.Tm)(unsafe.Pointer(result)).Ftm_hour = int32(t.Hour())
	(*time.Tm)(unsafe.Pointer(result)).Ftm_mday = int32(t.Day())
	(*time.Tm)(unsafe.Pointer(result)).Ftm_mon = int32(t.Month() - 1)
	(*time.Tm)(unsafe.Pointer(result)).Ftm_year = int32(t.Year() - 1900)
	(*time.Tm)(unsafe.Pointer(result)).Ftm_wday = int32(t.Weekday())
	(*time.Tm)(unsafe.Pointer(result)).Ftm_yday = int32(t.YearDay())
	(*time.Tm)(unsafe.Pointer(result)).Ftm_isdst = Bool32(isTimeDST(t))
	return result
}

// int open(const char *pathname, int flags, ...);
func Xopen(t *TLS, pathname uintptr, flags int32, args uintptr) int32 {
	return Xopen64(t, pathname, flags, args)
}

// int open(const char *pathname, int flags, ...);
func Xopen64(t *TLS, pathname uintptr, flags int32, args uintptr) int32 {
	var mode types.Mode_t
	if args != 0 {
		mode = *(*types.Mode_t)(unsafe.Pointer(args))
	}
	n, _, err := unix.Syscall(unix.SYS_OPEN, pathname, uintptr(flags), uintptr(mode))
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return int32(n)
}

// off_t lseek(int fd, off_t offset, int whence);
func Xlseek(t *TLS, fd int32, offset types.Off_t, whence int32) types.Off_t {
	return types.Off_t(Xlseek64(t, fd, types.X__off64_t(offset), whence))
}

// off64_t lseek64(int fd, off64_t offset, int whence);
func Xlseek64(t *TLS, fd int32, offset types.X__off64_t, whence int32) types.X__off64_t {
	off, err := unix.Seek(int(fd), offset, int(whence))
	if err != nil {
		t.setErrno(err)
		return -1
	}

	return off
}

var fsyncStatbuf stat.Stat

// int fsync(int fd);
func Xfsync(t *TLS, fd int32) int32 {
	if noFsync {
		// Simulate -DSQLITE_NO_SYNC for sqlite3 testfixture, see function full_sync in sqlite3.c
		return Xfstat(t, fd, uintptr(unsafe.Pointer(&fsyncStatbuf)))
	}

	if _, _, err := unix.Syscall(unix.SYS_FSYNC, uintptr(fd), 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// long sysconf(int name);
func Xsysconf(t *TLS, name int32) long {
	switch name {
	case unistd.X_SC_PAGESIZE:
		return long(unix.Getpagesize())
	}

	panic(todo(""))
}

// int close(int fd);
func Xclose(t *TLS, fd int32) int32 {
	if _, _, err := unix.Syscall(unix.SYS_CLOSE, uintptr(fd), 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// char *getcwd(char *buf, size_t size);
func Xgetcwd(t *TLS, buf uintptr, size types.Size_t) uintptr {
	n, _, err := unix.Syscall(unix.SYS_GETCWD, buf, uintptr(size), 0)
	if err != 0 {
		t.setErrno(err)
		return 0
	}

	return n
}

// int fstat(int fd, struct stat *statbuf);
func Xfstat(t *TLS, fd int32, statbuf uintptr) int32 {
	return Xfstat64(t, fd, statbuf)
}

// int fstat(int fd, struct stat *statbuf);
func Xfstat64(t *TLS, fd int32, statbuf uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_FSTAT, uintptr(fd), statbuf, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int ftruncate(int fd, off_t length);
func Xftruncate(t *TLS, fd int32, length types.Off_t) int32 {
	return Xftruncate64(t, fd, types.X__off64_t(length))
}

// int ftruncate(int fd, off_t length);
func Xftruncate64(t *TLS, fd int32, length types.X__off64_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_FTRUNCATE, uintptr(fd), uintptr(length), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int fcntl(int fd, int cmd, ... /* arg */ );
func Xfcntl(t *TLS, fd, cmd int32, args uintptr) int32 {
	return Xfcntl64(t, fd, cmd, args)
}

// int fcntl(int fd, int cmd, ... /* arg */ );
func Xfcntl64(t *TLS, fd, cmd int32, args uintptr) int32 {
	var arg uintptr
	if args != 0 {
		arg = *(*uintptr)(unsafe.Pointer(args))
	}
	n, _, err := unix.Syscall(unix.SYS_FCNTL, uintptr(fd), uintptr(cmd), arg)
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return int32(n)
}

// ssize_t read(int fd, void *buf, size_t count);
func Xread(t *TLS, fd int32, buf uintptr, count types.Size_t) types.Ssize_t {
	n, _, err := unix.Syscall(unix.SYS_READ, uintptr(fd), buf, uintptr(count))
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return types.Ssize_t(n)
}

// ssize_t write(int fd, const void *buf, size_t count);
func Xwrite(t *TLS, fd int32, buf uintptr, count types.Size_t) types.Ssize_t {
	n, _, err := unix.Syscall(unix.SYS_WRITE, uintptr(fd), buf, uintptr(count))
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return types.Ssize_t(n)
}

// int fchmod(int fd, mode_t mode);
func Xfchmod(t *TLS, fd int32, mode types.Mode_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_FCHMOD, uintptr(fd), uintptr(mode), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int rmdir(const char *pathname);
func Xrmdir(t *TLS, pathname uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_RMDIR, pathname, 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int fchown(int fd, uid_t owner, gid_t group);
func Xfchown(t *TLS, fd int32, owner types.Uid_t, group types.Gid_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_FCHOWN, uintptr(fd), uintptr(owner), uintptr(group)); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// uid_t geteuid(void);
func Xgeteuid(t *TLS) types.Uid_t {
	n, _, _ := unix.Syscall(unix.SYS_GETEUID, 0, 0, 0)
	return types.Uid_t(n)
}

// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
func Xmmap64(t *TLS, addr uintptr, length types.Size_t, prot, flags, fd int32, offset types.X__off64_t) uintptr {
	data, _, err := unix.Syscall6(unix.SYS_MMAP, addr, uintptr(length), uintptr(prot), uintptr(flags), uintptr(fd), uintptr(offset))
	if err != 0 {
		t.setErrno(err)
		return ^uintptr(0) // (void*)-1
	}

	return data
}

// int munmap(void *addr, size_t length);
func Xmunmap(t *TLS, addr uintptr, length types.Size_t) int32 {
	if _, _, err := unix.Syscall(unix.SYS_MUNMAP, addr, uintptr(length), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int gettimeofday(struct timeval *tv, struct timezone *tz);
func Xgettimeofday(t *TLS, tv, tz uintptr) int32 {
	if tz != 0 {
		panic(todo(""))
	}

	var tvs unix.Timeval
	err := unix.Gettimeofday(&tvs)
	if err != nil {
		t.setErrno(err)
		return -1
	}

	*(*unix.Timeval)(unsafe.Pointer(tv)) = tvs
	return 0
}

// int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
func Xgetsockopt(t *TLS, sockfd, level, optname int32, optval, optlen uintptr) int32 {
	if _, _, err := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(sockfd), uintptr(level), uintptr(optname), optval, optlen, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
func Xsetsockopt(t *TLS, sockfd, level, optname int32, optval uintptr, optlen socket.Socklen_t) int32 {
	if _, _, err := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(sockfd), uintptr(level), uintptr(optname), optval, uintptr(optlen), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int ioctl(int fd, unsigned long request, ...);
func Xioctl(t *TLS, fd int32, request ulong, va uintptr) int32 {
	var argp uintptr
	if va != 0 {
		argp = VaUintptr(&va)
	}
	n, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(request), argp)
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return int32(n)
}

// int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
func Xgetsockname(t *TLS, sockfd int32, addr, addrlen uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_GETSOCKNAME, uintptr(sockfd), addr, addrlen); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
func Xselect(t *TLS, nfds int32, readfds, writefds, exceptfds, timeout uintptr) int32 {
	n, err := unix.Select(
		int(nfds),
		(*unix.FdSet)(unsafe.Pointer(readfds)),
		(*unix.FdSet)(unsafe.Pointer(writefds)),
		(*unix.FdSet)(unsafe.Pointer(exceptfds)),
		(*unix.Timeval)(unsafe.Pointer(timeout)),
	)
	if err != nil {
		t.setErrno(err)
		return -1
	}

	return int32(n)
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

// int mkfifo(const char *pathname, mode_t mode);
func Xmkfifo(t *TLS, pathname uintptr, mode types.Mode_t) int32 {
	if err := unix.Mkfifo(GoString(pathname), mode); err != nil {
		t.setErrno(err)
		return -1
	}

	return 0
}

// mode_t umask(mode_t mask);
func Xumask(t *TLS, mask types.Mode_t) types.Mode_t {
	n, _, _ := unix.Syscall(unix.SYS_UMASK, uintptr(mask), 0, 0)
	return types.Mode_t(n)
}

// int utime(const char *filename, const struct utimbuf *times);
func Xutime(t *TLS, filename, times uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_UTIME, filename, times, 0); err != 0 {
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

// int execvp(const char *file, char *const argv[]);
func Xexecvp(t *TLS, file, argv uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_EXECVE, file, argv, Environ()); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// pid_t waitpid(pid_t pid, int *wstatus, int options);
func Xwaitpid(t *TLS, pid types.Pid_t, wstatus uintptr, optname int32) types.Pid_t {
	n, _, err := unix.Syscall6(unix.SYS_WAIT4, uintptr(pid), wstatus, uintptr(optname), 0, 0, 0)
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return types.Pid_t(n)
}

// int uname(struct utsname *buf);
func Xuname(t *TLS, buf uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_UNAME, buf, 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// ssize_t recv(int sockfd, void *buf, size_t len, int flags);
func Xrecv(t *TLS, sockfd int32, buf uintptr, len types.Size_t, flags int32) types.Ssize_t {
	n, _, err := unix.Syscall6(unix.SYS_RECVFROM, uintptr(sockfd), buf, uintptr(len), uintptr(flags), 0, 0)
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return types.Ssize_t(n)
}

// ssize_t send(int sockfd, const void *buf, size_t len, int flags);
func Xsend(t *TLS, sockfd int32, buf uintptr, len types.Size_t, flags int32) types.Ssize_t {
	n, _, err := unix.Syscall6(unix.SYS_SENDTO, uintptr(sockfd), buf, uintptr(len), uintptr(flags), 0, 0)
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return types.Ssize_t(n)
}

// int shutdown(int sockfd, int how);
func Xshutdown(t *TLS, sockfd, how int32) int32 {
	if _, _, err := unix.Syscall(unix.SYS_SHUTDOWN, uintptr(sockfd), uintptr(how), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
func Xgetpeername(t *TLS, sockfd int32, addr uintptr, addrlen uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_GETPEERNAME, uintptr(sockfd), addr, uintptr(addrlen)); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int socket(int domain, int type, int protocol);
func Xsocket(t *TLS, domain, type1, protocol int32) int32 {
	n, _, err := unix.Syscall(unix.SYS_SOCKET, uintptr(domain), uintptr(type1), uintptr(protocol))
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return int32(n)
}

// int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
func Xbind(t *TLS, sockfd int32, addr uintptr, addrlen uint32) int32 {
	n, _, err := unix.Syscall(unix.SYS_BIND, uintptr(sockfd), addr, uintptr(addrlen))
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return int32(n)
}

// int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
func Xconnect(t *TLS, sockfd int32, addr uintptr, addrlen uint32) int32 {
	if _, _, err := unix.Syscall(unix.SYS_CONNECT, uintptr(sockfd), addr, uintptr(addrlen)); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int listen(int sockfd, int backlog);
func Xlisten(t *TLS, sockfd, backlog int32) int32 {
	if _, _, err := unix.Syscall(unix.SYS_LISTEN, uintptr(sockfd), uintptr(backlog), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
func Xaccept(t *TLS, sockfd int32, addr uintptr, addrlen uintptr) int32 {
	n, _, err := unix.Syscall6(unix.SYS_ACCEPT4, uintptr(sockfd), addr, uintptr(addrlen), 0, 0, 0)
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return int32(n)
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
func Xgetrlimit(t *TLS, resource int32, rlim uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_GETRLIMIT, uintptr(resource), uintptr(rlim), 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	return 0
}

// int setrlimit(int resource, const struct rlimit *rlim);
func Xsetrlimit(t *TLS, resource int32, rlim uintptr) int32 {
	if _, _, err := unix.Syscall(unix.SYS_SETRLIMIT, uintptr(resource), uintptr(rlim), 0); err != 0 {
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

	return types.Time_t(n)
}

// uid_t getuid(void);
func Xgetuid(t *TLS) types.Uid_t {
	return types.Uid_t(os.Getuid())
}

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

var staticGetpwuid pwd.Passwd

func init() {
	atExit = append(atExit, func() { closePasswd(&staticGetpwuid) })
}

func closePasswd(p *pwd.Passwd) {
	Xfree(nil, p.Fpw_name)
	Xfree(nil, p.Fpw_passwd)
	Xfree(nil, p.Fpw_gecos)
	Xfree(nil, p.Fpw_dir)
	Xfree(nil, p.Fpw_shell)
	*p = pwd.Passwd{}
}

// struct passwd *getpwuid(uid_t uid);
func Xgetpwuid(t *TLS, uid uint32) uintptr {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		panic(todo("", err))
	}

	defer f.Close()

	sid := strconv.Itoa(int(uid))
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// eg. "root:x:0:0:root:/root:/bin/bash"
		a := strings.Split(sc.Text(), ":")
		if len(a) < 7 {
			panic(todo(""))
		}

		if a[2] == sid {
			uid, err := strconv.Atoi(a[2])
			if err != nil {
				panic(todo(""))
			}

			gid, err := strconv.Atoi(a[3])
			if err != nil {
				panic(todo(""))
			}

			closePasswd(&staticGetpwuid)
			gecos := a[4]
			if strings.Contains(gecos, ",") {
				a := strings.Split(gecos, ",")
				gecos = a[0]
			}
			initPasswd(t, &staticGetpwuid, a[0], a[1], uint32(uid), uint32(gid), gecos, a[5], a[6])
			return uintptr(unsafe.Pointer(&staticGetpwuid))
		}
	}

	if sc.Err() != nil {
		panic(todo(""))
	}

	return 0
}

func initPasswd(t *TLS, p *pwd.Passwd, name, pwd string, uid, gid uint32, gecos, dir, shell string) {
	p.Fpw_name = cString(t, name)
	p.Fpw_passwd = cString(t, pwd)
	p.Fpw_uid = uid
	p.Fpw_gid = gid
	p.Fpw_gecos = cString(t, gecos)
	p.Fpw_dir = cString(t, dir)
	p.Fpw_shell = cString(t, shell)
}

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
	if stream == 0 {
		t.setErrno(errno.EBADF)
		return -1
	}

	if fd := (*stdio.FILE)(unsafe.Pointer(stream)).F_fileno; fd >= 0 {
		return fd
	}

	t.setErrno(errno.EBADF)
	return -1
}

var staticGetpwnam pwd.Passwd

func init() {
	atExit = append(atExit, func() { closePasswd(&staticGetpwnam) })
}

// struct passwd *getpwnam(const char *name);
func Xgetpwnam(t *TLS, name uintptr) uintptr {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		panic(todo("", err))
	}

	defer f.Close()

	sname := GoString(name)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// eg. "root:x:0:0:root:/root:/bin/bash"
		a := strings.Split(sc.Text(), ":")
		if len(a) < 7 {
			panic(todo(""))
		}

		if a[0] == sname {
			uid, err := strconv.Atoi(a[2])
			if err != nil {
				panic(todo(""))
			}

			gid, err := strconv.Atoi(a[3])
			if err != nil {
				panic(todo(""))
			}

			closePasswd(&staticGetpwnam)
			gecos := a[4]
			if strings.Contains(gecos, ",") {
				a := strings.Split(gecos, ",")
				gecos = a[0]
			}
			initPasswd(t, &staticGetpwnam, a[0], a[1], uint32(uid), uint32(gid), gecos, a[5], a[6])
			return uintptr(unsafe.Pointer(&staticGetpwnam))
		}
	}

	if sc.Err() != nil {
		panic(todo(""))
	}

	return 0
}

var staticGetgrnam grp.Group

func init() {
	atExit = append(atExit, func() { closeGroup(&staticGetgrnam) })
}

// struct group *getgrnam(const char *name);
func Xgetgrnam(t *TLS, name uintptr) uintptr {
	f, err := os.Open("/etc/group")
	if err != nil {
		panic(todo(""))
	}

	defer f.Close()

	sname := GoString(name)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// eg. "root:x:0:"
		a := strings.Split(sc.Text(), ":")
		if len(a) < 4 {
			panic(todo(""))
		}

		if a[0] == sname {
			closeGroup(&staticGetgrnam)
			gid, err := strconv.Atoi(a[2])
			if err != nil {
				panic(todo(""))
			}

			var names []string
			if a[3] != "" {
				names = strings.Split(a[3], ",")
			}
			initGroup(t, &staticGetgrnam, a[0], a[1], uint32(gid), names)
			return uintptr(unsafe.Pointer(&staticGetgrnam))
		}
	}

	if sc.Err() != nil {
		panic(todo(""))
	}

	return 0
}

func closeGroup(p *grp.Group) {
	Xfree(nil, p.Fgr_name)
	Xfree(nil, p.Fgr_passwd)
	if p.Fgr_mem != 0 {
		panic(todo(""))
	}

	*p = grp.Group{}
}

func initGroup(t *TLS, p *grp.Group, name, pwd string, gid uint32, names []string) {
	p.Fgr_name = cString(t, name)
	p.Fgr_passwd = cString(t, pwd)
	p.Fgr_gid = gid
	p.Fgr_mem = 0
	if len(names) != 0 {
		panic(todo("%q %q %v %q %v", name, pwd, gid, names, len(names)))
	}
}

func init() {
	atExit = append(atExit, func() { closeGroup(&staticGetgrgid) })
}

var staticGetgrgid grp.Group

// struct group *getgrgid(gid_t gid);
func Xgetgrgid(t *TLS, gid uint32) uintptr {
	f, err := os.Open("/etc/group")
	if err != nil {
		panic(todo(""))
	}

	defer f.Close()

	sid := strconv.Itoa(int(gid))
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// eg. "root:x:0:"
		a := strings.Split(sc.Text(), ":")
		if len(a) < 4 {
			panic(todo(""))
		}

		if a[2] == sid {
			closeGroup(&staticGetgrgid)
			var names []string
			if a[3] != "" {
				names = strings.Split(a[3], ",")
			}
			initGroup(t, &staticGetgrgid, a[0], a[1], gid, names)
			return uintptr(unsafe.Pointer(&staticGetgrgid))
		}
	}

	if sc.Err() != nil {
		panic(todo(""))
	}

	return 0
}

// struct dirent *readdir(DIR *dirp);
func Xreaddir(t *TLS, dirp uintptr) uintptr {
	return Xreaddir64(t, dirp)
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

// int mkstemps(char *template, int suffixlen);
func Xmkstemps(t *TLS, template uintptr, suffixlen int32) int32 {
	len := uintptr(Xstrlen(t, template))
	x := template + uintptr(len-6) - uintptr(suffixlen)
	for i := uintptr(0); i < 6; i++ {
		if *(*byte)(unsafe.Pointer(x + i)) != 'X' {
			t.setErrno(errno.EINVAL)
			return -1
		}
	}

	fd, err := tempFile(template, x)
	if err != 0 {
		t.setErrno(err)
		return -1
	}

	return int32(fd)
}

// int mkstemp(char *template);
func Xmkstemp(t *TLS, template uintptr) int32 {
	return Xmkstemps(t, template, 0)
}

func newFtsent(t *TLS, info int, path string, stat *unix.Stat_t, err syscall.Errno) (r *fts.FTSENT) {
	var statp uintptr
	if stat != nil {
		statp = mustMalloc(t, types.Size_t(unsafe.Sizeof(unix.Stat_t{})))
		*(*unix.Stat_t)(unsafe.Pointer(statp)) = *stat
	}
	return &fts.FTSENT{
		Ffts_info:    uint16(info),
		Ffts_path:    mustCString(path),
		Ffts_pathlen: uint16(len(path)),
		Ffts_statp:   statp,
		Ffts_errno:   int32(err),
	}
}

func newCFtsent(t *TLS, info int, path string, stat *unix.Stat_t, err syscall.Errno) uintptr {
	p := mustCalloc(t, types.Size_t(unsafe.Sizeof(fts.FTSENT{})))
	*(*fts.FTSENT)(unsafe.Pointer(p)) = *newFtsent(t, info, path, stat, err)
	return p
}

func ftsentClose(t *TLS, p uintptr) {
	Xfree(t, (*fts.FTSENT)(unsafe.Pointer(p)).Ffts_path)
	Xfree(t, (*fts.FTSENT)(unsafe.Pointer(p)).Ffts_statp)
}

type ftstream struct {
	s []uintptr
	x int
}

func (f *ftstream) close(t *TLS) {
	for _, p := range f.s {
		ftsentClose(t, p)
		Xfree(t, p)
	}
	*f = ftstream{}
}

// FTS *fts_open(char * const *path_argv, int options, int (*compar)(const FTSENT **, const FTSENT **));
func Xfts_open(t *TLS, path_argv uintptr, options int32, compar uintptr) uintptr {
	f := &ftstream{}

	var walk func(string)
	walk = func(path string) {
		var fi os.FileInfo
		var err error
		switch {
		case options&fts.FTS_LOGICAL != 0:
			panic(todo(""))
		case options&fts.FTS_PHYSICAL != 0:
			fi, err = os.Lstat(path)
		default:
			panic(todo(""))
		}

		if err != nil {
			panic(todo(""))
		}

		var statp *unix.Stat_t
		if options&fts.FTS_NOSTAT == 0 {
			var stat unix.Stat_t
			if err := unix.Stat(path, &stat); err != nil {
				t.setErrno(err)
				f = nil
				return
			}

			statp = &stat
		}

	out:
		switch {
		case fi.IsDir():
			f.s = append(f.s, newCFtsent(t, fts.FTS_D, path, statp, 0))
			g, err := os.Open(path)
			switch x := err.(type) {
			case nil:
				// ok
			case *os.PathError:
				f.s = append(f.s, newCFtsent(t, fts.FTS_ERR, path, statp, x.Err.(syscall.Errno)))
				break out
			default:
				panic(todo("%q: %v %T", path, x, x))
			}

			names, err := g.Readdirnames(-1)
			g.Close()
			if err != nil {
				panic(todo(""))
			}

			for _, name := range names {
				walk(path + "/" + name)
				if f == nil {
					break out
				}
			}

			f.s = append(f.s, newCFtsent(t, fts.FTS_DP, path, statp, 0))
		default:
			f.s = append(f.s, newCFtsent(t, fts.FTS_F, path, statp, 0))
		}
	}

	for {
		p := *(*uintptr)(unsafe.Pointer(path_argv))
		if p == 0 {
			if f == nil {
				return 0
			}

			if compar != 0 {
				panic(todo(""))
			}

			return addObject(f)
		}

		walk(GoString(p))
		path_argv += unsafe.Sizeof(uintptr(0))
	}
}

// FTSENT *fts_read(FTS *ftsp);
func Xfts_read(t *TLS, ftsp uintptr) uintptr {
	f := getObject(ftsp).(*ftstream)
	if f.x == len(f.s) {
		t.setErrno(0)
		return 0
	}

	r := f.s[f.x]
	f.x++
	return r
}

// int fts_close(FTS *ftsp);
func Xfts_close(t *TLS, ftsp uintptr) int32 {
	getObject(ftsp).(*ftstream).close(t)
	removeObject(ftsp)
	return 0
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

// int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact);
func Xsigaction(t *TLS, signum int32, act, oldact uintptr) int32 {
	var kact, koldact uintptr
	if act != 0 {
		kact = mustMalloc(t, types.Size_t(unsafe.Sizeof(asmsignal.Sigaction{})))
		defer Xfree(t, kact)
		*(*asmsignal.Sigaction)(unsafe.Pointer(kact)) = asmsignal.Sigaction{
			Fsa_handler:  (*signal.Sigaction)(unsafe.Pointer(act)).F__sigaction_handler.Fsa_handler,
			Fsa_flags:    uint64((*signal.Sigaction)(unsafe.Pointer(act)).Fsa_flags),
			Fsa_restorer: (*signal.Sigaction)(unsafe.Pointer(act)).Fsa_restorer,
			Fsa_mask:     (*signal.Sigaction)(unsafe.Pointer(act)).Fsa_mask.F__val[0],
		}
	}
	if oldact != 0 {
		koldact = mustMalloc(t, types.Size_t(unsafe.Sizeof(asmsignal.Sigaction{})))
		defer Xfree(t, koldact)
	}
	if _, _, err := unix.Syscall6(unix.SYS_RT_SIGACTION, uintptr(signal.SIGABRT), kact, koldact, unsafe.Sizeof(asmsignal.Sigset_t(0)), 0, 0); err != 0 {
		t.setErrno(err)
		return -1
	}

	if oldact != 0 {
		*(*signal.Sigaction)(unsafe.Pointer(oldact)) = signal.Sigaction{
			F__sigaction_handler: struct{ Fsa_handler signal.X__sighandler_t }{Fsa_handler: (*asmsignal.Sigaction)(unsafe.Pointer(koldact)).Fsa_handler},
			Fsa_mask:             struct{ F__val [16]uint64 }{F__val: [16]uint64{(*asmsignal.Sigaction)(unsafe.Pointer(koldact)).Fsa_mask}},
			Fsa_flags:            int32((*asmsignal.Sigaction)(unsafe.Pointer(koldact)).Fsa_flags),
			Fsa_restorer:         (*asmsignal.Sigaction)(unsafe.Pointer(koldact)).Fsa_restorer,
		}
	}
	return 0
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

// speed_t cfgetospeed(const struct termios *termios_p);
func Xcfgetospeed(t *TLS, termios_p uintptr) termios.Speed_t {
	panic(todo(""))
}

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

// char *nl_langinfo(nl_item item);
func Xnl_langinfo(t *TLS, item langinfo.Nl_item) uintptr {
	panic(todo(""))
}

// FILE *popen(const char *command, const char *type);
func Xpopen(t *TLS, command, type1 uintptr) uintptr {
	panic(todo(""))
}

// char *realpath(const char *path, char *resolved_path);
func Xrealpath(t *TLS, path, resolved_path uintptr) uintptr {
	s, err := filepath.EvalSymlinks(GoString(path))
	if err != nil {
		if os.IsNotExist(err) {
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

// char *inet_ntoa(struct in_addr in);
func Xinet_ntoa(t *TLS, in1 in.In_addr) uintptr {
	panic(todo(""))
}

func X__ccgo_in6addr_anyp(t *TLS) uintptr {
	return uintptr(unsafe.Pointer(&in6_addr_any))
}

func Xabort(t *TLS) {
	p := mustMalloc(t, types.Size_t(unsafe.Sizeof(signal.Sigaction{})))
	*(*signal.Sigaction)(unsafe.Pointer(p)) = signal.Sigaction{
		F__sigaction_handler: struct{ Fsa_handler signal.X__sighandler_t }{Fsa_handler: signal.SIG_DFL},
	}
	Xsigaction(t, signal.SIGABRT, p, 0)
	Xfree(t, p)
	unix.Kill(unix.Getpid(), syscall.Signal(signal.SIGABRT))
	panic(todo("unrechable"))
}
