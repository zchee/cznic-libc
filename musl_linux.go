// Copyright Copyright © 2005-2020 Rich Felker, et al.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE-MUSL file.

// Modifications Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc/dirent"
	"modernc.org/libc/errno"
	"modernc.org/libc/fcntl"
	"modernc.org/libc/sys/types"
)

//	struct __dirstream
//	{
//		off_t tell;
//		int fd;
//		int buf_pos;
//		int buf_end;
//		volatile int lock[1];
//		/* Any changes to this struct must preserve the property:
//		 * offsetof(struct __dirent, buf) % sizeof(off_t) == 0 */
//		char buf[2048];
//	};
type __dirstream struct {
	tell    types.X__off64_t //TODO 32 bit
	fd      int32
	buf_pos int32
	buf_end int32
	lock    int32
	buf     [2048]byte
}

func init() {
	if unsafe.Offsetof(__dirstream{}.buf)%unsafe.Sizeof(types.X__off64_t(0)) != 0 { //TODO 32 bit
		panic(todo(""))
	}
}

// DIR *opendir(const char *name);
func Xopendir(t *TLS, name uintptr) uintptr {
	//	DIR *opendir(const char *name)
	//	{
	//		int fd;
	//		DIR *dir;
	//
	//		if ((fd = open(name, O_RDONLY|O_DIRECTORY|O_CLOEXEC)) < 0)
	//			return 0;
	//		if (!(dir = calloc(1, sizeof *dir))) {
	//			__syscall(SYS_close, fd);
	//			return 0;
	//		}
	//		dir->fd = fd;
	//		return dir;
	//	}
	fd, _, err := unix.Syscall(unix.SYS_OPEN, name, fcntl.O_RDONLY|fcntl.O_DIRECTORY|fcntl.O_CLOEXEC, 0)
	if fd < 0 {
		t.setErrno(err)
		return 0
	}

	dir := Xcalloc(t, 1, types.Size_t(unsafe.Sizeof(__dirstream{})))
	if dir == 0 {
		unix.Syscall(unix.SYS_CLOSE, fd, 0, 0)
		t.setErrno(errno.ENOMEM)
		return 0
	}

	(*__dirstream)(unsafe.Pointer(dir)).fd = int32(fd)
	return dir
}

// struct dirent *readdir(DIR *dirp);
func Xreaddir64(t *TLS, dirp uintptr) (r uintptr) {
	//	struct dirent *readdir(DIR *dir)
	//	{
	//		struct dirent *de;
	//
	//		if (dir->buf_pos >= dir->buf_end) {
	//			int len = __syscall(SYS_getdents, dir->fd, dir->buf, sizeof dir->buf);
	//			if (len <= 0) {
	//				if (len < 0 && len != -ENOENT) errno = -len;
	//				return 0;
	//			}
	//			dir->buf_end = len;
	//			dir->buf_pos = 0;
	//		}
	//		de = (void *)(dir->buf + dir->buf_pos);
	//		dir->buf_pos += de->d_reclen;
	//		dir->tell = de->d_off;
	//		return de;
	//	}
	if (*__dirstream)(unsafe.Pointer(dirp)).buf_pos >= (*__dirstream)(unsafe.Pointer(dirp)).buf_end {
		len, _, err := unix.Syscall(unix.SYS_GETDENTS64, uintptr((*__dirstream)(unsafe.Pointer(dirp)).fd), uintptr(unsafe.Pointer(dirp+unsafe.Offsetof(__dirstream{}.buf))), unsafe.Sizeof(__dirstream{}.buf)) //TODO 32 bit
		if err != 0 {
			t.setErrno(err)
			return 0
		}

		if len == 0 {
			return 0
		}

		(*__dirstream)(unsafe.Pointer(dirp)).buf_end = int32(len)
		(*__dirstream)(unsafe.Pointer(dirp)).buf_pos = 0
	}
	de := dirp + unsafe.Offsetof(__dirstream{}.buf) + uintptr((*__dirstream)(unsafe.Pointer(dirp)).buf_pos)
	(*__dirstream)(unsafe.Pointer(dirp)).buf_pos += int32((*dirent.Dirent)(unsafe.Pointer(de)).Fd_reclen)
	(*__dirstream)(unsafe.Pointer(dirp)).tell = (*dirent.Dirent)(unsafe.Pointer(de)).Fd_off
	return de
}

// int closedir(DIR *dirp);
func Xclosedir(t *TLS, dirp uintptr) int32 {
	//	int closedir(DIR *dir)
	//	{
	//		int ret = close(dir->fd);
	//		free(dir);
	//		return ret;
	//	}
	ret := Xclose(t, (*__dirstream)(unsafe.Pointer(dirp)).fd)
	Xfree(t, dirp)
	return ret
}
