// Copyright Copyright © 2005-2020 Rich Felker, et al.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE-MUSL file.

// Modifications Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package libc // import "modernc.org/libc"

import (
	//TODO "net"
	"unsafe"

	"golang.org/x/sys/unix"
	"modernc.org/libc/dirent"
	"modernc.org/libc/errno"
	"modernc.org/libc/fcntl"
	"modernc.org/libc/netdb"
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
	if err != 0 {
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

// int getaddrinfo(const char *restrict host, const char *restrict serv, const struct addrinfo *restrict hint, struct addrinfo **restrict res)
func getaddrinfo(t *TLS, host, serv, hint, res uintptr) int32 {
	if dmesgs {
		dmesg("%v: host %q serv %q, hint %#x, res %#x", origin(1), GoString(host), GoString(serv), hint, res)
	}

	//	struct service ports[MAXSERVS];
	//	struct address addrs[MAXADDRS];
	//	char canon[256], *outcanon;
	//	int nservs, naddrs, nais, canon_len, i, j, k;
	//	int family = AF_UNSPEC, flags = 0, proto = 0, socktype = 0;
	family := int32(netdb.AF_UNSPEC)
	var flags, proto, socktype int32
	//	struct aibuf *out;

	//	if (!host && !serv) return EAI_NONAME;
	if host == 0 && serv == 0 {
		return netdb.EAI_NONAME
	}

	//	if (hint) {
	if hint != 0 {
		//		family = hint->ai_family;
		family = (*netdb.Addrinfo)(unsafe.Pointer(hint)).Fai_family
		//		flags = hint->ai_flags;
		flags = (*netdb.Addrinfo)(unsafe.Pointer(hint)).Fai_flags
		//		proto = hint->ai_protocol;
		proto = (*netdb.Addrinfo)(unsafe.Pointer(hint)).Fai_protocol
		//		socktype = hint->ai_socktype;
		socktype = (*netdb.Addrinfo)(unsafe.Pointer(hint)).Fai_socktype

		//		const int mask = AI_PASSIVE | AI_CANONNAME | AI_NUMERICHOST |
		//			AI_V4MAPPED | AI_ALL | AI_ADDRCONFIG | AI_NUMERICSERV;
		mask := int32(netdb.AI_PASSIVE | netdb.AI_CANONNAME | netdb.AI_NUMERICHOST | netdb.AI_V4MAPPED | netdb.AI_ALL | netdb.AI_ADDRCONFIG | netdb.AI_NUMERICSERV)
		//		if ((flags & mask) != flags)
		//			return EAI_BADFLAGS;
		if flags&mask != flags {
			return netdb.EAI_BADFLAGS
		}

		//		switch (family) {
		//		case AF_INET:
		//		case AF_INET6:
		//		case AF_UNSPEC:
		//			break;
		//		default:
		//			return EAI_FAMILY;
		//		}
		switch family {
		case netdb.AF_INET, netdb.AF_INET6, netdb.AF_UNSPEC:
		// nop
		default:
			return netdb.EAI_FAMILY
		}
	}
	//	}

	//	if (flags & AI_ADDRCONFIG) {
	if flags&netdb.AI_ADDRCONFIG != 0 {
		panic(todo(""))
		//		/* Define the "an address is configured" condition for address
		//		 * families via ability to create a socket for the family plus
		//		 * routability of the loopback address for the family. */
		//		static const struct sockaddr_in lo4 = {
		//			.sin_family = AF_INET, .sin_port = 65535,
		//			.sin_addr.s_addr = __BYTE_ORDER == __BIG_ENDIAN
		//				? 0x7f000001 : 0x0100007f
		//		};
		//		static const struct sockaddr_in6 lo6 = {
		//			.sin6_family = AF_INET6, .sin6_port = 65535,
		//			.sin6_addr = IN6ADDR_LOOPBACK_INIT
		//		};
		//		int tf[2] = { AF_INET, AF_INET6 };
		//		const void *ta[2] = { &lo4, &lo6 };
		//		socklen_t tl[2] = { sizeof lo4, sizeof lo6 };
		//		for (i=0; i<2; i++) {
		//			if (family==tf[1-i]) continue;
		//			int s = socket(tf[i], SOCK_CLOEXEC|SOCK_DGRAM,
		//				IPPROTO_UDP);
		//			if (s>=0) {
		//				int cs;
		//				pthread_setcancelstate(
		//					PTHREAD_CANCEL_DISABLE, &cs);
		//				int r = connect(s, ta[i], tl[i]);
		//				pthread_setcancelstate(cs, 0);
		//				close(s);
		//				if (!r) continue;
		//			}
		//			switch (errno) {
		//			case EADDRNOTAVAIL:
		//			case EAFNOSUPPORT:
		//			case EHOSTUNREACH:
		//			case ENETDOWN:
		//			case ENETUNREACH:
		//				break;
		//			default:
		//				return EAI_SYSTEM;
		//			}
		//			if (family == tf[i]) return EAI_NONAME;
		//			family = tf[1-i];
		//		}
	}
	//	}

	//	nservs = __lookup_serv(ports, serv, proto, socktype, flags);
	ports, nservs := __lookup_serv(t, serv, proto, socktype, flags)
	//	if (nservs < 0) return nservs;
	if nservs < 0 {
		return nservs
	}

	//	naddrs = __lookup_name(addrs, canon, host, family, flags);
	addrs, canon, naddrs := __lookup_name(t, host, family, flags)
	//	if (naddrs < 0) return naddrs;
	if naddrs < 0 {
		return naddrs
	}

	//	nais = nservs * naddrs;
	nais := nservs * naddrs
	//	canon_len = strlen(canon);
	//	out = calloc(1, nais * sizeof(*out) + canon_len + 1);
	out := Xcalloc(t, types.Size_t(nais), types.Size_t(unsafe.Sizeof(netdb.Addrinfo{})))
	//	if (!out) return EAI_MEMORY;
	if out == 0 {
		return netdb.EAI_MEMORY
	}

	//	if (canon_len) {
	//		outcanon = (void *)&out[nais];
	//		memcpy(outcanon, canon, canon_len+1);
	//	} else {
	//		outcanon = 0;
	//	}

	var k, i int32
	//	for (k=i=0; i<naddrs; i++) for (j=0; j<nservs; j++, k++) {
	for ; i < naddrs; i++ {
		var prevpk uintptr
		for j := int32(0); j < nservs; j, k = j+1, k+1 {
			//		out[k].slot = k;
			//		out[k].ai = (struct addrinfo){
			//			.ai_family = addrs[i].family,
			//			.ai_socktype = ports[j].socktype,
			//			.ai_protocol = ports[j].proto,
			//			.ai_addrlen = addrs[i].family == AF_INET
			//				? sizeof(struct sockaddr_in)
			//				: sizeof(struct sockaddr_in6),
			//			.ai_addr = (void *)&out[k].sa,
			//			.ai_canonname = outcanon };
			var addrlen netdb.Socklen_t
			switch {
			case addrs[i].family == netdb.AF_INET:
				addrlen = netdb.Socklen_t(unsafe.Sizeof(netdb.Sockaddr_in{}))
			default:
				addrlen = netdb.Socklen_t(unsafe.Sizeof(netdb.Sockaddr_in6{}))
			}
			sa := Xmalloc(t, types.Size_t(addrlen))
			if sa == 0 {
				Xfree(t, out)
				return netdb.EAI_MEMORY
			}

			var pcanon uintptr
			if k == 0 && canon != "" {
				var err error
				if pcanon, err = CString(canon); err != nil {
					Xfree(t, out)
					Xfree(t, sa)
					return netdb.EAI_MEMORY
				}
			}
			pk := out + uintptr(k)*unsafe.Sizeof(netdb.Addrinfo{})
			*(*netdb.Addrinfo)(unsafe.Pointer(pk)) = netdb.Addrinfo{
				Fai_family:    addrs[i].family,
				Fai_socktype:  int32(ports[j].socktype),
				Fai_protocol:  int32(ports[j].proto),
				Fai_addrlen:   addrlen,
				Fai_addr:      sa,
				Fai_canonname: pcanon,
			}
			//		if (k) out[k-1].ai.ai_next = &out[k].ai;
			if prevpk != 0 {
				*&(*netdb.Addrinfo)(unsafe.Pointer(prevpk)).Fai_next = pk
			}
			prevpk = pk
			//		switch (addrs[i].family) {
			switch addrs[i].family {
			//		case AF_INET:
			case netdb.AF_INET:
				//			out[k].sa.sin.sin_family = AF_INET;
				(*netdb.Sockaddr_in)(unsafe.Pointer(sa)).Fsin_family = netdb.AF_INET
				//			out[k].sa.sin.sin_port = htons(ports[j].port);
				(*netdb.Sockaddr_in)(unsafe.Pointer(sa)).Fsin_port = Xhtons(t, ports[j].port)
				//			memcpy(&out[k].sa.sin.sin_addr, &addrs[i].addr, 4);
				(*netdb.Sockaddr_in)(unsafe.Pointer(sa)).Fsin_addr.Fs_addr = *(*uint32)(unsafe.Pointer(&addrs[i].addr))
				//			break;
				//		case AF_INET6:
			case netdb.AF_INET6:
				panic(todo(""))
				//			out[k].sa.sin6.sin6_family = AF_INET6;
				//			out[k].sa.sin6.sin6_port = htons(ports[j].port);
				//			out[k].sa.sin6.sin6_scope_id = addrs[i].scopeid;
				//			memcpy(&out[k].sa.sin6.sin6_addr, &addrs[i].addr, 16);
				//			break;
			}
			//		}
		}
	}
	//	}
	//	out[0].ref = nais;
	//	*res = &out->ai;
	*(*uintptr)(unsafe.Pointer(res)) = out
	return 0
}

// void freeaddrinfo(struct addrinfo *res);
func freeaddrinfo(t *TLS, res uintptr) {
	panic(todo(""))
	//TODO
}

//	}

//	struct service {
//	        uint16_t port;
//	        unsigned char proto, socktype;
//	};
type struct_service struct {
	port     uint16
	proto    byte
	socktype byte
}

var __lookup_serv_init_z = [1]byte{0}

// int __lookup_serv(struct service buf[static MAXSERVS], const char *name, int proto, int socktype, int flags)
func __lookup_serv(t *TLS, name uintptr, proto, socktype, flags int32) (buf []struct_service, _ int32) {
	if dmesgs {
		dmesg("%v: %q %v, %v, %#x", origin(1), GoString(name), proto, socktype, flags)
	}
	pz := t.Alloc(int(unsafe.Sizeof(uintptr(0))))
	defer t.Free(int(unsafe.Sizeof(uintptr(0))))
	//	{
	//		char line[128];
	//		int cnt = 0;
	//		char *p, *z = "";
	z := uintptr(unsafe.Pointer(&__lookup_serv_init_z))
	*(*uintptr)(unsafe.Pointer(pz)) = z
	//		unsigned long port = 0;
	var port ulong
	//
	//		switch (socktype) {
	switch socktype {
	//		case SOCK_STREAM:
	case netdb.SOCK_STREAM:
		//			switch (proto) {
		switch proto {
		//			case 0:
		case 0:
			//				proto = IPPROTO_TCP;
			proto = netdb.IPPROTO_TCP
			//			case IPPROTO_TCP:
		case netdb.IPPROTO_TCP:
			//				break;
			// ok nop
			//			default:
		default:
			//				return EAI_SERVICE;
			return nil, netdb.EAI_SERVICE
		}
		//			}
		//			break;
		//		case SOCK_DGRAM:
	case netdb.SOCK_DGRAM:
		panic(todo(""))
		//			switch (proto) {
		//			case 0:
		//				proto = IPPROTO_UDP;
		//			case IPPROTO_UDP:
		//				break;
		//			default:
		//				return EAI_SERVICE;
		//			}
		//		case 0:
	case 0:
		//			break;
		// ok nop
		//		default:
	default:
		panic(todo(""))
		//			if (name) return EAI_SERVICE;
		//			buf[0].port = 0;
		//			buf[0].proto = proto;
		//			buf[0].socktype = socktype;
		//			return 1;
	}
	//		}

	//		if (name) {
	if name != 0 {
		//			if (!*name) return EAI_SERVICE;
		if *(*byte)(unsafe.Pointer(name)) == 0 {
			return nil, netdb.EAI_SERVICE
		}

		//			port = strtoul(name, &z, 10);
		port = Xstrtoul(t, name, pz, 10)
		z = *(*uintptr)(unsafe.Pointer(pz))
	}
	//		}

	//		if (!*z) {
	if *(*byte)(unsafe.Pointer(z)) == 0 {
		//			if (port > 65535) return EAI_SERVICE;
		if port > 65536 {
			return nil, netdb.EAI_SERVICE
		}

		//			if (proto != IPPROTO_UDP) {
		if proto != netdb.IPPROTO_UDP {
			//				buf[cnt].port = port;
			//				buf[cnt].socktype = SOCK_STREAM;
			//				buf[cnt++].proto = IPPROTO_TCP;
			buf = append(buf, struct_service{port: uint16(port), socktype: netdb.SOCK_STREAM, proto: netdb.IPPROTO_TCP})
		}
		//			}
		//			if (proto != IPPROTO_TCP) {
		if proto != netdb.IPPROTO_TCP {
			//				buf[cnt].port = port;
			//				buf[cnt].socktype = SOCK_DGRAM;
			panic(todo(""))
			//				buf[cnt++].proto = IPPROTO_UDP;
		}
		//			}
		//			return cnt;
		return buf, int32(len(buf))
	}
	//		}

	//		if (flags & AI_NUMERICSERV) return EAI_NONAME;
	if flags&netdb.AI_NUMERICSERV != 0 {
		return nil, netdb.EAI_NONAME
	}

	sname := GoString(name)
	panic(todo("%q %v %v", sname, proto, port))
	//		size_t l = strlen(name);
	//
	//		unsigned char _buf[1032];
	//		FILE _f, *f = __fopen_rb_ca("/etc/services", &_f, _buf, sizeof _buf);
	//		if (!f) switch (errno) {
	//		case ENOENT:
	//		case ENOTDIR:
	//		case EACCES:
	//			return EAI_SERVICE;
	//		default:
	//			return EAI_SYSTEM;
	//		}
	//
	//		while (fgets(line, sizeof line, f) && cnt < MAXSERVS) {
	//			if ((p=strchr(line, '#'))) *p++='\n', *p=0;
	//
	//			/* Find service name */
	//			for(p=line; (p=strstr(p, name)); p++) {
	//				if (p>line && !isspace(p[-1])) continue;
	//				if (p[l] && !isspace(p[l])) continue;
	//				break;
	//			}
	//			if (!p) continue;
	//
	//			/* Skip past canonical name at beginning of line */
	//			for (p=line; *p && !isspace(*p); p++);
	//
	//			port = strtoul(p, &z, 10);
	//			if (port > 65535 || z==p) continue;
	//			if (!strncmp(z, "/udp", 4)) {
	//				if (proto == IPPROTO_TCP) continue;
	//				buf[cnt].port = port;
	//				buf[cnt].socktype = SOCK_DGRAM;
	//				buf[cnt++].proto = IPPROTO_UDP;
	//			}
	//			if (!strncmp(z, "/tcp", 4)) {
	//				if (proto == IPPROTO_UDP) continue;
	//				buf[cnt].port = port;
	//				buf[cnt].socktype = SOCK_STREAM;
	//				buf[cnt++].proto = IPPROTO_TCP;
	//			}
	//		}
	//		__fclose_ca(f);
	//		return cnt > 0 ? cnt : EAI_SERVICE;
	panic(todo(""))
}

//	}

//	struct address {
//		int family;
//		unsigned scopeid;
//		uint8_t addr[16];
//		int sortkey;
//	};
type struct_address struct {
	family  int32
	scopeid uint32
	addr    [16]byte
	sortkey int32
}

//	int __lookup_name(struct address buf[static MAXADDRS], char canon[static 256], const char *name, int family, int flags)
func __lookup_name(t *TLS, name uintptr, family, flags int32) (buf []struct_address, canon string, _ int32) {
	if dmesgs {
		dmesg("%v: %q %v, %#x", origin(1), GoString(name), family, flags)
	}
	//	{
	//		int cnt = 0, i, j;
	//
	//		*canon = 0;
	var sname string
	//		if (name) {
	if name != 0 {
		sname = GoString(name)
		//			/* reject empty name and check len so it fits into temp bufs */
		//			size_t l = strnlen(name, 255);
		//			if (l-1 >= 254)
		//				return EAI_NONAME;
		//			memcpy(canon, name, l+1);
		canon = sname
	}
	//		}

	//		/* Procedurally, a request for v6 addresses with the v4-mapped
	//		 * flag set is like a request for unspecified family, followed
	//		 * by filtering of the results. */
	//		if (flags & AI_V4MAPPED) {
	if flags&netdb.AI_V4MAPPED != 0 {
		panic(todo(""))
		//			if (family == AF_INET6) family = AF_UNSPEC;
		//			else flags -= AI_V4MAPPED;
	}
	//		}

	//		/* Try each backend until there's at least one result. */
	//		cnt = name_from_null(buf, name, family, flags);
	buf = name_from_null(t, sname, family, flags)
	//		if (!cnt) cnt = name_from_numeric(buf, name, family);
	var cnt int32
	if len(buf) == 0 {
		buf, cnt = name_from_numeric(t, sname, family)
	}
	//		if (!cnt && !(flags & AI_NUMERICHOST)) {
	if cnt == 0 && flags&netdb.AI_NUMERICHOST == 0 {
		panic(todo(""))
		//			cnt = name_from_hosts(buf, canon, name, family);
		//			if (!cnt) cnt = name_from_dns_search(buf, canon, name, family);
	}
	//		}

	//		if (cnt<=0) return cnt ? cnt : EAI_NONAME;
	if cnt <= 0 {
		panic(todo(""))
	}
	//
	//		/* Filter/transform results for v4-mapped lookup, if requested. */
	//		if (flags & AI_V4MAPPED) {
	if flags&netdb.AI_V4MAPPED != 0 {
		panic(todo(""))
		//			if (!(flags & AI_ALL)) {
		//				/* If any v6 results exist, remove v4 results. */
		//				for (i=0; i<cnt && buf[i].family != AF_INET6; i++);
		//				if (i<cnt) {
		//					for (j=0; i<cnt; i++) {
		//						if (buf[i].family == AF_INET6)
		//							buf[j++] = buf[i];
		//					}
		//					cnt = i = j;
		//				}
		//			}
		//			/* Translate any remaining v4 results to v6 */
		//			for (i=0; i<cnt; i++) {
		//				if (buf[i].family != AF_INET) continue;
		//				memcpy(buf[i].addr+12, buf[i].addr, 4);
		//				memcpy(buf[i].addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
		//				buf[i].family = AF_INET6;
		//			}
	}
	//		}

	//		/* No further processing is needed if there are fewer than 2
	//		 * results or if there are only IPv4 results. */
	//		if (cnt<2 || family==AF_INET) return cnt;
	if cnt < 2 && family == netdb.AF_INET {
		return buf, canon, cnt
	}

	//		for (i=0; i<cnt; i++) if (buf[i].family != AF_INET) break;
	var i int32
	for i = 0; i < cnt; i++ {
		if buf[i].family != netdb.AF_INET {
			break
		}
	}
	//		if (i==cnt) return cnt;
	if i == cnt {
		return buf, canon, cnt
	}

	panic(todo(""))
	//		int cs;
	//		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cs);
	//
	//		/* The following implements a subset of RFC 3484/6724 destination
	//		 * address selection by generating a single 31-bit sort key for
	//		 * each address. Rules 3, 4, and 7 are omitted for having
	//		 * excessive runtime and code size cost and dubious benefit.
	//		 * So far the label/precedence table cannot be customized. */
	//		for (i=0; i<cnt; i++) {
	//			int family = buf[i].family;
	//			int key = 0;
	//			struct sockaddr_in6 sa6 = { 0 }, da6 = {
	//				.sin6_family = AF_INET6,
	//				.sin6_scope_id = buf[i].scopeid,
	//				.sin6_port = 65535
	//			};
	//			struct sockaddr_in sa4 = { 0 }, da4 = {
	//				.sin_family = AF_INET,
	//				.sin_port = 65535
	//			};
	//			void *sa, *da;
	//			socklen_t salen, dalen;
	//			if (family == AF_INET6) {
	//				memcpy(da6.sin6_addr.s6_addr, buf[i].addr, 16);
	//				da = &da6; dalen = sizeof da6;
	//				sa = &sa6; salen = sizeof sa6;
	//			} else {
	//				memcpy(sa6.sin6_addr.s6_addr,
	//					"\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
	//				memcpy(da6.sin6_addr.s6_addr+12, buf[i].addr, 4);
	//				memcpy(da6.sin6_addr.s6_addr,
	//					"\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
	//				memcpy(da6.sin6_addr.s6_addr+12, buf[i].addr, 4);
	//				memcpy(&da4.sin_addr, buf[i].addr, 4);
	//				da = &da4; dalen = sizeof da4;
	//				sa = &sa4; salen = sizeof sa4;
	//			}
	//			const struct policy *dpolicy = policyof(&da6.sin6_addr);
	//			int dscope = scopeof(&da6.sin6_addr);
	//			int dlabel = dpolicy->label;
	//			int dprec = dpolicy->prec;
	//			int prefixlen = 0;
	//			int fd = socket(family, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP);
	//			if (fd >= 0) {
	//				if (!connect(fd, da, dalen)) {
	//					key |= DAS_USABLE;
	//					if (!getsockname(fd, sa, &salen)) {
	//						if (family == AF_INET) memcpy(
	//							sa6.sin6_addr.s6_addr+12,
	//							&sa4.sin_addr, 4);
	//						if (dscope == scopeof(&sa6.sin6_addr))
	//							key |= DAS_MATCHINGSCOPE;
	//						if (dlabel == labelof(&sa6.sin6_addr))
	//							key |= DAS_MATCHINGLABEL;
	//						prefixlen = prefixmatch(&sa6.sin6_addr,
	//							&da6.sin6_addr);
	//					}
	//				}
	//				close(fd);
	//			}
	//			key |= dprec << DAS_PREC_SHIFT;
	//			key |= (15-dscope) << DAS_SCOPE_SHIFT;
	//			key |= prefixlen << DAS_PREFIX_SHIFT;
	//			key |= (MAXADDRS-i) << DAS_ORDER_SHIFT;
	//			buf[i].sortkey = key;
	//		}
	//		qsort(buf, cnt, sizeof *buf, addrcmp);
	//
	//		pthread_setcancelstate(cs, 0);
	//
	//		return cnt;
	panic(todo("%q %q %#x, %#x", sname, canon, family, flags))
}

//	}

//	static int name_from_numeric(struct address buf[static 1], const char *name, int family)
//	{
//		return __lookup_ipliteral(buf, name, family);
//	}
func name_from_numeric(t *TLS, name string, family int32) ([]struct_address, int32) {
	return __lookup_ipliteral(t, name, family)
}

//	int __lookup_ipliteral(struct address buf[static 1], const char *name, int family)
func __lookup_ipliteral(t *TLS, name string, family int32) ([]struct_address, int32) {
	if dmesgs {
		dmesg("%v: %q %v", origin(1), name, family)
	}
	//	{
	//		struct in_addr a4;
	//		struct in6_addr a6;
	//		if (__inet_aton(name, &a4) > 0) {
	panic(todo(""))
	//		if ip := net.ParseIP(name); ip != nil && ip.To4() != nil {
	//			//			if (family == AF_INET6) /* wrong family */
	//			//				return EAI_NONAME;
	//			if family == netdb.AF_INET6 {
	//				return nil, netdb.EAI_NONAME
	//			}
	//
	//			//			memcpy(&buf[0].addr, &a4, sizeof a4);
	//			//			buf[0].family = AF_INET;
	//			//			buf[0].scopeid = 0;
	//			//			return 1;
	//			var addr [16]byte
	//			copy(addr[:], ip)
	//			return []struct_address{{
	//				addr:    addr,
	//				family:  netdb.AF_INET,
	//				scopeid: 0,
	//			}}, 1
	//		}
	//		//		}
	//
	//		panic(todo("%q %#x", name, family))
	//		//		char tmp[64];
	//		//		char *p = strchr(name, '%'), *z;
	//		//		unsigned long long scopeid = 0;
	//		//		if (p && p-name < 64) {
	//		//			memcpy(tmp, name, p-name);
	//		//			tmp[p-name] = 0;
	//		//			name = tmp;
	//		//		}
	//		//
	//		//		if (inet_pton(AF_INET6, name, &a6) <= 0)
	//		//			return 0;
	//		//		if (family == AF_INET) /* wrong family */
	//		//			return EAI_NONAME;
	//		//
	//		//		memcpy(&buf[0].addr, &a6, sizeof a6);
	//		//		buf[0].family = AF_INET6;
	//		//		if (p) {
	//		//			if (isdigit(*++p)) scopeid = strtoull(p, &z, 10);
	//		//			else z = p-1;
	//		//			if (*z) {
	//		//				if (!IN6_IS_ADDR_LINKLOCAL(&a6) &&
	//		//				    !IN6_IS_ADDR_MC_LINKLOCAL(&a6))
	//		//					return EAI_NONAME;
	//		//				scopeid = if_nametoindex(p);
	//		//				if (!scopeid) return EAI_NONAME;
	//		//			}
	//		//			if (scopeid > UINT_MAX) return EAI_NONAME;
	//		//		}
	//		//		buf[0].scopeid = scopeid;
	//		//		return 1;
	//		panic(todo("%q %#x", name, family))
}

//	}

//	static int name_from_null(struct address buf[static 2], const char *name, int family, int flags)
func name_from_null(t *TLS, name string, family, flags int32) (buf []struct_address) {
	if dmesgs {
		dmesg("%v: %q %v %#x", origin(1), name, family, flags)
	}
	//	{
	//		int cnt = 0;
	//		if (name) return 0;
	if name != "" {
		return nil
	}

	//		if (flags & AI_PASSIVE) {
	if flags&netdb.AI_PASSIVE != 0 {
		//			if (family != AF_INET6)
		//				buf[cnt++] = (struct address){ .family = AF_INET };
		if family != netdb.AF_INET6 {
			buf = append(buf, struct_address{family: netdb.AF_INET})
		}
		//			if (family != AF_INET)
		//				buf[cnt++] = (struct address){ .family = AF_INET6 };
		if family != netdb.AF_INET {
			buf = append(buf, struct_address{family: netdb.AF_INET6})
		}
	} else {
		panic(todo(""))
		//		} else {
		//			if (family != AF_INET6)
		//				buf[cnt++] = (struct address){ .family = AF_INET, .addr = { 127,0,0,1 } };
		//			if (family != AF_INET)
		//				buf[cnt++] = (struct address){ .family = AF_INET6, .addr = { [15] = 1 } };
	}
	//		}
	//		return cnt;
	return buf
	//	}
}
