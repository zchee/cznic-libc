// Code generated by 'ccgo termios/gen.c -D__signed__=signed -D__attribute__(x)= -ccgo-crt-import-path "" -ccgo-export-defines "" -ccgo-export-enums "" -ccgo-export-externs X -ccgo-export-fields F -ccgo-export-structs "" -ccgo-export-typedefs "" -ccgo-header -ccgo-long-double-is-double -ccgo-pkgname termios -o termios/termios_linux_386.go', DO NOT EDIT.

package termios

import (
	"math"
	"reflect"
	"unsafe"
)

var _ = math.Pi
var _ reflect.Kind
var _ unsafe.Pointer

const (
	B0                             = 0000000
	B1000000                       = 0010010
	B110                           = 0000003
	B115200                        = 0010002
	B1152000                       = 0010011
	B1200                          = 0000011
	B134                           = 0000004
	B150                           = 0000005
	B1500000                       = 0010012
	B1800                          = 0000012
	B19200                         = 0000016
	B200                           = 0000006
	B2000000                       = 0010013
	B230400                        = 0010003
	B2400                          = 0000013
	B2500000                       = 0010014
	B300                           = 0000007
	B3000000                       = 0010015
	B3500000                       = 0010016
	B38400                         = 0000017
	B4000000                       = 0010017
	B460800                        = 0010004
	B4800                          = 0000014
	B50                            = 0000001
	B500000                        = 0010005
	B57600                         = 0010001
	B576000                        = 0010006
	B600                           = 0000010
	B75                            = 0000002
	B921600                        = 0010007
	B9600                          = 0000015
	BRKINT                         = 0000002
	BS0                            = 0000000
	BS1                            = 0020000
	BSDLY                          = 0020000
	CBAUD                          = 0010017
	CBAUDEX                        = 0010000
	CBRK                           = 0
	CDISCARD                       = 15
	CDSUSP                         = 25
	CEOF                           = 4
	CEOL                           = 0
	CEOT                           = 4
	CERASE                         = 0177
	CFLUSH                         = 15
	CIBAUD                         = 002003600000
	CINTR                          = 3
	CKILL                          = 21
	CLNEXT                         = 22
	CLOCAL                         = 0004000
	CMIN                           = 1
	CMSPAR                         = 010000000000
	CQUIT                          = 034
	CR0                            = 0000000
	CR1                            = 0001000
	CR2                            = 0002000
	CR3                            = 0003000
	CRDLY                          = 0003000
	CREAD                          = 0000200
	CREPRINT                       = 18
	CRPRNT                         = 18
	CRTSCTS                        = 020000000000
	CS5                            = 0000000
	CS6                            = 0000020
	CS7                            = 0000040
	CS8                            = 0000060
	CSIZE                          = 0000060
	CSTART                         = 17
	CSTATUS                        = 0
	CSTOP                          = 19
	CSTOPB                         = 0000100
	CSUSP                          = 26
	CTIME                          = 0
	CWERASE                        = 23
	ECHO                           = 0000010
	ECHOCTL                        = 0001000
	ECHOE                          = 0000020
	ECHOK                          = 0000040
	ECHOKE                         = 0004000
	ECHONL                         = 0000100
	ECHOPRT                        = 0002000
	EXTA                           = 14
	EXTB                           = 15
	EXTPROC                        = 0200000
	FF0                            = 0000000
	FF1                            = 0100000
	FFDLY                          = 0100000
	FLUSHO                         = 0010000
	HUPCL                          = 0002000
	ICANON                         = 0000002
	ICRNL                          = 0000400
	IEXTEN                         = 0100000
	IGNBRK                         = 0000001
	IGNCR                          = 0000200
	IGNPAR                         = 0000004
	IMAXBEL                        = 0020000
	INLCR                          = 0000100
	INPCK                          = 0000020
	ISIG                           = 0000001
	ISTRIP                         = 0000040
	IUCLC                          = 0001000
	IUTF8                          = 0040000
	IXANY                          = 0004000
	IXOFF                          = 0010000
	IXON                           = 0002000
	NCCS                           = 32
	NL0                            = 0000000
	NL1                            = 0000400
	NLDLY                          = 0000400
	NOFLSH                         = 0000200
	OCRNL                          = 0000010
	OFDEL                          = 0000200
	OFILL                          = 0000100
	OLCUC                          = 0000002
	ONLCR                          = 0000004
	ONLRET                         = 0000040
	ONOCR                          = 0000020
	OPOST                          = 0000001
	PARENB                         = 0000400
	PARMRK                         = 0000010
	PARODD                         = 0001000
	PENDIN                         = 0040000
	TAB0                           = 0000000
	TAB1                           = 0004000
	TAB2                           = 0010000
	TAB3                           = 0014000
	TABDLY                         = 0014000
	TCIFLUSH                       = 0
	TCIOFF                         = 2
	TCIOFLUSH                      = 2
	TCION                          = 3
	TCOFLUSH                       = 1
	TCOOFF                         = 0
	TCOON                          = 1
	TCSADRAIN                      = 1
	TCSAFLUSH                      = 2
	TCSANOW                        = 0
	TOSTOP                         = 0000400
	TTYDEF_CFLAG                   = 1440
	TTYDEF_IFLAG                   = 11554
	TTYDEF_LFLAG                   = 35355
	TTYDEF_OFLAG                   = 6149
	TTYDEF_SPEED                   = 13
	VDISCARD                       = 13
	VEOF                           = 4
	VEOL                           = 11
	VEOL2                          = 16
	VERASE                         = 2
	VINTR                          = 0
	VKILL                          = 3
	VLNEXT                         = 15
	VMIN                           = 6
	VQUIT                          = 1
	VREPRINT                       = 12
	VSTART                         = 8
	VSTOP                          = 9
	VSUSP                          = 10
	VSWTC                          = 7
	VT0                            = 0000000
	VT1                            = 0040000
	VTDLY                          = 0040000
	VTIME                          = 5
	VWERASE                        = 14
	XCASE                          = 0000004
	XTABS                          = 0014000
	X_ATFILE_SOURCE                = 1
	X_BITS_TYPESIZES_H             = 1
	X_BITS_TYPES_H                 = 1
	X_DEFAULT_SOURCE               = 1
	X_FEATURES_H                   = 1
	X_FILE_OFFSET_BITS             = 64
	X_HAVE_STRUCT_TERMIOS_C_ISPEED = 1
	X_HAVE_STRUCT_TERMIOS_C_OSPEED = 1
	X_POSIX_C_SOURCE               = 200809
	X_POSIX_SOURCE                 = 1
	X_STDC_PREDEF_H                = 1
	X_SYS_CDEFS_H                  = 1
	X_SYS_TTYDEFAULTS_H_           = 0
	X_TERMIOS_H                    = 1
	I386                           = 1
	Linux                          = 1
	Unix                           = 1
)

type Ptrdiff_t = int32 /* <builtin>:3:26 */

type Size_t = uint32 /* <builtin>:9:23 */

type Wchar_t = int32 /* <builtin>:15:24 */

type X__builtin_va_list = uintptr /* <builtin>:34:14 */
type X__float128 = float64        /* <builtin>:35:21 */

// Copyright (C) 1991-2018 Free Software Foundation, Inc.
//   This file is part of the GNU C Library.
//
//   The GNU C Library is free software; you can redistribute it and/or
//   modify it under the terms of the GNU Lesser General Public
//   License as published by the Free Software Foundation; either
//   version 2.1 of the License, or (at your option) any later version.
//
//   The GNU C Library is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   Lesser General Public License for more details.
//
//   You should have received a copy of the GNU Lesser General Public
//   License along with the GNU C Library; if not, see
//   <http://www.gnu.org/licenses/>.

//	POSIX Standard: 7.1-2 General Terminal Interface	<termios.h>

// Copyright (C) 1991-2018 Free Software Foundation, Inc.
//   This file is part of the GNU C Library.
//
//   The GNU C Library is free software; you can redistribute it and/or
//   modify it under the terms of the GNU Lesser General Public
//   License as published by the Free Software Foundation; either
//   version 2.1 of the License, or (at your option) any later version.
//
//   The GNU C Library is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   Lesser General Public License for more details.
//
//   You should have received a copy of the GNU Lesser General Public
//   License along with the GNU C Library; if not, see
//   <http://www.gnu.org/licenses/>.

// These are defined by the user (or the compiler)
//   to specify the desired environment:
//
//   __STRICT_ANSI__	ISO Standard C.
//   _ISOC99_SOURCE	Extensions to ISO C89 from ISO C99.
//   _ISOC11_SOURCE	Extensions to ISO C99 from ISO C11.
//   __STDC_WANT_LIB_EXT2__
//			Extensions to ISO C99 from TR 27431-2:2010.
//   __STDC_WANT_IEC_60559_BFP_EXT__
//			Extensions to ISO C11 from TS 18661-1:2014.
//   __STDC_WANT_IEC_60559_FUNCS_EXT__
//			Extensions to ISO C11 from TS 18661-4:2015.
//   __STDC_WANT_IEC_60559_TYPES_EXT__
//			Extensions to ISO C11 from TS 18661-3:2015.
//
//   _POSIX_SOURCE	IEEE Std 1003.1.
//   _POSIX_C_SOURCE	If ==1, like _POSIX_SOURCE; if >=2 add IEEE Std 1003.2;
//			if >=199309L, add IEEE Std 1003.1b-1993;
//			if >=199506L, add IEEE Std 1003.1c-1995;
//			if >=200112L, all of IEEE 1003.1-2004
//			if >=200809L, all of IEEE 1003.1-2008
//   _XOPEN_SOURCE	Includes POSIX and XPG things.  Set to 500 if
//			Single Unix conformance is wanted, to 600 for the
//			sixth revision, to 700 for the seventh revision.
//   _XOPEN_SOURCE_EXTENDED XPG things and X/Open Unix extensions.
//   _LARGEFILE_SOURCE	Some more functions for correct standard I/O.
//   _LARGEFILE64_SOURCE	Additional functionality from LFS for large files.
//   _FILE_OFFSET_BITS=N	Select default filesystem interface.
//   _ATFILE_SOURCE	Additional *at interfaces.
//   _GNU_SOURCE		All of the above, plus GNU extensions.
//   _DEFAULT_SOURCE	The default set of features (taking precedence over
//			__STRICT_ANSI__).
//
//   _FORTIFY_SOURCE	Add security hardening to many library functions.
//			Set to 1 or 2; 2 performs stricter checks than 1.
//
//   _REENTRANT, _THREAD_SAFE
//			Obsolete; equivalent to _POSIX_C_SOURCE=199506L.
//
//   The `-ansi' switch to the GNU C compiler, and standards conformance
//   options such as `-std=c99', define __STRICT_ANSI__.  If none of
//   these are defined, or if _DEFAULT_SOURCE is defined, the default is
//   to have _POSIX_SOURCE set to one and _POSIX_C_SOURCE set to
//   200809L, as well as enabling miscellaneous functions from BSD and
//   SVID.  If more than one of these are defined, they accumulate.  For
//   example __STRICT_ANSI__, _POSIX_SOURCE and _POSIX_C_SOURCE together
//   give you ISO C, 1003.1, and 1003.2, but nothing else.
//
//   These are defined by this file and are used by the
//   header files to decide what to declare or define:
//
//   __GLIBC_USE (F)	Define things from feature set F.  This is defined
//			to 1 or 0; the subsequent macros are either defined
//			or undefined, and those tests should be moved to
//			__GLIBC_USE.
//   __USE_ISOC11		Define ISO C11 things.
//   __USE_ISOC99		Define ISO C99 things.
//   __USE_ISOC95		Define ISO C90 AMD1 (C95) things.
//   __USE_ISOCXX11	Define ISO C++11 things.
//   __USE_POSIX		Define IEEE Std 1003.1 things.
//   __USE_POSIX2		Define IEEE Std 1003.2 things.
//   __USE_POSIX199309	Define IEEE Std 1003.1, and .1b things.
//   __USE_POSIX199506	Define IEEE Std 1003.1, .1b, .1c and .1i things.
//   __USE_XOPEN		Define XPG things.
//   __USE_XOPEN_EXTENDED	Define X/Open Unix things.
//   __USE_UNIX98		Define Single Unix V2 things.
//   __USE_XOPEN2K        Define XPG6 things.
//   __USE_XOPEN2KXSI     Define XPG6 XSI things.
//   __USE_XOPEN2K8       Define XPG7 things.
//   __USE_XOPEN2K8XSI    Define XPG7 XSI things.
//   __USE_LARGEFILE	Define correct standard I/O things.
//   __USE_LARGEFILE64	Define LFS things with separate names.
//   __USE_FILE_OFFSET64	Define 64bit interface as default.
//   __USE_MISC		Define things from 4.3BSD or System V Unix.
//   __USE_ATFILE		Define *at interfaces and AT_* constants for them.
//   __USE_GNU		Define GNU extensions.
//   __USE_FORTIFY_LEVEL	Additional security measures used, according to level.
//
//   The macros `__GNU_LIBRARY__', `__GLIBC__', and `__GLIBC_MINOR__' are
//   defined by this file unconditionally.  `__GNU_LIBRARY__' is provided
//   only for compatibility.  All new code should use the other symbols
//   to test for features.
//
//   All macros listed above as possibly being defined by this file are
//   explicitly undefined if they are not explicitly defined.
//   Feature-test macros that are not defined by the user or compiler
//   but are implied by the other feature-test macros defined (or by the
//   lack of any definitions) are defined by the file.
//
//   ISO C feature test macros depend on the definition of the macro
//   when an affected header is included, not when the first system
//   header is included, and so they are handled in
//   <bits/libc-header-start.h>, which does not have a multiple include
//   guard.  Feature test macros that can be handled from the first
//   system header included are handled here.

// Undefine everything, so we get a clean slate.

// Suppress kernel-name space pollution unless user expressedly asks
//   for it.

// Convenience macro to test the version of gcc.
//   Use like this:
//   #if __GNUC_PREREQ (2,8)
//   ... code requiring gcc 2.8 or later ...
//   #endif
//   Note: only works for GCC 2.0 and later, because __GNUC_MINOR__ was
//   added in 2.0.

// Similarly for clang.  Features added to GCC after version 4.2 may
//   or may not also be available in clang, and clang's definitions of
//   __GNUC(_MINOR)__ are fixed at 4 and 2 respectively.  Not all such
//   features can be queried via __has_extension/__has_feature.

// Whether to use feature set F.

// _BSD_SOURCE and _SVID_SOURCE are deprecated aliases for
//   _DEFAULT_SOURCE.  If _DEFAULT_SOURCE is present we do not
//   issue a warning; the expectation is that the source is being
//   transitioned to use the new macro.

// If _GNU_SOURCE was defined by the user, turn on all the other features.

// If nothing (other than _GNU_SOURCE and _DEFAULT_SOURCE) is defined,
//   define _DEFAULT_SOURCE.

// This is to enable the ISO C11 extension.

// This is to enable the ISO C99 extension.

// This is to enable the ISO C90 Amendment 1:1995 extension.

// If none of the ANSI/POSIX macros are defined, or if _DEFAULT_SOURCE
//   is defined, use POSIX.1-2008 (or another version depending on
//   _XOPEN_SOURCE).

// Some C libraries once required _REENTRANT and/or _THREAD_SAFE to be
//   defined in all multithreaded code.  GNU libc has not required this
//   for many years.  We now treat them as compatibility synonyms for
//   _POSIX_C_SOURCE=199506L, which is the earliest level of POSIX with
//   comprehensive support for multithreaded code.  Using them never
//   lowers the selected level of POSIX conformance, only raises it.

// The function 'gets' existed in C89, but is impossible to use
//   safely.  It has been removed from ISO C11 and ISO C++14.  Note: for
//   compatibility with various implementations of <cstdio>, this test
//   must consider only the value of __cplusplus when compiling C++.

// Get definitions of __STDC_* predefined macros, if the compiler has
//   not preincluded this header automatically.
// Copyright (C) 1991-2018 Free Software Foundation, Inc.
//   This file is part of the GNU C Library.
//
//   The GNU C Library is free software; you can redistribute it and/or
//   modify it under the terms of the GNU Lesser General Public
//   License as published by the Free Software Foundation; either
//   version 2.1 of the License, or (at your option) any later version.
//
//   The GNU C Library is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   Lesser General Public License for more details.
//
//   You should have received a copy of the GNU Lesser General Public
//   License along with the GNU C Library; if not, see
//   <http://www.gnu.org/licenses/>.

// This macro indicates that the installed library is the GNU C Library.
//   For historic reasons the value now is 6 and this will stay from now
//   on.  The use of this variable is deprecated.  Use __GLIBC__ and
//   __GLIBC_MINOR__ now (see below) when you want to test for a specific
//   GNU C library version and use the values in <gnu/lib-names.h> to get
//   the sonames of the shared libraries.

// Major and minor version number of the GNU C library package.  Use
//   these macros to test for features in specific releases.

// This is here only because every header file already includes this one.
// Copyright (C) 1992-2018 Free Software Foundation, Inc.
//   This file is part of the GNU C Library.
//
//   The GNU C Library is free software; you can redistribute it and/or
//   modify it under the terms of the GNU Lesser General Public
//   License as published by the Free Software Foundation; either
//   version 2.1 of the License, or (at your option) any later version.
//
//   The GNU C Library is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   Lesser General Public License for more details.
//
//   You should have received a copy of the GNU Lesser General Public
//   License along with the GNU C Library; if not, see
//   <http://www.gnu.org/licenses/>.

// We are almost always included from features.h.

// The GNU libc does not support any K&R compilers or the traditional mode
//   of ISO C compilers anymore.  Check for some of the combinations not
//   anymore supported.

// Some user header file might have defined this before.

// Compilers that are not clang may object to
//       #if defined __clang__ && __has_extension(...)
//   even though they do not need to evaluate the right-hand side of the &&.

// These two macros are not used in glibc anymore.  They are kept here
//   only because some other projects expect the macros to be defined.

// For these things, GCC behaves the ANSI way normally,
//   and the non-ANSI way under -traditional.

// This is not a typedef so `const __ptr_t' does the right thing.

// C++ needs to know that types and declarations are C, not C++.

// Fortify support.

// Support for flexible arrays.
//   Headers that should use flexible arrays only if they're "real"
//   (e.g. only if they won't affect sizeof()) should test
//   #if __glibc_c99_flexarr_available.

// __asm__ ("xyz") is used throughout the headers to rename functions
//   at the assembly language level.  This is wrapped by the __REDIRECT
//   macro, in order to support compilers that can do this some other
//   way.  When compilers don't support asm-names at all, we have to do
//   preprocessor tricks instead (which don't have exactly the right
//   semantics, but it's the best we can do).
//
//   Example:
//   int __REDIRECT(setpgrp, (__pid_t pid, __pid_t pgrp), setpgid);

// GCC has various useful declarations that can be made with the
//   `__attribute__' syntax.  All of the ways we use this do fine if
//   they are omitted for compilers that don't understand it.

// At some point during the gcc 2.96 development the `malloc' attribute
//   for functions was introduced.  We don't want to use it unconditionally
//   (although this would be possible) since it generates warnings.

// Tell the compiler which arguments to an allocation function
//   indicate the size of the allocation.

// At some point during the gcc 2.96 development the `pure' attribute
//   for functions was introduced.  We don't want to use it unconditionally
//   (although this would be possible) since it generates warnings.

// This declaration tells the compiler that the value is constant.

// At some point during the gcc 3.1 development the `used' attribute
//   for functions was introduced.  We don't want to use it unconditionally
//   (although this would be possible) since it generates warnings.

// Since version 3.2, gcc allows marking deprecated functions.

// Since version 4.5, gcc also allows one to specify the message printed
//   when a deprecated function is used.  clang claims to be gcc 4.2, but
//   may also support this feature.

// At some point during the gcc 2.8 development the `format_arg' attribute
//   for functions was introduced.  We don't want to use it unconditionally
//   (although this would be possible) since it generates warnings.
//   If several `format_arg' attributes are given for the same function, in
//   gcc-3.0 and older, all but the last one are ignored.  In newer gccs,
//   all designated arguments are considered.

// At some point during the gcc 2.97 development the `strfmon' format
//   attribute for functions was introduced.  We don't want to use it
//   unconditionally (although this would be possible) since it
//   generates warnings.

// The nonull function attribute allows to mark pointer parameters which
//   must not be NULL.

// If fortification mode, we warn about unused results of certain
//   function calls which can lead to problems.

// Forces a function to be always inlined.

// Associate error messages with the source location of the call site rather
//   than with the source location inside the function.

// GCC 4.3 and above with -std=c99 or -std=gnu99 implements ISO C99
//   inline semantics, unless -fgnu89-inline is used.  Using __GNUC_STDC_INLINE__
//   or __GNUC_GNU_INLINE is not a good enough check for gcc because gcc versions
//   older than 4.3 may define these macros and still not guarantee GNU inlining
//   semantics.
//
//   clang++ identifies itself as gcc-4.2, but has support for GNU inlining
//   semantics, that can be checked fot by using the __GNUC_STDC_INLINE_ and
//   __GNUC_GNU_INLINE__ macro definitions.

// GCC 4.3 and above allow passing all anonymous arguments of an
//   __extern_always_inline function to some other vararg function.

// It is possible to compile containing GCC extensions even if GCC is
//   run in pedantic mode if the uses are carefully marked using the
//   `__extension__' keyword.  But this is not generally available before
//   version 2.8.

// __restrict is known in EGCS 1.2 and above.

// ISO C99 also allows to declare arrays as non-overlapping.  The syntax is
//     array_name[restrict]
//   GCC 3.1 supports this.

// Determine the wordsize from the preprocessor defines.

// Properties of long double type.  ldbl-96 version.
//   Copyright (C) 2016-2018 Free Software Foundation, Inc.
//   This file is part of the GNU C Library.
//
//   The GNU C Library is free software; you can redistribute it and/or
//   modify it under the terms of the GNU Lesser General Public
//   License  published by the Free Software Foundation; either
//   version 2.1 of the License, or (at your option) any later version.
//
//   The GNU C Library is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   Lesser General Public License for more details.
//
//   You should have received a copy of the GNU Lesser General Public
//   License along with the GNU C Library; if not, see
//   <http://www.gnu.org/licenses/>.

// long double is distinct from double, so there is nothing to
//   define here.

// __glibc_macro_warning (MESSAGE) issues warning MESSAGE.  This is
//   intended for use in preprocessor macros.
//
//   Note: MESSAGE must be a _single_ string; concatenation of string
//   literals is not supported.

// Generic selection (ISO C11) is a C-only feature, available in GCC
//   since version 4.9.  Previous versions do not provide generic
//   selection, even though they might set __STDC_VERSION__ to 201112L,
//   when in -std=c11 mode.  Thus, we must check for !defined __GNUC__
//   when testing __STDC_VERSION__ for generic selection support.
//   On the other hand, Clang also defines __GNUC__, so a clang-specific
//   check is required to enable the use of generic selection.

// If we don't have __REDIRECT, prototypes will be missing if
//   __USE_FILE_OFFSET64 but not __USE_LARGEFILE[64].

// Decide whether we can define 'extern inline' functions in headers.

// This is here only because every header file already includes this one.
//   Get the definitions of all the appropriate `__stub_FUNCTION' symbols.
//   <gnu/stubs.h> contains `#define __stub_FUNCTION' when FUNCTION is a stub
//   that will always return failure (and set errno to ENOSYS).
// This file is automatically generated.
//   This file selects the right generated file of `__stub_FUNCTION' macros
//   based on the architecture being compiled for.

// This file is automatically generated.
//   It defines a symbol `__stub_FUNCTION' for each function
//   in the C library which is a stub, meaning it will fail
//   every time called, usually setting errno to ENOSYS.

// We need `pid_t'.
// bits/types.h -- definitions of __*_t types underlying *_t types.
//   Copyright (C) 2002-2018 Free Software Foundation, Inc.
//   This file is part of the GNU C Library.
//
//   The GNU C Library is free software; you can redistribute it and/or
//   modify it under the terms of the GNU Lesser General Public
//   License as published by the Free Software Foundation; either
//   version 2.1 of the License, or (at your option) any later version.
//
//   The GNU C Library is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   Lesser General Public License for more details.
//
//   You should have received a copy of the GNU Lesser General Public
//   License along with the GNU C Library; if not, see
//   <http://www.gnu.org/licenses/>.

// Never include this file directly; use <sys/types.h> instead.

// Copyright (C) 1991-2018 Free Software Foundation, Inc.
//   This file is part of the GNU C Library.
//
//   The GNU C Library is free software; you can redistribute it and/or
//   modify it under the terms of the GNU Lesser General Public
//   License as published by the Free Software Foundation; either
//   version 2.1 of the License, or (at your option) any later version.
//
//   The GNU C Library is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   Lesser General Public License for more details.
//
//   You should have received a copy of the GNU Lesser General Public
//   License along with the GNU C Library; if not, see
//   <http://www.gnu.org/licenses/>.

// Determine the wordsize from the preprocessor defines.

// Convenience types.
type X__u_char = uint8   /* types.h:30:23 */
type X__u_short = uint16 /* types.h:31:28 */
type X__u_int = uint32   /* types.h:32:22 */
type X__u_long = uint32  /* types.h:33:27 */

// Fixed-size types, underlying types depend on word size and compiler.
type X__int8_t = int8     /* types.h:36:21 */
type X__uint8_t = uint8   /* types.h:37:23 */
type X__int16_t = int16   /* types.h:38:26 */
type X__uint16_t = uint16 /* types.h:39:28 */
type X__int32_t = int32   /* types.h:40:20 */
type X__uint32_t = uint32 /* types.h:41:22 */
type X__int64_t = int64   /* types.h:46:44 */
type X__uint64_t = uint64 /* types.h:47:46 */

// Smallest types with at least a given width.
type X__int_least8_t = X__int8_t     /* types.h:51:18 */
type X__uint_least8_t = X__uint8_t   /* types.h:52:19 */
type X__int_least16_t = X__int16_t   /* types.h:53:19 */
type X__uint_least16_t = X__uint16_t /* types.h:54:20 */
type X__int_least32_t = X__int32_t   /* types.h:55:19 */
type X__uint_least32_t = X__uint32_t /* types.h:56:20 */
type X__int_least64_t = X__int64_t   /* types.h:57:19 */
type X__uint_least64_t = X__uint64_t /* types.h:58:20 */

// quad_t is also 64 bits.
type X__quad_t = int64    /* types.h:65:37 */
type X__u_quad_t = uint64 /* types.h:66:46 */

// Largest integral types.
type X__intmax_t = int64   /* types.h:74:37 */
type X__uintmax_t = uint64 /* types.h:75:46 */

// The machine-dependent file <bits/typesizes.h> defines __*_T_TYPE
//   macros for each of the OS types we define below.  The definitions
//   of those macros must use the following macros for underlying types.
//   We define __S<SIZE>_TYPE and __U<SIZE>_TYPE for the signed and unsigned
//   variants of each of the following integer types on this machine.
//
//	16		-- "natural" 16-bit type (always short)
//	32		-- "natural" 32-bit type (always int)
//	64		-- "natural" 64-bit type (long or long long)
//	LONG32		-- 32-bit type, traditionally long
//	QUAD		-- 64-bit type, always long long
//	WORD		-- natural type of __WORDSIZE bits (int or long)
//	LONGWORD	-- type of __WORDSIZE bits, traditionally long
//
//   We distinguish WORD/LONGWORD, 32/LONG32, and 64/QUAD so that the
//   conventional uses of `long' or `long long' type modifiers match the
//   types we define, even when a less-adorned type would be the same size.
//   This matters for (somewhat) portably writing printf/scanf formats for
//   these types, where using the appropriate l or ll format modifiers can
//   make the typedefs and the formats match up across all GNU platforms.  If
//   we used `long' when it's 64 bits where `long long' is expected, then the
//   compiler would warn about the formats not matching the argument types,
//   and the programmer changing them to shut up the compiler would break the
//   program's portability.
//
//   Here we assume what is presently the case in all the GCC configurations
//   we support: long long is always 64 bits, long is always word/address size,
//   and int is always 32 bits.

// We want __extension__ before typedef's that use nonstandard base types
//   such as `long long' in C89 mode.
// bits/typesizes.h -- underlying types for *_t.  Linux/x86-64 version.
//   Copyright (C) 2012-2018 Free Software Foundation, Inc.
//   This file is part of the GNU C Library.
//
//   The GNU C Library is free software; you can redistribute it and/or
//   modify it under the terms of the GNU Lesser General Public
//   License as published by the Free Software Foundation; either
//   version 2.1 of the License, or (at your option) any later version.
//
//   The GNU C Library is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   Lesser General Public License for more details.
//
//   You should have received a copy of the GNU Lesser General Public
//   License along with the GNU C Library; if not, see
//   <http://www.gnu.org/licenses/>.

// See <bits/types.h> for the meaning of these macros.  This file exists so
//   that <bits/types.h> need not vary across different GNU platforms.

// X32 kernel interface is 64-bit.

// Number of descriptors that can fit in an `fd_set'.

type X__dev_t = X__u_quad_t                /* types.h:143:25 */ // Type of device numbers.
type X__uid_t = uint32                     /* types.h:144:25 */ // Type of user identifications.
type X__gid_t = uint32                     /* types.h:145:25 */ // Type of group identifications.
type X__ino_t = uint32                     /* types.h:146:25 */ // Type of file serial numbers.
type X__ino64_t = X__u_quad_t              /* types.h:147:27 */ // Type of file serial numbers (LFS).
type X__mode_t = uint32                    /* types.h:148:26 */ // Type of file attribute bitmasks.
type X__nlink_t = uint32                   /* types.h:149:27 */ // Type of file link counts.
type X__off_t = int32                      /* types.h:150:25 */ // Type of file sizes and offsets.
type X__off64_t = X__quad_t                /* types.h:151:27 */ // Type of file sizes and offsets (LFS).
type X__pid_t = int32                      /* types.h:152:25 */ // Type of process identifications.
type X__fsid_t = struct{ F__val [2]int32 } /* types.h:153:26 */ // Type of file system IDs.
type X__clock_t = int32                    /* types.h:154:27 */ // Type of CPU usage counts.
type X__rlim_t = uint32                    /* types.h:155:26 */ // Type for resource measurement.
type X__rlim64_t = X__u_quad_t             /* types.h:156:28 */ // Type for resource measurement (LFS).
type X__id_t = uint32                      /* types.h:157:24 */ // General type for IDs.
type X__time_t = int32                     /* types.h:158:26 */ // Seconds since the Epoch.
type X__useconds_t = uint32                /* types.h:159:30 */ // Count of microseconds.
type X__suseconds_t = int32                /* types.h:160:31 */ // Signed count of microseconds.

type X__daddr_t = int32 /* types.h:162:27 */ // The type of a disk address.
type X__key_t = int32   /* types.h:163:25 */ // Type of an IPC key.

// Clock ID used in clock and timer functions.
type X__clockid_t = int32 /* types.h:166:29 */

// Timer ID returned by `timer_create'.
type X__timer_t = uintptr /* types.h:169:12 */

// Type to represent block size.
type X__blksize_t = int32 /* types.h:172:29 */

// Types from the Large File Support interface.

// Type to count number of disk blocks.
type X__blkcnt_t = int32       /* types.h:177:28 */
type X__blkcnt64_t = X__quad_t /* types.h:178:30 */

// Type to count file system blocks.
type X__fsblkcnt_t = uint32        /* types.h:181:30 */
type X__fsblkcnt64_t = X__u_quad_t /* types.h:182:32 */

// Type to count file system nodes.
type X__fsfilcnt_t = uint32        /* types.h:185:30 */
type X__fsfilcnt64_t = X__u_quad_t /* types.h:186:32 */

// Type of miscellaneous file system fields.
type X__fsword_t = int32 /* types.h:189:28 */

type X__ssize_t = int32 /* types.h:191:27 */ // Type of a byte count, or error.

// Signed long type used in system calls.
type X__syscall_slong_t = int32 /* types.h:194:33 */
// Unsigned long type used in system calls.
type X__syscall_ulong_t = uint32 /* types.h:196:33 */

// These few don't really vary by system, they always correspond
//   to one of the other defined types.
type X__loff_t = X__off64_t /* types.h:200:19 */ // Type of file sizes and offsets (LFS).
type X__caddr_t = uintptr   /* types.h:201:14 */

// Duplicates info from stdint.h but this is used in unistd.h.
type X__intptr_t = int32 /* types.h:204:25 */

// Duplicate info from sys/socket.h.
type X__socklen_t = uint32 /* types.h:207:23 */

// C99: An integer type that can be accessed as an atomic entity,
//   even in the presence of asynchronous interrupts.
//   It is not currently necessary for this to be machine-specific.
type X__sig_atomic_t = int32 /* types.h:212:13 */

type Pid_t = X__pid_t /* termios.h:30:17 */

// Get the system-dependent definitions of `struct termios', `tcflag_t',
//   `cc_t', `speed_t', and all the macros specifying the flag bits.
// termios type and macro definitions.  Linux version.
//   Copyright (C) 1993-2018 Free Software Foundation, Inc.
//   This file is part of the GNU C Library.
//
//   The GNU C Library is free software; you can redistribute it and/or
//   modify it under the terms of the GNU Lesser General Public
//   License as published by the Free Software Foundation; either
//   version 2.1 of the License, or (at your option) any later version.
//
//   The GNU C Library is distributed in the hope that it will be useful,
//   but WITHOUT ANY WARRANTY; without even the implied warranty of
//   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//   Lesser General Public License for more details.
//
//   You should have received a copy of the GNU Lesser General Public
//   License along with the GNU C Library; if not, see
//   <http://www.gnu.org/licenses/>.

type Cc_t = uint8      /* termios.h:23:23 */
type Speed_t = uint32  /* termios.h:24:22 */
type Tcflag_t = uint32 /* termios.h:25:22 */

type Termios = struct {
	Fc_iflag  Tcflag_t
	Fc_oflag  Tcflag_t
	Fc_cflag  Tcflag_t
	Fc_lflag  Tcflag_t
	Fc_line   Cc_t
	Fc_cc     [32]Cc_t
	_         [3]byte
	Fc_ispeed Speed_t
	Fc_ospeed Speed_t
} /* termios.h:28:1 */

// -
// Copyright (c) 1982, 1986, 1993
//	The Regents of the University of California.  All rights reserved.
// (c) UNIX System Laboratories, Inc.
// All or some portions of this file are derived from material licensed
// to the University of California by American Telephone and Telegraph
// Co. or Unix System Laboratories, Inc. and are reproduced herein with
// the permission of UNIX System Laboratories, Inc.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 4. Neither the name of the University nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
//	@(#)ttydefaults.h	8.4 (Berkeley) 1/21/94

// System wide defaults for terminal state.  Linux version.

// Defaults on "first" open.

// Control Character Defaults
// compat

// PROTECTED INCLUSION ENDS HERE

// #define TTYDEFCHARS to include an array of default control characters.

var _ int8 /* gen.c:2:13: */
