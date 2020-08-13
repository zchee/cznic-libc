// Code generated by 'ccgo /tmp/go-generate-104800690/x.c -ccgo-crt-import-path  -ccgo-export-defines  -ccgo-export-enums  -ccgo-export-externs X -ccgo-export-fields F -ccgo-export-structs  -ccgo-export-typedefs  -ccgo-pkgname termios -o termios/termios_linux_amd64.go', DO NOT EDIT.

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
	X_HAVE_STRUCT_TERMIOS_C_ISPEED = 1
	X_HAVE_STRUCT_TERMIOS_C_OSPEED = 1
	X_LP64                         = 1
	X_POSIX_C_SOURCE               = 200809
	X_POSIX_SOURCE                 = 1
	X_STDC_PREDEF_H                = 1
	X_SYS_CDEFS_H                  = 1
	X_SYS_TTYDEFAULTS_H_           = 0
	X_TERMIOS_H                    = 1
	Linux                          = 1
	Unix                           = 1
)

type Ptrdiff_t = int64 /* <builtin>:3:26 */

type Size_t = uint64 /* <builtin>:9:23 */

type Wchar_t = int32 /* <builtin>:15:24 */

type Pid_t = int32 /* termios.h:30:17 */

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
	Fc_ispeed Speed_t
	Fc_ospeed Speed_t
}

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

var _ int8 /* x.c:2:13: */
