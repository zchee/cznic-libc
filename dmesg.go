// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build libc.dmesg

package libc // import "modernc.org/libc"

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const dmesgs = true

var (
	pid  = fmt.Sprintf("[%v %v] ", os.Getpid(), filepath.Base(os.Args[0]))
	logf *os.File
)

func init() {
	var err error
	var fn string
	switch {
	case runtime.GOOS == "windows":
		fn = "y:\\libc.log"
	default:
		fn = filepath.Join(os.TempDir(), "libc.log")
	}
	new := false
	if _, err := os.Stat(fn); os.IsNotExist(err) {
		new = true
	}
	if logf, err = os.OpenFile(fn, os.O_APPEND|os.O_CREATE|os.O_WRONLY|os.O_SYNC, 0644); err != nil {
		panic(err.Error())
	}
	if new {
		fmt.Printf("dmesgs in %s\n", fn)
		dmesg("%v", time.Now())
	}
}

func dmesg(s string, args ...interface{}) {
	if s == "" {
		s = strings.Repeat("%v ", len(args))
	}
	s = fmt.Sprintf(pid+s, args...)
	switch {
	case len(s) != 0 && s[len(s)-1] == '\n':
		fmt.Fprint(logf, s)
	default:
		fmt.Fprintln(logf, s)
	}
}
