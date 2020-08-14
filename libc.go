// Copyright 2020 The Libc Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !cgo

//go.generate echo package libc > ccgo.go
//go:generate go run generate.go
//go:generate go fmt ./...

//
package libc // import "modernc.org/libc"
