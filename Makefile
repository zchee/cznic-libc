# Copyright 2019 The Libc Authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

.PHONY:	all bench clean cover cpu editor internalError later mem nuke todo edit devbench \
	linux_386 \
	linux_amd64 \


grep=--include=*.go
ngrep='internalError\|TODOOK'
log=log-$(shell go env GOOS)-$(shell go env GOARCH)

all:
	LC_ALL=C make all_log 2>&1 | tee log

all_log:
	date
	go version
	uname -a
	gofmt -l -s -w *.go
	GOOS=linux GOARCH=386 go build
	GOOS=linux GOARCH=amd64 go build
	GOOS=linux GOARCH=arm go build
	GOOS=linux GOARCH=arm64 go build
	#TODO GOOS=windows GOARCH=386 go build
	GOOS=windows GOARCH=amd64 go build
	go vet 2>&1 | grep -v $(ngrep) || true
	golint 2>&1 | grep -v $(ngrep) || true
	staticcheck || true

linux_amd64:
	TARGET_GOOS=linux TARGET_GOARCH=amd64 go generate
	GOOS=linux GOARCH=amd64 go build -v ./...

linux_386:
	CCGO_CPP=i686-linux-gnu-cpp TARGET_GOOS=linux TARGET_GOARCH=386 go generate
	GOOS=linux GOARCH=386 go build -v ./...

linux_arm:
	CCGO_CPP=arm-linux-gnueabi-cpp-8 TARGET_GOOS=linux TARGET_GOARCH=arm go generate
	GOOS=linux GOARCH=arm go build -v ./...

linux_arm64:
	CCGO_CPP=aarch64-linux-gnu-cpp-8 TARGET_GOOS=linux TARGET_GOARCH=arm64 go generate
	GOOS=linux GOARCH=arm64 go build -v ./...

windows_amd64:
	CCGO_CPP=x86_64-w64-mingw32-cpp TARGET_GOOS=windows TARGET_GOARCH=amd64 go generate
	CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows GOARCH=amd64 go build -v ./...

devbench:
	date 2>&1 | tee log-devbench
	go test -timeout 24h -dev -run @ -bench . 2>&1 | tee -a log-devbench
	grep -n 'FAIL\|SKIP' log-devbench || true

bench:
	date 2>&1 | tee log-bench
	go test -timeout 24h -v -run '^[^E]' -bench . 2>&1 | tee -a log-bench
	grep -n 'FAIL\|SKIP' log-bench || true

clean:
	go clean
	rm -f *~ *.test *.out

cover:
	t=$(shell mktemp) ; go test -coverprofile $$t && go tool cover -html $$t && unlink $$t

cpu: clean
	go test -run @ -bench . -cpuprofile cpu.out
	go tool pprof -lines *.test cpu.out

edit:
	touch log
	gvim -p Makefile *.go \
	&

editor:
	make windows_amd64
	gofmt -l -s -w *.go
	go test -i
	go test -short 2>&1 | tee -a log
	go install -v ./...

later:
	@grep -n $(grep) LATER * || true
	@grep -n $(grep) MAYBE * || true

mem: clean
	go test -v -run ParserCS -memprofile mem.out -timeout 24h
	go tool pprof -lines -web -alloc_space *.test mem.out

nuke: clean
	go clean -i

todo:
	@grep -nr $(grep) ^[[:space:]]*_[[:space:]]*=[[:space:]][[:alpha:]][[:alnum:]]* * | grep -v $(ngrep) || true
	@grep -nr $(grep) 'TODO\|panic' * | grep -v $(ngrep) || true
	@grep -nr $(grep) BUG * | grep -v $(ngrep) || true
	@grep -nr $(grep) [^[:alpha:]]println * | grep -v $(ngrep) || true
	@grep -nir $(grep) 'work.*progress' || true

