// +build ignore

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"modernc.org/cc/v3"
)

var (
	goos   = runtime.GOOS
	goarch = runtime.GOARCH
)

func main() {
	if s := os.Getenv("TARGET_GOOS"); s != "" {
		goos = s
	}
	if s := os.Getenv("TARGET_GOARCH"); s != "" {
		goarch = s
	}
	switch goos {
	case "linux":
		makeMusl(goos, goarch)
	case "windows":
		makeMuslWin(goos, goarch)
	}
	_, _, hostSysIncludes, err := cc.HostConfig(os.Getenv("CCGO_CPP"))
	if err != nil {
		fail("%v", err)
	}

	g := []string{"libc.go", "libc_posix.go"}
	x, err := filepath.Glob(fmt.Sprintf("*_%s.go", goos))
	if err != nil {
		fail("%v", err)
	}

	g = append(g, x...)
	if x, err = filepath.Glob(fmt.Sprintf("*_%s_%s.go", goos, goarch)); err != nil {
		fail("%v", err)
	}

	g = append(g, x...)
	m := map[string]struct{}{}
	for _, v := range g {
		f, err := os.Open(v)
		if err != nil {
			fail("%v", err)
		}

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			s := sc.Text()
			switch {
			case strings.HasPrefix(s, "func X"):
				s = s[len("func X"):]
				x := strings.IndexByte(s, '(')
				s = s[:x]
			case strings.HasPrefix(s, "var X"):
				s = s[len("var X"):]
				x := strings.IndexByte(s, ' ')
				s = s[:x]
			default:
				continue
			}

			m[s] = struct{}{}
		}
		if err := sc.Err(); err != nil {
			fail("%v", err)
		}

		f.Close()
	}
	var a []string
	for k := range m {
		a = append(a, k)
	}
	sort.Strings(a)
	b := bytes.NewBuffer(nil)
	b.WriteString(`// Code generated by 'go generate' - DO NOT EDIT.

package libc // import "modernc.org/libc"

var CAPI = map[string]struct{}{`)

	for _, v := range a {
		fmt.Fprintf(b, "\n\t%q: {},", v)
	}
	b.WriteString("\n}")
	if err := ioutil.WriteFile(fmt.Sprintf("capi_%s_%s.go", goos, goarch), b.Bytes(), 0660); err != nil {
		fail("%v", err)
	}

	ccgoHelpers()

	if err := libcHeaders(hostSysIncludes); err != nil {
		fail("%v", err)
	}
}

func makeMusl(goos, goarch string) {
	wd, err := os.Getwd()
	if err != nil {
		fail("%v", err)
	}

	if err := os.Chdir("musl"); err != nil {
		fail("%v", err)
	}

	var arch string
	switch goarch {
	case "amd64":
		arch = "x86_64"
	case "386":
		arch = "i386"
	case "arm":
		arch = "arm"
	case "arm64":
		arch = "aarch64"
	default:
		fail("unknown/unsupported GOARCH: %q", goarch)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			fail("%v", err)
		}
	}()

	run("mkdir", "-p", "obj/include/bits")
	run("sh", "-c", fmt.Sprintf("sed -f ./tools/mkalltypes.sed ./arch/%s/bits/alltypes.h.in ./include/alltypes.h.in > obj/include/bits/alltypes.h", arch))
	run("sh", "-c", fmt.Sprintf("cp arch/%s/bits/syscall.h.in obj/include/bits/syscall.h", arch))
	run("sh", "-c", fmt.Sprintf("sed -n -e s/__NR_/SYS_/p < arch/%s/bits/syscall.h.in >> obj/include/bits/syscall.h", arch))
	out := run(
		"ccgo",
		"-D__attribute__(x)=",
		"-ccgo-export-externs", "X",
		"-ccgo-hide", "__syscall0,__syscall1,__syscall2,__syscall3,__syscall4,__syscall5,__syscall6",
		"-ccgo-libc",
		"-ccgo-long-double-is-double",
		"-ccgo-pkgname", "libc",
		"-nostdinc",
		"-o", fmt.Sprintf("../musl_%s_%s.go", goos, goarch),

		// Keep the order below, don't sort!
		fmt.Sprintf("-I%s", filepath.Join("arch", arch)),
		fmt.Sprintf("-I%s", "arch/generic"),
		fmt.Sprintf("-I%s", "obj/src/internal"),
		fmt.Sprintf("-I%s", "src/include"),
		fmt.Sprintf("-I%s", "src/internal"),
		fmt.Sprintf("-I%s", "obj/include"),
		fmt.Sprintf("-I%s", "include"),
		// Keep the order above, don't sort!

		"copyright.c", // Inject legalese first

		// Keep the below lines sorted.
		"src/ctype/isalnum.c",
		"src/ctype/isalpha.c",
		"src/ctype/isdigit.c",
		"src/ctype/isxdigit.c",
		"src/dirent/closedir.c",
		"src/dirent/opendir.c",
		"src/dirent/readdir.c",
		"src/internal/intscan.c",
		"src/internal/shgetc.c",
		"src/network/freeaddrinfo.c",
		"src/network/getaddrinfo.c",
		"src/network/gethostbyaddr.c",
		"src/network/gethostbyaddr_r.c",
		"src/network/gethostbyname.c",
		"src/network/gethostbyname2.c",
		"src/network/gethostbyname2_r.c",
		"src/network/getnameinfo.c",
		"src/network/h_errno.c",
		"src/network/inet_aton.c",
		"src/network/inet_ntop.c",
		"src/network/inet_pton.c",
		"src/network/lookup_ipliteral.c",
		"src/network/lookup_name.c",
		"src/network/lookup_serv.c",
		"src/stdio/__toread.c",
		"src/stdio/__uflow.c",
		"src/stdlib/strtol.c",
		"src/string/strnlen.c",
		"src/string/strspn.c",
	)
	fmt.Printf("%s\n", out)
}

func makeMuslWin(goos, goarch string) {
	wd, err := os.Getwd()
	if err != nil {
		fail("%v", err)
	}

	if err := os.Chdir("musl"); err != nil {
		fail("%v", err)
	}

	var arch string
	switch goarch {
	case "amd64":
		arch = "x86_64"
	case "386":
		arch = "i386"
	case "arm":
		arch = "arm"
	case "arm64":
		arch = "aarch64"
	default:
		fail("unknown/unsupported GOARCH: %q", goarch)
	}
	defer func() {
		if err := os.Chdir(wd); err != nil {
			fail("%v", err)
		}
	}()

	run("mkdir", "-p", "obj/include/bits")
	run("sh", "-c", fmt.Sprintf("sed -f ./tools/mkalltypes.sed ./arch/%s/bits/alltypes.h.in ./include/alltypes.h.in > obj/include/bits/alltypes.h", arch))
	run("sh", "-c", fmt.Sprintf("cp arch/%s/bits/syscall.h.in obj/include/bits/syscall.h", arch))
	run("sh", "-c", fmt.Sprintf("sed -n -e s/__NR_/SYS_/p < arch/%s/bits/syscall.h.in >> obj/include/bits/syscall.h", arch))
	out := run(
		"ccgo",
		"-D__attribute__(x)=",
		"-ccgo-export-externs", "X",
		"-ccgo-hide", "__syscall0,__syscall1,__syscall2,__syscall3,__syscall4,__syscall5,__syscall6",
		"-ccgo-libc",
		"-ccgo-long-double-is-double",
		"-ccgo-pkgname", "libc",
		"-nostdinc",
		"-o", fmt.Sprintf("../musl_%s_%s.go", goos, goarch),

		// Keep the order below, don't sort!
		fmt.Sprintf("-I%s", filepath.Join("arch", arch)),
		fmt.Sprintf("-I%s", "arch/generic"),
		fmt.Sprintf("-I%s", "obj/src/internal"),
		fmt.Sprintf("-I%s", "src/include"),
		fmt.Sprintf("-I%s", "src/internal"),
		fmt.Sprintf("-I%s", "obj/include"),
		fmt.Sprintf("-I%s", "include"),
		// Keep the order above, don't sort!

		"copyright.c", // Inject legalese first

		// Keep the below lines sorted.
		"src/ctype/isalnum.c",
		"src/ctype/isalpha.c",
		"src/ctype/isdigit.c",
		"src/ctype/islower.c",
		"src/ctype/isprint.c",
		"src/ctype/isspace.c",
		"src/ctype/isxdigit.c",
		"src/internal/intscan.c",
		"src/internal/shgetc.c",
		"src/stdio/__toread.c",
		"src/stdio/__uflow.c",
		"src/stdlib/strtol.c",
	)
	fmt.Printf("%s\n", out)
}

func run(arg0 string, args ...string) []byte {
	fmt.Printf("%s %q\n", arg0, args)
	cmd := exec.Command(arg0, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		sout := strings.TrimSpace(string(out) + "\n")
		fmt.Fprintf(os.Stderr, "==== FAIL\n%s\n%s\n", sout, err)
		fail("%v", err)
	}
	return out
}

func libcHeaders(paths []string) error {
	const cfile = "gen.c"
	return filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		dir := path
		ok := false
		for _, v := range paths {
			full := filepath.Join(v, dir+".h")
			if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
				ok = true
				break
			}
		}
		if !ok {
			return nil
		}

		src := fmt.Sprintf(`#include <%s.h>
static char _;
`, dir)
		fn := filepath.Join(dir, cfile)
		if err := ioutil.WriteFile(fn, []byte(src), 0660); err != nil {
			return err
		}

		defer os.Remove(fn)

		dest := filepath.Join(path, fmt.Sprintf("%s_%s_%s.go", filepath.Base(path), goos, goarch))
		base := filepath.Base(dir)
		cmd := exec.Command(
			"ccgo", fn,
			"-D__signed__=signed", // <asm/signal.h>
			"-D__attribute__(x)=",
			"-ccgo-crt-import-path", "",
			"-ccgo-export-defines", "",
			"-ccgo-export-enums", "",
			"-ccgo-export-externs", "X",
			"-ccgo-export-fields", "F",
			"-ccgo-export-structs", "",
			"-ccgo-export-typedefs", "",
			"-ccgo-header",
			"-ccgo-long-double-is-double",
			"-ccgo-pkgname", base,
			"-o", dest,
		)
		out, err := cmd.CombinedOutput()
		sout := strings.TrimSpace(string(out) + "\n")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n%s\n", path, sout, err)
		} else {
			fmt.Fprintf(os.Stdout, "%s\n%s", path, sout)
		}
		return nil
	})
}

func fail(s string, args ...interface{}) {
	s = fmt.Sprintf(s, args...)
	fmt.Fprintf(os.Stderr, "\n%v: FAIL\n%s\n", origin(2), s)
	os.Exit(1)
}

func origin(skip int) string {
	pc, fn, fl, _ := runtime.Caller(skip)
	f := runtime.FuncForPC(pc)
	var fns string
	if f != nil {
		fns = f.Name()
		if x := strings.LastIndex(fns, "."); x > 0 {
			fns = fns[x+1:]
		}
	}
	return fmt.Sprintf("%s:%d:%s", fn, fl, fns)
}

func ccgoHelpers() {
	var (
		signed = []string{
			"int8",
			"int16",
			"int32",
			"int64",
		}
		unsigned = []string{
			"uint8",
			"uint16",
			"uint32",
			"uint64",
		}
		ints   = append(signed[:len(signed):len(signed)], unsigned...)
		intptr = append(ints[:len(ints):len(ints)], "uintptr")
		arith  = append(ints[:len(ints):len(ints)], "float32", "float64")
		scalar = append(arith[:len(arith):len(arith)], []string{"uintptr"}...)
		sizes  = []string{"8", "16", "32", "64"}
		atomic = []string{
			"int32",
			"int64",
			"uint32",
			"uint64",
			"uintptr",
		}
	)

	b := bytes.NewBuffer(nil)
	b.WriteString(`// Code generated by 'go generate' - DO NOT EDIT.

package libc // import "modernc.org/libc"

import (
	"sync/atomic"
	"unsafe"
)

`)
	for _, v := range atomic {
		fmt.Fprintln(b)
		fmt.Fprintf(b, "func AtomicStoreN%s(ptr uintptr, val %s, memorder int32) { atomic.Store%[1]s((*%[2]s)(unsafe.Pointer(ptr)), val) }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range atomic {
		fmt.Fprintln(b)
		fmt.Fprintf(b, "func AtomicLoadN%s(ptr uintptr, memorder int32) %s { return atomic.Load%[1]s((*%[2]s)(unsafe.Pointer(ptr))) }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func Assign%s(p *%s, v %[2]s) %[2]s { *p = v; return v }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func AssignPtr%s(p uintptr, v %s) %[2]s { *(*%[2]s)(unsafe.Pointer(p)) = v; return v }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func AssignMul%s(p *%s, v %[2]s) %[2]s { *p *= v; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func AssignDiv%s(p *%s, v %[2]s) %[2]s { *p /= v; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignRem%s(p *%s, v %[2]s) %[2]s { *p %%= v; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func AssignAdd%s(p *%s, v %[2]s) %[2]s { *p += v; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func AssignSub%s(p *%s, v %[2]s) %[2]s { *p -= v; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignAnd%s(p *%s, v %[2]s) %[2]s { *p &= v; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignXor%s(p *%s, v %[2]s) %[2]s { *p ^= v; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignOr%s(p *%s, v %[2]s) %[2]s { *p |= v; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func AssignMulPtr%s(p uintptr, v %s) %[2]s { *(*%[2]s)(unsafe.Pointer(p)) *= v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func AssignDivPtr%s(p uintptr, v %s) %[2]s { *(*%[2]s)(unsafe.Pointer(p)) /= v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignRemPtr%s(p uintptr, v %s) %[2]s { *(*%[2]s)(unsafe.Pointer(p)) %%= v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func AssignAddPtr%s(p uintptr, v %s) %[2]s { *(*%[2]s)(unsafe.Pointer(p)) += v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func AssignSubPtr%s(p uintptr, v %s) %[2]s { *(*%[2]s)(unsafe.Pointer(p)) -= v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignAndPtr%s(p uintptr, v %s) %[2]s { *(*%[2]s)(unsafe.Pointer(p)) &= v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignXorPtr%s(p uintptr, v %s) %[2]s { *(*%[2]s)(unsafe.Pointer(p)) ^= v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignOrPtr%s(p uintptr, v %s) %[2]s { *(*%[2]s)(unsafe.Pointer(p)) |= v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignShlPtr%s(p uintptr, v int) %s { *(*%[2]s)(unsafe.Pointer(p)) <<= v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignShrPtr%s(p uintptr, v int) %s { *(*%[2]s)(unsafe.Pointer(p)) >>= v; return *(*%[2]s)(unsafe.Pointer(p)) }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignShl%s(p *%s, v int) %[2]s { *p <<= v; return *p }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func AssignShr%s(p *%s, v int) %[2]s { *p >>= v; return *p }\n\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func PreInc%s(p *%s, d %[2]s) %[2]s { *p += d; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func PreDec%s(p *%s, d %[2]s) %[2]s { *p -= d; return *p }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func PostInc%s(p *%s, d %[2]s) %[2]s { r := *p; *p += d; return r }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func PostDec%s(p *%s, d %[2]s) %[2]s { r := *p; *p -= d; return r }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		for _, w := range scalar {
			fmt.Fprintf(b, "func %sFrom%s(n %s) %s { return %[4]s(n) }\n", capitalize(v), capitalize(w), w, v)
		}
	}

	fmt.Fprintln(b)
	for _, v := range scalar {
		fmt.Fprintf(b, "func %s(n %s) %[2]s { return n }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func Neg%s(n %s) %[2]s { return -n }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range intptr {
		fmt.Fprintf(b, "func Cpl%s(n %s) %[2]s { return ^n }\n", capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, v := range ints {
		fmt.Fprintf(b, `
func Bool%s(b bool) %s {
	if b {
		return 1
	}
	return 0
}
`, capitalize(v), v)
	}

	fmt.Fprintln(b)
	for _, sz := range sizes {
		for _, v := range ints {
			fmt.Fprintf(b, `
func SetBitFieldPtr%s%s(p uintptr, v %s, off int, mask uint%[1]s) {
	*(*uint%[1]s)(unsafe.Pointer(p)) = *(*uint%[1]s)(unsafe.Pointer(p))&^uint%[1]s(mask) | uint%[1]s(v<<off)&mask
}

`, sz, capitalize(v), v)
		}
	}

	fmt.Fprintln(b)
	for _, sz := range []int{8, 16, 32, 64} {
		for _, v := range []int{8, 16, 32, 64} {
			fmt.Fprintf(b, `
func AssignBitFieldPtr%dInt%d(p uintptr, v int%[2]d, w, off int, mask uint%[1]d) int%[2]d {
	*(*uint%[1]d)(unsafe.Pointer(p)) = *(*uint%[1]d)(unsafe.Pointer(p))&^uint%[1]d(mask) | uint%[1]d(v<<off)&mask
	s := %[2]d - w
	return v << s >> s
}

`, sz, v)
		}
	}

	fmt.Fprintln(b)
	for _, sz := range []int{8, 16, 32, 64} {
		for _, v := range []int{8, 16, 32, 64} {
			fmt.Fprintf(b, `
func AssignBitFieldPtr%dUint%d(p uintptr, v uint%[2]d, w, off int, mask uint%[1]d) uint%[2]d {
	*(*uint%[1]d)(unsafe.Pointer(p)) = *(*uint%[1]d)(unsafe.Pointer(p))&^uint%[1]d(mask) | uint%[1]d(v<<off)&mask
	return v & uint%[2]d(mask >> off)
}

`, sz, v)
		}
	}

	fmt.Fprintln(b)
	for _, sz := range []int{8, 16, 32, 64} {
		for _, v := range []int{8, 16, 32, 64} {
			fmt.Fprintf(b, `
func PostDecBitFieldPtr%dInt%d(p uintptr, d int%[2]d, w, off int, mask uint%[1]d) (r int%[2]d) {
	x0 := *(*uint%[1]d)(unsafe.Pointer(p))
	s := %[2]d - w
	r = int%[2]d(x0) & int%[2]d(mask) << s >> s
	*(*uint%[1]d)(unsafe.Pointer(p)) = x0&^uint%[1]d(mask) | uint%[1]d(r-d)<<off&mask
	return r
}

`, sz, v)
		}
	}

	fmt.Fprintln(b)
	for _, sz := range []int{8, 16, 32, 64} {
		for _, v := range []int{8, 16, 32, 64} {
			fmt.Fprintf(b, `
func PostDecBitFieldPtr%dUint%d(p uintptr, d uint%[2]d, w, off int, mask uint%[1]d) (r uint%[2]d) {
	x0 := *(*uint%[1]d)(unsafe.Pointer(p))
	r = uint%[2]d(x0) & uint%[2]d(mask) >> off
	*(*uint%[1]d)(unsafe.Pointer(p)) = x0&^uint%[1]d(mask) | uint%[1]d(r-d)<<off&mask
	return r
}

`, sz, v)
		}
	}

	fmt.Fprintln(b)
	for _, sz := range []int{8, 16, 32, 64} {
		for _, v := range []int{8, 16, 32, 64} {
			fmt.Fprintf(b, `
func PostIncBitFieldPtr%dInt%d(p uintptr, d int%[2]d, w, off int, mask uint%[1]d) (r int%[2]d) {
	x0 := *(*uint%[1]d)(unsafe.Pointer(p))
	s := %[2]d - w
	r = int%[2]d(x0) & int%[2]d(mask) << s >> s
	*(*uint%[1]d)(unsafe.Pointer(p)) = x0&^uint%[1]d(mask) | uint%[1]d(r+d)<<off&mask
	return r
}

`, sz, v)
		}
	}

	fmt.Fprintln(b)
	for _, sz := range []int{8, 16, 32, 64} {
		for _, v := range []int{8, 16, 32, 64} {
			fmt.Fprintf(b, `
func PostIncBitFieldPtr%dUint%d(p uintptr, d uint%[2]d, w, off int, mask uint%[1]d) (r uint%[2]d) {
	x0 := *(*uint%[1]d)(unsafe.Pointer(p))
	r = uint%[2]d(x0) & uint%[2]d(mask) >> off
	*(*uint%[1]d)(unsafe.Pointer(p)) = x0&^uint%[1]d(mask) | uint%[1]d(r+d)<<off&mask
	return r
}

`, sz, v)
		}
	}

	b.WriteString("\n")
	if err := ioutil.WriteFile(fmt.Sprintf("ccgo.go"), b.Bytes(), 0660); err != nil {
		fail("%v", err)
	}
}

func capitalize(s string) string { return strings.ToUpper(s[:1]) + s[1:] }
