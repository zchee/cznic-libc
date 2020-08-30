// Code generated by 'go generate' - DO NOT EDIT.

package libc // import "modernc.org/libc"

var CAPI = map[string]struct{}{
	"__assert_fail":         {},
	"__builtin_abort":       {},
	"__builtin_abs":         {},
	"__builtin_copysign":    {},
	"__builtin_copysignf":   {},
	"__builtin_exit":        {},
	"__builtin_expect":      {},
	"__builtin_fabs":        {},
	"__builtin_free":        {},
	"__builtin_malloc":      {},
	"__builtin_memcmp":      {},
	"__builtin_memcpy":      {},
	"__builtin_memset":      {},
	"__builtin_prefetch":    {},
	"__builtin_printf":      {},
	"__builtin_snprintf":    {},
	"__builtin_sprintf":     {},
	"__builtin_strchr":      {},
	"__builtin_strcmp":      {},
	"__builtin_strcpy":      {},
	"__builtin_strlen":      {},
	"__builtin_trap":        {},
	"__builtin_unreachable": {},
	"__ccgo_in6addr_anyp":   {},
	"__ctype_b_loc":         {},
	"__errno_location":      {},
	"__isnan":               {},
	"__isnanf":              {},
	"__isnanl":              {},
	"__isoc99_sscanf":       {},
	"_exit":                 {},
	"abort":                 {},
	"abs":                   {},
	"accept":                {},
	"access":                {},
	"acos":                  {},
	"alarm":                 {},
	"asin":                  {},
	"atan":                  {},
	"atan2":                 {},
	"atof":                  {},
	"atoi":                  {},
	"atol":                  {},
	"backtrace":             {},
	"backtrace_symbols_fd":  {},
	"bind":                  {},
	"calloc":                {},
	"ceil":                  {},
	"cfgetospeed":           {},
	"cfsetispeed":           {},
	"cfsetospeed":           {},
	"chdir":                 {},
	"chmod":                 {},
	"chown":                 {},
	"close":                 {},
	"closedir":              {},
	"connect":               {},
	"copysign":              {},
	"copysignf":             {},
	"cos":                   {},
	"cosf":                  {},
	"cosh":                  {},
	"dlclose":               {},
	"dlerror":               {},
	"dlopen":                {},
	"dlsym":                 {},
	"dup2":                  {},
	"environ":               {},
	"execvp":                {},
	"exit":                  {},
	"exp":                   {},
	"fabs":                  {},
	"fabsf":                 {},
	"fchmod":                {},
	"fchown":                {},
	"fclose":                {},
	"fcntl":                 {},
	"fcntl64":               {},
	"fdopen":                {},
	"ferror":                {},
	"fflush":                {},
	"fgetc":                 {},
	"fgets":                 {},
	"fileno":                {},
	"floor":                 {},
	"fmod":                  {},
	"fopen":                 {},
	"fopen64":               {},
	"fork":                  {},
	"fprintf":               {},
	"fputc":                 {},
	"fputs":                 {},
	"fread":                 {},
	"free":                  {},
	"freeaddrinfo":          {},
	"frexp":                 {},
	"fseek":                 {},
	"fstat":                 {},
	"fstat64":               {},
	"fsync":                 {},
	"ftell":                 {},
	"ftruncate":             {},
	"ftruncate64":           {},
	"fts_close":             {},
	"fts_open":              {},
	"fts_read":              {},
	"fwrite":                {},
	"gai_strerror":          {},
	"getaddrinfo":           {},
	"getcwd":                {},
	"getenv":                {},
	"geteuid":               {},
	"getgrgid":              {},
	"getgrnam":              {},
	"gethostbyaddr":         {},
	"gethostbyname":         {},
	"getnameinfo":           {},
	"getpeername":           {},
	"getpid":                {},
	"getpwnam":              {},
	"getpwuid":              {},
	"getrlimit":             {},
	"getrusage":             {},
	"getservbyname":         {},
	"getsockname":           {},
	"getsockopt":            {},
	"gettimeofday":          {},
	"getuid":                {},
	"gmtime_r":              {},
	"htonl":                 {},
	"htons":                 {},
	"hypot":                 {},
	"inet_ntoa":             {},
	"ioctl":                 {},
	"isatty":                {},
	"isnan":                 {},
	"isnanf":                {},
	"isnanl":                {},
	"ldexp":                 {},
	"link":                  {},
	"listen":                {},
	"localtime":             {},
	"localtime_r":           {},
	"log":                   {},
	"log10":                 {},
	"lseek":                 {},
	"lseek64":               {},
	"lstat":                 {},
	"lstat64":               {},
	"malloc":                {},
	"memchr":                {},
	"memcmp":                {},
	"memcpy":                {},
	"memmove":               {},
	"memset":                {},
	"mkdir":                 {},
	"mkfifo":                {},
	"mknod":                 {},
	"mkstemp":               {},
	"mkstemps":              {},
	"mktime":                {},
	"mmap64":                {},
	"modf":                  {},
	"munmap":                {},
	"nl_langinfo":           {},
	"ntohs":                 {},
	"open":                  {},
	"open64":                {},
	"opendir":               {},
	"pclose":                {},
	"perror":                {},
	"pipe":                  {},
	"popen":                 {},
	"pow":                   {},
	"printf":                {},
	"putc":                  {},
	"putchar":               {},
	"qsort":                 {},
	"raise":                 {},
	"rand":                  {},
	"read":                  {},
	"readdir":               {},
	"readdir64":             {},
	"readlink":              {},
	"realloc":               {},
	"realpath":              {},
	"recv":                  {},
	"rename":                {},
	"rewind":                {},
	"rmdir":                 {},
	"round":                 {},
	"select":                {},
	"send":                  {},
	"setlocale":             {},
	"setrlimit":             {},
	"setsockopt":            {},
	"setvbuf":               {},
	"shutdown":              {},
	"sigaction":             {},
	"signal":                {},
	"sin":                   {},
	"sinf":                  {},
	"sinh":                  {},
	"sleep":                 {},
	"snprintf":              {},
	"socket":                {},
	"sprintf":               {},
	"sqrt":                  {},
	"stat":                  {},
	"stat64":                {},
	"stderr":                {},
	"stdin":                 {},
	"stdout":                {},
	"strcasecmp":            {},
	"strcat":                {},
	"strchr":                {},
	"strcmp":                {},
	"strcpy":                {},
	"strcspn":               {},
	"strdup":                {},
	"strerror":              {},
	"strlen":                {},
	"strncmp":               {},
	"strncpy":               {},
	"strpbrk":               {},
	"strrchr":               {},
	"strstr":                {},
	"strtol":                {},
	"strtoul":               {},
	"symlink":               {},
	"sysconf":               {},
	"system":                {},
	"tan":                   {},
	"tanh":                  {},
	"tcgetattr":             {},
	"tcsetattr":             {},
	"time":                  {},
	"tolower":               {},
	"toupper":               {},
	"tzset":                 {},
	"umask":                 {},
	"uname":                 {},
	"unlink":                {},
	"usleep":                {},
	"utime":                 {},
	"utimes":                {},
	"vfprintf":              {},
	"vprintf":               {},
	"waitpid":               {},
	"write":                 {},
}
