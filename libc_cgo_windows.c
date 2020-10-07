// +build libc.cgo

#include <windows.h>

extern char **environ;

int __ccgo_errno() {
	return errno;
}

void *__ccgo_environ()
{
	return (void *)environ;
}

void *__ccgo_errno_location()
{
	return &errno;
}

unsigned __ccgo_getLastError()
{
	return GetLastError();
}
