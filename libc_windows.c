// +build !libc.ccgo

#include <windows.h>

extern char **environ;

void *__ccgo_environ()
{
	return (void *)environ;
}

unsigned __ccgo_getLastError()
{
	return GetLastError();
}

void *__ccgo_errno_location()
{
	return &errno;
}
