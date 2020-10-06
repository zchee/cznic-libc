// +build !libc.cgo

#include "_cgo_export.h"
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

DWORD WINAPI __ccgo_thread_proc(LPVOID lpParameter)
{
	return __ccgo_thread_proc_cb((unsigned long long)lpParameter);
}

HANDLE
__ccgo_CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes,
		    SIZE_T dwStackSize,
		    unsigned long long obj,
		    DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	return CreateThread(lpThreadAttributes, dwStackSize, __ccgo_thread_proc,
			    (LPVOID) obj, dwCreationFlags, lpThreadId);
}
