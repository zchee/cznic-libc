#include "_cgo_export.h"

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
