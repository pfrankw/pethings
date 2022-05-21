#ifndef PEUTILS_RUNPE_H
#define PEUTILS_RUNPE_H

#define UNICODE

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>


#include <peutils/tricks.h>

typedef LONG (WINAPI * _NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef FARPROC (WINAPI *_GetProcAddress)( HMODULE hModule, LPCSTR  lpProcName );
typedef BOOL (WINAPI *_CreateProcess)( LPWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                      BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPWSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation );
typedef LPVOID (WINAPI *_VirtualAlloc)( LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect );
typedef LPVOID (WINAPI *_VirtualAllocEx)( HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect );
typedef BOOL (WINAPI *_ReadProcessMemory)( HANDLE  hProcess, LPCVOID lpBaseAddress, LPVOID  lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesRead );
typedef BOOL (WINAPI *_WriteProcessMemory)( HANDLE  hProcess, LPVOID  lpBaseAddress, LPCVOID lpBuffer, SIZE_T  nSize, SIZE_T  *lpNumberOfBytesWritten );

typedef HMODULE (WINAPI *_GetModuleHandle)( LPCTSTR lpModuleName );

typedef BOOL (WINAPI *_GetThreadContext)( HANDLE hThread, LPCONTEXT lpContext );
typedef BOOL (WINAPI *_SetThreadContext)( HANDLE  hThread, const CONTEXT *lpContext );
typedef DWORD (WINAPI *_ResumeThread)( HANDLE hThread );
typedef BOOL (WINAPI *_TerminateProcess)( HANDLE hProcess, UINT uExitCode );




HANDLE peutils_runpe( wchar_t *path, wchar_t *cmdline, wchar_t *cwd, void *k32, void *gpa, void *pefile );
void peutils_runpe_end();

#endif
