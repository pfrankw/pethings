/* Quick n' Dirty File Decoder
 * Author: Grant Curell
 * Date: 3 August 2013
 * Code borrowed from:
 * http://securityxploded.com/memory-execution-of-executable.php
 * http://www.rohitab.com/discuss/topic/38986-execute-pe-file-on-virtual-memory/
 * Using a mix of my own code and code borrowed from the sources above the
 * decoder will take a file encoded with the encoder, decode it directly into
 * memory, and run it. It will also rebase the code as necessary if the
 * preferred base address isn't available.
 */

#include <windows.h>
#include <stdio.h>

#define DEREF_32( name )*(DWORD *)(name)
#define BLOCKSIZE 100

void fix_relocations(
	IMAGE_BASE_RELOCATION *base_reloc,
	DWORD dir_size,
	DWORD new_imgbase,
	DWORD old_imgbase);

int main(int argc, char **argv)
{
	char file[20] = "output.exe"; //Name of encoded file here
	char memblocktemp[BLOCKSIZE];
	int totalbytes = 0, relocate_diff;
	HANDLE handle;
	PVOID vpointer = NULL, memalloc = NULL;
	HINSTANCE laddress;
	LPSTR libname;
	DWORD size;
	DWORD EntryAddr;
	int state;
	DWORD byteread;
	PIMAGE_NT_HEADERS nt;
	PIMAGE_SECTION_HEADER section;
	DWORD dwValueA;
	DWORD dwValueB;
	DWORD dwValueC;
	DWORD dwValueD;
	DWORD dwValueE;

	// read the file
	printf("Reading file..\n");
	handle = CreateFile(argv[1],GENERIC_READ,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);

	// get the file size
	size = GetFileSize(handle,NULL);

	// Allocate the space
	vpointer = VirtualAlloc(NULL,size,MEM_COMMIT,PAGE_READWRITE);

	// read file on the allocated space
	state = ReadFile(handle,vpointer,size,&byteread,NULL);

	CloseHandle(handle);

	// read NT header of the file
	nt = (PIMAGE_NT_HEADERS)((PCHAR)(vpointer) + ((PIMAGE_DOS_HEADER)vpointer)->e_lfanew);
	handle = GetCurrentProcess();

	// Allocate the space with Imagebase as a desired address allocation request
	memalloc = VirtualAllocEx(
		handle,
		(PVOID)(nt->OptionalHeader.ImageBase),
		nt->OptionalHeader.SizeOfImage,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
		);
	//Rebase as needed
	//Also make sure that a relocation section exists
	if(memalloc==NULL &&
		nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		memalloc = VirtualAllocEx(
			handle,
			NULL,
			nt->OptionalHeader.SizeOfImage,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
			);
	else {
		printf("Executable does not have a relocation section! Cannot rebase.\n");
		system("pause");
		exit(0);
	}

	//Get difference between base and relocated address
	//relocate_diff = (DWORD)memalloc - nt->OptionalHeader.ImageBase;

	// get VA of entry point
	EntryAddr = (DWORD)memalloc + nt->OptionalHeader.AddressOfEntryPoint;

	DWORD error = GetLastError();

	// Write headers on the allocated space
	WriteProcessMemory(
		handle,
		memalloc,
		vpointer,
		nt->OptionalHeader.SizeOfHeaders,
		NULL
		);

	// write sections on the allocated space
	section = IMAGE_FIRST_SECTION(nt);
	for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		//if(i<nt->FileHeader.NumberOfSections)
		//	break;
		WriteProcessMemory(
			handle,
			(PCHAR)(memalloc) + section[i].VirtualAddress,
			(PCHAR)(vpointer) + section[i].PointerToRawData,
			section[i].SizeOfRawData,
			0
			);
	}

	// read import dirctory
	dwValueB = (DWORD) &(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);

	// get the VA
	dwValueC = (DWORD)memalloc +
		((PIMAGE_DATA_DIRECTORY)dwValueB)->VirtualAddress;


	while(((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->Name)
	{
		// get DLL name
		libname = (LPSTR)((DWORD)memalloc +
			((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->Name);

		// Load dll
		laddress = LoadLibrary(libname);

		// get first thunk, it will become our IAT
		dwValueA = (DWORD)memalloc +
			((PIMAGE_IMPORT_DESCRIPTOR)dwValueC)->FirstThunk;

		// resolve function addresses
		while(DEREF_32(dwValueA))
		{
			dwValueD = (DWORD)memalloc + DEREF_32(dwValueA);
			// get function name
			LPSTR Fname = (LPSTR)((PIMAGE_IMPORT_BY_NAME)dwValueD)->Name;
			// get function addresses
			DEREF_32(dwValueA) = (DWORD)GetProcAddress(laddress,Fname);
			dwValueA += 4;
		}

		dwValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );

	}

	//Rebase the executable as needed in memory
	fix_relocations(
		(PIMAGE_BASE_RELOCATION)((DWORD)memalloc + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
		nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
		(DWORD)memalloc,
		nt->OptionalHeader.ImageBase);

	// call the entry point :: here we assume that everything is ok.
	((void(*)(void))EntryAddr)();

}

/* void fix_relocations
 * Function for rebasing a program to a new image base
 * IMAGE_BASE_RELOCATION *base_reloc - The relocation section of the image to be used
 * DWORD relocation_size - Size of the relocation section
 * DWORD new_imgbase - Location in memory of the new image base
 * DWORD old_imgbase - Location in memory of the old image base
 */
void fix_relocations(IMAGE_BASE_RELOCATION *base_reloc, DWORD relocation_size, DWORD new_imgbase, DWORD old_imgbase)
{
    IMAGE_BASE_RELOCATION *cur_reloc = base_reloc, *reloc_end;

	//Calculate the difference between the old image base and the new
    DWORD delta = new_imgbase - old_imgbase;

	//Calculate the end of the relocation section
    reloc_end = (PIMAGE_BASE_RELOCATION)((char *)base_reloc + relocation_size);

	//Loop through the IMAGE_BASE_RELOCATION structures
    while (cur_reloc < reloc_end && cur_reloc->VirtualAddress) {

		//Determine the number of relocations in this IMAGE_BASE_RELOCATION structure
        DWORD count = (cur_reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		//Grab the current relocation entry. The plus one is to account for the loop below
        WORD *cur_entry = (WORD *)(cur_reloc + 1);

		//Grab the address in new memory where the relocation will occur
        void *page_va = (void *)((char *)new_imgbase + cur_reloc->VirtualAddress);

		//Loop through each of the relocations in the current IMAGE_BASE_RELOCATION structure
        while (count--) {

            /* is valid x86 relocation? */
            if (*cur_entry >> 12 == IMAGE_REL_BASED_HIGHLOW)
				//Add the delta. The 0x0fff ands out the type of relocation
                *(DWORD *)((char *)page_va + (*cur_entry & 0x0fff)) += delta;

			//Move to the next entry
            cur_entry++;

        }

        /* advance to the next one */
        cur_reloc = (IMAGE_BASE_RELOCATION *)((char *)cur_reloc + cur_reloc->SizeOfBlock);

    }

}
