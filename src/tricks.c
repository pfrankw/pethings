#include "peutils/tricks.h"


/* __attribute__((always_inline)) */
void* peutils_find_gpa(void* k32){
  void *exports = 0, *k = 0;
  uint32_t *pfn = 0;
  //void *ret;
  uint32_t *pfn_names = 0;
  uint16_t *pfn_names_ord = 0;
  uint32_t nfn = 0, ifn = 0; /* Function number */
  char str_GetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };

  k = k32 + *((uint32_t*)(k32 + 0x3C));
  if( *(uint8_t*)(k) != 'P' || *(uint8_t*)(k+1) != 'E' )
    return 0;
  exports = k32 + *((uint32_t*)(k + 0x78));
  nfn = *(uint32_t*)(exports+0x14);
  pfn = k32 + *(uint32_t*)(exports+0x1C);
  pfn_names = k32 + *(uint32_t*)(exports+0x20);
  pfn_names_ord = k32 + *(uint32_t*)(exports+0x24);

  for(ifn=0; ifn<nfn; ifn++){
    int i = 0;
    char *pfn_name = k32 + pfn_names[ifn];
    while( pfn_name[i] != 0 && str_GetProcAddress[i] != 0 && pfn_name[i] == str_GetProcAddress[i] ){
      i++;
    }
    if( i == 14 ){
      return k32 + pfn[pfn_names_ord[ifn]];
    }
  }

  return 0;
}
void peutils_find_gpa_end(){}

void* peutils_find_kernel32(){
  void* ret;
/*
  asm(
    "mov rax, [fs:0x60];"
    "mov rax, [rax+0x18];"
    "mov rax, [rax+0x20];"
    "mov rax, [rax];"
    "mov rax, [rax];"
    "mov %0, [rax+0x20];"
    : "=r"(ret)
  );
*/
  asm (
    "push ebx;"
    "mov ebx, [fs:0x30];"
    "mov ebx, [ebx+0xC];"
    "mov ebx, [ebx+0x14];"
    "mov ebx, [ebx];"
    "mov ebx, [ebx];"
    "mov %0, [ebx+0x10];"
    "pop ebx;"
    : "=r"(ret)
  );

  return ret;
}
void peutils_find_kernel32_end(){}
