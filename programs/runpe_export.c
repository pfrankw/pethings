#include <stdio.h>
#include <stdint.h>

#include <peutils/runpe.h>

void usage(){
  printf("Usage: runpe_export runpe_file\n");
  fflush(stdout);
  system("PAUSE");
  exit( -1 );
}

int main( int argc, char **argv ){

  int r = -1;
  FILE *fp;
  uint32_t runpe_len;

  if( argc != 2 )
    usage();

  fp = fopen( argv[1], "wb" );
  if( !fp )
    goto exit;

  runpe_len = (uint32_t) peutils_runpe_end - (uint32_t) peutils_runpe;
  printf("RunPE length: %u\n", runpe_len);
  if( fwrite( peutils_runpe, 1, runpe_len, fp ) != runpe_len )
    goto exit;

  r = 0;
 exit:
  if( fp ) fclose( fp );
  return r;
}
