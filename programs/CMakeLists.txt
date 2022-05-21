cmake_minimum_required( VERSION 3.0 )

project( peutils_programs )

SET( EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin )
SET( LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/lib )

include_directories( ../include /usr/local/include )
link_directories( LIBRARY_OUTPUT_PATH /usr/local/lib )

add_executable( runfile runfile.c )
add_executable( runpe_export runpe_export.c )

add_executable( sample sample.c )

add_executable( newrunpe newrunpe.c )

target_link_libraries( runfile peutils )
target_link_libraries( runpe_export peutils )

#-Wl,--dynamicbase,--export-all-symbols
#-Wl,--image-base=x
#SET( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--image-base=0x00400000")
SET( CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -mno-ms-bitfields -Wall -masm=intel -O0" )
SET( CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -g" )
SET( CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -s -static" )
