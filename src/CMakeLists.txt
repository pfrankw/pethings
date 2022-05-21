cmake_minimum_required( VERSION 3.0 )

project( peutils_src )

SET( EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin )
SET( LIBRARY_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/lib )

include_directories( ../include /usr/local/include )

add_library ( peutils tricks.c runpe.c )
#target_link_libraries( peutils )

message( "CMAKE_C_FLAGS ${CMAKE_C_FLAGS}" )

SET( CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -mno-ms-bitfields -Wall -masm=intel" )
SET( CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG}" )
SET( CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -s" )

install( TARGETS peutils DESTINATION lib )
