cmake_minimum_required( VERSION 3.0 )

if( NOT CMAKE_BUILD_TYPE )
  set( CMAKE_BUILD_TYPE "RELEASE" )
endif()

message( "Current CMake build type is ${CMAKE_BUILD_TYPE}" )

project( peutils )

add_subdirectory( src )
add_subdirectory( programs )

install( DIRECTORY "${CMAKE_SOURCE_DIR}/include/peutils"
         DESTINATION include )
