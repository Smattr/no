cmake_minimum_required(VERSION 3.2)
project(box C)

# this seems to be some magic to get libraries to install correctlyd
include(GNUInstallDirs)

add_compile_options(-std=c99 -ansi -pedantic -Wall -Wextra -Wwrite-strings -Wmissing-declarations -Wshadow)

# enable --as-needed, present on GNU ld on Linux, to minimise dependencies
if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")
  set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--as-needed")
endif ()

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
  set(DEPRIVILEGE_C deprivilege-macos.c)
else()
  message(FATAL_ERROR sandboxing not implemented for this platform)
endif()

add_executable(box main.c ${DEPRIVILEGE_C})
install(TARGETS box RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
