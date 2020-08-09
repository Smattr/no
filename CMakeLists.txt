cmake_minimum_required(VERSION 3.2)
project(no C)

# this seems to be some magic to get libraries to install correctly
include(GNUInstallDirs)

add_compile_options(-std=c99 -pedantic -Wall -Wextra -Wwrite-strings -Wmissing-declarations -Wshadow)
add_definitions (-D_DEFAULT_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE)

# enable --as-needed, present on GNU ld on Linux, to minimise dependencies
if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--as-needed")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--as-needed")
endif()

add_subdirectory(libno)
add_subdirectory(no)

enable_testing()
add_test(integration env PATH=${CMAKE_CURRENT_BINARY_DIR}/no:$ENV{PATH} python3 ${CMAKE_CURRENT_SOURCE_DIR}/test/test.py)
