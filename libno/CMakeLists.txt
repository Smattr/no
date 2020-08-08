project(libno LANGUAGES C)

add_library(libno
  include/no/no.h)

# TODO: add implementations for other platforms
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
  target_sources(libno PRIVATE src/macos/exec.c)
elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
  target_sources(libno PRIVATE src/linux/exec.c)
else()
  target_sources(libno PRIVATE src/stub/exec.c)
endif()

target_include_directories(libno
  PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
  PRIVATE
  src)

# force the output to libno.a instead of liblibno.a
set_target_properties(libno PROPERTIES PREFIX "")

# clagged boiler plate to install a library
install(TARGETS libno EXPORT LibnoConfig
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

export(TARGETS libno FILE LibnoConfig.cmake)
