add_executable(no main.c)
target_link_libraries(no libno)

install(TARGETS no
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
