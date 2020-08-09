add_executable(no main.c)
target_link_libraries(no libno)

add_custom_target(manpage
  ALL
  DEPENDS no.1.gz)
add_custom_command(
  OUTPUT no.1.gz
  COMMAND gzip -9 --no-name --to-stdout no.1 >"${CMAKE_CURRENT_BINARY_DIR}/no.1.gz"
  MAIN_DEPENDENCY no.1
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

install(TARGETS no
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/no.1.gz
  DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
