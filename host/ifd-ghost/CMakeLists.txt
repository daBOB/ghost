# SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
# SPDX-License-Identifier: GPL-3.0-only

# ghost's PC/SC reader driver (ifd_ghost.c), which the session's own pcscd
# loads for the client's forwarded smart card readers (gdp-spec.md §8.8).
# Needs pcsc-lite's driver headers (`apt install libpcsclite-dev`); without
# them neither it nor wraith's smart card forwarding is built.
find_path(GHOST_PCSC_IFD_INCLUDE PCSC/ifdhandler.h)
if(NOT GHOST_PCSC_IFD_INCLUDE)
  message(STATUS "ifd-ghost: no PCSC/ifdhandler.h, so no smart card forwarding (apt install libpcsclite-dev)")
  return()
endif()

find_package(Threads REQUIRED)
add_library(ifd-ghost MODULE ifd_ghost.c)
target_include_directories(ifd-ghost PRIVATE "${GHOST_PCSC_IFD_INCLUDE}" "${GHOST_PCSC_IFD_INCLUDE}/PCSC")
target_link_libraries(ifd-ghost PRIVATE Threads::Threads)
target_compile_options(ifd-ghost PRIVATE -Wall -Wextra)
set_target_properties(ifd-ghost PROPERTIES
  C_VISIBILITY_PRESET default
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/ghost/pcsc")

# wraith writes this path into pcscd's reader configuration.
set(GHOST_IFD_DRIVER_PATH "${CMAKE_INSTALL_PREFIX}/lib/ghost/pcsc/libifd-ghost.so" CACHE INTERNAL "")
install(TARGETS ifd-ghost LIBRARY DESTINATION lib/ghost/pcsc)

# The driver against a fake wraith, with no card and no pcscd.
add_executable(ifd_ghost_test tests/ifd_ghost_test.c ifd_ghost.c)
target_include_directories(ifd_ghost_test PRIVATE "${GHOST_PCSC_IFD_INCLUDE}" "${GHOST_PCSC_IFD_INCLUDE}/PCSC" "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(ifd_ghost_test PRIVATE Threads::Threads)
add_test(NAME ifd_ghost_test COMMAND ifd_ghost_test)
