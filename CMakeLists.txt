cmake_minimum_required(VERSION 3.10.0)

project(kmip CXX)

enable_testing()

option(WITH_ASAN "Enable AddressSanitizer for project build" OFF)

if(WITH_ASAN)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    set(_asan_compile_flags "-fsanitize=address -fno-omit-frame-pointer")
    set(_asan_link_flags "-fsanitize=address")

    string(APPEND CMAKE_CXX_FLAGS " ${_asan_compile_flags}")
    string(APPEND CMAKE_EXE_LINKER_FLAGS " ${_asan_link_flags}")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " ${_asan_link_flags}")
  else()
    message(FATAL_ERROR "WITH_ASAN=ON is supported only with Clang or GCC compilers")
  endif()
endif()

add_subdirectory(kmipcore)
add_subdirectory(kmipclient)

# Lets a downstream project consume an installed build with
# find_package(kmipclient), instead of just vendoring this repo with
# add_subdirectory(). kmipcore and kmipclient version independently (see
# their own *_version.hpp), but the installed package as a whole is
# versioned by kmipclient, the one EXPORT set it's all part of.
include(CMakePackageConfigHelpers)

set(KMIP_INSTALL_CMAKEDIR
    "lib/cmake/kmipclient"
    CACHE STRING "Installation directory for the kmipclient CMake package config files"
)

install(
  EXPORT kmipclient
  NAMESPACE kmipclient::
  FILE kmipclientTargets.cmake
  DESTINATION ${KMIP_INSTALL_CMAKEDIR}
)

configure_package_config_file(
  cmake/kmipclientConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/kmipclientConfig.cmake
  INSTALL_DESTINATION ${KMIP_INSTALL_CMAKEDIR}
)

# Tracks kmipclient/include/kmipclient/kmipclient_version.hpp.
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/kmipclientConfigVersion.cmake
  VERSION 0.3.0
  COMPATIBILITY SameMinorVersion
)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/kmipclientConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/kmipclientConfigVersion.cmake
  DESTINATION ${KMIP_INSTALL_CMAKEDIR}
)

find_package(Doxygen)

option(BUILD_DOCS "Build API documentation with Doxygen" ${DOXYGEN_FOUND})

if(BUILD_DOCS)
  if(NOT DOXYGEN_FOUND)
    message(FATAL_ERROR "BUILD_DOCS is ON but Doxygen was not found.")
  endif()

  configure_file(Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile COPYONLY)

  add_custom_target(doc
    COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM
  )

  # Make the 'doc' target depend on your build targets if necessary
  # add_dependencies(doc your_library your_executable)
else()
  message(STATUS "Doxygen not found or BUILD_DOCS=OFF, skipping documentation generation.")
endif()
