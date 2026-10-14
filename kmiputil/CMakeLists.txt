cmake_minimum_required(VERSION 3.10.0)
project(kmiputil)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)

add_library(
  kmiputil
  STATIC
  include/kmiputil/KeyGenerator.hpp
  include/kmiputil/KeyReader.hpp
  include/kmiputil/KeyWriter.hpp
  src/AesKey.cpp
  src/AesKey.hpp
  src/Encoding.cpp
  src/Encoding.hpp
  src/KeyGenerator.cpp
  src/KeyReader.cpp
  src/KeyWriter.cpp
  src/OpenSSLUtils.hpp
)

target_include_directories(
  kmiputil PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(kmiputil PUBLIC kmipclient OpenSSL::Crypto)

set_property(TARGET kmiputil PROPERTY POSITION_INDEPENDENT_CODE ON)

target_compile_features(kmiputil INTERFACE cxx_std_20)

set_target_properties(
  kmiputil
  PROPERTIES
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)

export(TARGETS kmipcore kmipclient kmiputil FILE "kmiputil.cmake")

install(
  TARGETS kmiputil
  EXPORT kmipclient
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
)

install(DIRECTORY include/kmiputil DESTINATION include)

# Google Test integration
option(BUILD_TESTS "Build the tests" OFF)

if(BUILD_TESTS)
  if(NOT (TARGET gtest OR TARGET gmock))
    include(FetchContent)
    FetchContent_Declare(
      googletest
      GIT_REPOSITORY https://github.com/google/googletest.git
      GIT_TAG v1.14.0
    )

    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif()

  enable_testing()

  add_executable(
    kmiputil_test
    tests/EncodingTest.cpp
    tests/KeyGeneratorTest.cpp
    tests/KeyReaderTest.cpp
    tests/KeyWriterTest.cpp
  )

  # Tests also cover the internal encoding helpers.
  target_include_directories(kmiputil_test PRIVATE src)

  target_link_libraries(
    kmiputil_test
    PRIVATE
    GTest::gtest_main
    kmiputil
  )

  include(GoogleTest)
  gtest_discover_tests(kmiputil_test)
endif()
