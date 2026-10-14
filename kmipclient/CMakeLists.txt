cmake_minimum_required(VERSION 3.10.0)
project(kmipclient)

# Have to put these 2 lines here to compile
set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_library(
  kmipclient
  STATIC
  include/kmipclient/KmipClient.hpp
  src/KmipClient.cpp
  include/kmipclient/KmipClientPool.hpp
  src/KmipClientPool.cpp
  include/kmipclient/NetClient.hpp
  src/NetClientOpenSSL.cpp
  include/kmipclient/NetClientOpenSSL.hpp
  include/kmipclient/types.hpp
  src/IOUtils.cpp
  src/IOUtils.hpp
  include/kmipclient/Kmip.hpp
  src/Key.cpp
  src/SymmetricKey.cpp
  src/PublicKey.cpp
  src/PrivateKey.cpp
  src/X509Certificate.cpp
  include/kmipclient/Key.hpp
  include/kmipclient/KeyBase.hpp
  include/kmipclient/SymmetricKey.hpp
  include/kmipclient/PublicKey.hpp
  include/kmipclient/PrivateKey.hpp
  include/kmipclient/X509Certificate.hpp
)

target_include_directories(
  kmipclient PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)

target_link_libraries(kmipclient PUBLIC kmipcore OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
if(WIN32)
  target_link_libraries(kmipclient PUBLIC ws2_32)
endif()

set_property(TARGET kmipclient PROPERTY POSITION_INDEPENDENT_CODE ON)

target_compile_features(kmipclient INTERFACE cxx_std_20)

set_target_properties(
  kmipclient
  PROPERTIES
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)

option(WITH_ASAN "Enable Address Sanitizer" OFF)
if(WITH_ASAN)
  target_compile_options(kmipclient PUBLIC "-fsanitize=address" "-fno-omit-frame-pointer")
  target_link_options(kmipclient PUBLIC "-fsanitize=address")
endif()

export(TARGETS kmipcore kmipclient FILE "kmipclient.cmake")

install(
  TARGETS kmipclient
  EXPORT kmipclient
  DESTINATION cmake
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include/
  LIBRARY DESTINATION lib
)

macro(add_example name)
  add_executable(example_${name} examples/example_${name}.cpp)
  target_link_libraries(example_${name} PRIVATE kmipclient)
endmacro()

add_example(create_aes)
add_example(register_secret)
add_example(activate)
add_example(get)
add_example(get_tls_verify)
add_example(get_logger)
add_example(get_name)
add_example(get_secret)
add_example(revoke)
add_example(destroy)
add_example(register_key)
# Generates the key it registers locally.
target_link_libraries(example_register_key PRIVATE kmiputil)
add_example(locate)
add_example(locate_by_group)
add_example(get_all_ids)
add_example(get_attributes)
add_example(pool)
add_example(supported_versions)
add_example(query_server_info)

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
    kmipclient_test
    tests/IOUtilsTest.cpp
    tests/KmipClientIntegrationTest.cpp
    tests/KmipClientIntegrationTest_2_0.cpp
    tests/KmipClientPoolIntegrationTest.cpp
  )

  target_link_libraries(
    kmipclient_test
    PRIVATE
    GTest::gtest_main
    kmipclient
    # Integration tests build AES keys with kmiputil::KeyReader.
    kmiputil
  )

  include(GoogleTest)
  gtest_discover_tests(kmipclient_test)
endif()
