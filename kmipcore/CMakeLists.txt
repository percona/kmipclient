cmake_minimum_required(VERSION 3.10.0)

project(kmipcore LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "src/*.cpp")
file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "include/kmipcore/*.hpp")

add_library(kmipcore STATIC ${SOURCES} ${HEADERS})

target_include_directories(kmipcore PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

set_property(TARGET kmipcore PROPERTY POSITION_INDEPENDENT_CODE ON)

install(
  TARGETS kmipcore
  EXPORT kmipclient
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)

install(DIRECTORY include/kmipcore DESTINATION include)

add_executable(kmip_core_test tests/test_core.cpp)
target_link_libraries(kmip_core_test PRIVATE kmipcore)
add_test(NAME kmip_core_test COMMAND kmip_core_test)

add_executable(kmip_parser_test tests/test_parsers.cpp)
target_link_libraries(kmip_parser_test PRIVATE kmipcore)
add_test(NAME kmip_parser_test COMMAND kmip_parser_test)

add_executable(kmip_serialization_buffer_test tests/test_serialization_buffer.cpp)
target_link_libraries(kmip_serialization_buffer_test PRIVATE kmipcore)
add_test(NAME kmip_serialization_buffer_test COMMAND kmip_serialization_buffer_test)

add_executable(kmip_secure_memory_test tests/test_secure_memory.cpp)
target_link_libraries(kmip_secure_memory_test PRIVATE kmipcore)
add_test(NAME kmip_secure_memory_test COMMAND kmip_secure_memory_test)
