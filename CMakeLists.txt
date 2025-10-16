cmake_minimum_required(VERSION 3.10)
project(PSI_Cpp)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

enable_testing()

# Include directories
include_directories(${PROJECT_SOURCE_DIR}/src)

# Add source files
set(SOURCE_FILES
    src/main.cpp
    src/crypto_utils.cpp
    src/blake3_utils.cpp
    src/chacha_utils.cpp
    src/random_utils.cpp
    src/position_utils.cpp
    src/psi_protocol.cpp
    src/serialization_utils.cpp
)

# Main executable
add_executable(psi ${SOURCE_FILES})

add_executable(psi_demo
    tools/psi_demo.cpp
    src/psi_protocol.cpp
    src/position_utils.cpp
    src/random_utils.cpp
    src/crypto_utils.cpp
    src/chacha_utils.cpp
    src/blake3_utils.cpp
    src/serialization_utils.cpp
)

add_executable(psi_server
    tools/psi_server.cpp
    src/psi_protocol.cpp
    src/position_utils.cpp
    src/random_utils.cpp
    src/crypto_utils.cpp
    src/chacha_utils.cpp
    src/blake3_utils.cpp
    src/serialization_utils.cpp
)

# BLAKE3 library
add_library(blake3 STATIC
    third_party/blake3/blake3.c
    third_party/blake3/blake3_dispatch.c
    third_party/blake3/blake3_portable.c
)
target_compile_definitions(blake3 PRIVATE
    BLAKE3_NO_SSE2
    BLAKE3_NO_SSE41
    BLAKE3_NO_AVX2
    BLAKE3_NO_AVX512
)
target_include_directories(blake3 PUBLIC ${PROJECT_SOURCE_DIR}/third_party/blake3)

# libsodium discovery
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY sodium)

if (NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found. Please install libsodium development files.")
endif()

add_library(sodium_external INTERFACE)
target_include_directories(sodium_external INTERFACE ${SODIUM_INCLUDE_DIR})
target_link_libraries(sodium_external INTERFACE ${SODIUM_LIBRARY})

# Link libraries
find_package(OpenSSL REQUIRED)
target_link_libraries(psi OpenSSL::SSL OpenSSL::Crypto sodium_external blake3)
target_link_libraries(psi_demo OpenSSL::SSL OpenSSL::Crypto sodium_external blake3)
target_link_libraries(psi_server OpenSSL::SSL OpenSSL::Crypto sodium_external blake3)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GTEST REQUIRED gtest_main)

set(TEST_SOURCES
    tests/crypto_utils_test.cpp
    tests/random_utils_test.cpp
    tests/position_utils_test.cpp
    tests/psi_protocol_test.cpp
    tests/serialization_utils_test.cpp
    src/crypto_utils.cpp
    src/chacha_utils.cpp
    src/blake3_utils.cpp
    src/random_utils.cpp
    src/position_utils.cpp
    src/psi_protocol.cpp
    src/serialization_utils.cpp
)

add_executable(psi_tests ${TEST_SOURCES})
target_include_directories(psi_tests PRIVATE ${GTEST_INCLUDE_DIRS})
target_link_libraries(psi_tests
    PRIVATE
        ${GTEST_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
        sodium_external
        blake3
        pthread
)

add_test(NAME psi_tests COMMAND psi_tests)
