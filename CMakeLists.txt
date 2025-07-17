set(SCAN_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/aead
    ${CMAKE_CURRENT_SOURCE_DIR}/src/codec
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ec
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash
    ${CMAKE_CURRENT_SOURCE_DIR}/src/int
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kdf
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mac
    ${CMAKE_CURRENT_SOURCE_DIR}/src/rand
    ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ssl
    ${CMAKE_CURRENT_SOURCE_DIR}/src/symcipher
    ${CMAKE_CURRENT_SOURCE_DIR}/src/x509
)

set(ALL_C_SOURCES "")         # will hold every *.c we find

foreach(dir IN LISTS SCAN_DIRS)
    message(STATUS "Scanning directory: ${dir}")
    file(GLOB dir_srcs CONFIGURE_DEPENDS
     "${dir}/*.c") 
    # or:  "${dir}/**/*.c"  for recursive scan (CMake ≥3.12)

    list(APPEND ALL_C_SOURCES ${dir_srcs})
endforeach()

message(STATUS "BearSSL sources: ${ALL_C_SOURCES}")

set(TLS_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/
    ${CMAKE_CURRENT_SOURCE_DIR}/src/
)

add_smack_target(bearssl_test
    ENTRY_POINT br_sslio_write_all_wrapper
    INCLUDE_DIRS
        ${TLS_INCLUDE_DIRS}
    SOURCES
        bearssl_test_harness.c
        ${ALL_C_SOURCES}
)

add_executable(bearssl_test_native bearssl_test_harness.c ${ALL_C_SOURCES})
target_include_directories(bearssl_test_native
    PRIVATE                   # visible only while building this target
        ${CMAKE_CURRENT_SOURCE_DIR}/inc      # your own headers
        ${CMAKE_CURRENT_SOURCE_DIR}/src/
)
target_compile_definitions(bearssl_test_native
    PRIVATE              # only while compiling this target
    TEST             # expands to ‘-DTEST’
    COMPILE
)
target_compile_options(bearssl_test_native PRIVATE
    $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang>>:
        -Werror=implicit-function-declaration
    >
)

add_executable(bearssl_server_native ${CMAKE_CURRENT_SOURCE_DIR}/samples/server_basic.c ${ALL_C_SOURCES})
target_include_directories(bearssl_server_native
    PRIVATE                   # visible only while building this target
        ${CMAKE_CURRENT_SOURCE_DIR}/inc      # your own headers
        ${CMAKE_CURRENT_SOURCE_DIR}/src/
)
target_compile_options(bearssl_server_native PRIVATE
    $<$<AND:$<COMPILE_LANGUAGE:C>,$<C_COMPILER_ID:GNU,Clang>>:
        -Werror=implicit-function-declaration
    >
)