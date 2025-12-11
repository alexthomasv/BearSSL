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

add_smack_target(bearssl_test_decrypt
    ENTRY_POINT decrypt_wrapper
    INCLUDE_DIRS
        ${TLS_INCLUDE_DIRS}
    SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/decrypt.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_modpow2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_fmont.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_decode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_mulacc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_ninv15.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_montmul.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_sub.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_rshift.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_decred.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_bitlen.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/codec/ccopy.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_encode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_reduce.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_tmont.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_add.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_muladd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa/rsa_i15_priv.c)


add_smack_target(bearssl_test_pkcs1_i15
    ENTRY_POINT sign_wrapper
    INCLUDE_DIRS
        ${TLS_INCLUDE_DIRS}
    SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs_sign_i15.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_modpow2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_fmont.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_decode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_mulacc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_ninv15.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_montmul.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_sub.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_rshift.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_decred.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_bitlen.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/codec/ccopy.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_encode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_reduce.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_tmont.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_add.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i15_muladd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa/rsa_i15_priv.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa/rsa_i15_pkcs1_sign.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa/rsa_pkcs1_sig_pad.c)


add_smack_target(bearssl_test_pkcs1_i31
    ENTRY_POINT sign_wrapper
    INCLUDE_DIRS
        ${TLS_INCLUDE_DIRS}
    SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/pkcs_sign_i31.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_tmont.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_muladd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_add.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_reduce.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_fmont.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_ninv31.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_modpow2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_sub.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_mulacc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/codec/ccopy.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_decred.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i32_div32.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_rshift.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_bitlen.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_decode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_encode.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/int/i31_montmul.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa/rsa_i31_priv.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa/rsa_i31_pkcs1_sign.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rsa/rsa_pkcs1_sig_pad.c)

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