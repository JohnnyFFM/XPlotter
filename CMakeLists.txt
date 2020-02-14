cmake_minimum_required(VERSION 3.16)

project(xplotter)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

enable_language(ASM_MASM)

set(ASM_SOURCES src/crypto/shabal/shabal.asm)

set_property(SOURCE ${ASM_SOURCES} PROPERTY ASM_MASM)

set(HEADERS_CRYPTO 
    src/crypto/shabal/shabal.h 
    src/crypto/mshabal/mshabal.h 
    src/crypto/mshabal/mshabal256.h
)

set(SOURCES_CRYPTO 
    src/crypto/mshabal/mshabal_avx1.c 
    src/crypto/mshabal/mshabal_avx2.c 
    src/crypto/mshabal/mshabal_sse4.c 
    src/crypto/mshabal/mshabal256_avx2.c 
    ${ASM_SOURCES}
)

set(HEADERS 
    src/CpuInfo.h 
    src/Nonce.h
)

set(SOURCES 
    src/main.cpp
    src/CpuInfo.cpp 
    src/Nonce.cpp 
)

add_executable(${CMAKE_PROJECT_NAME} ${HEADERS} ${SOURCES} ${HEADERS_CRYPTO} ${SOURCES_CRYPTO})
