cmake_minimum_required(VERSION 3.16)
project(scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(USE_SYSTEM_OPENSSL "Try to use system OpenSSL (if available)." ON)
option(OPENSSL_FETCH_IF_MISSING "Allow CMake to fetch OpenSSL if system OpenSSL is missing." ON)

if (MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Собираем все *.cpp / *.cxx в исходной директории, но НЕ из каталога сборки
file(GLOB_RECURSE ALL_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/*.cxx"
)

# Фильтруем: исключаем файлы из CMAKE_BINARY_DIR и CMakeFiles (сгенерированные)
set(PROJECT_SOURCES "")
file(REAL_PATH "${CMAKE_BINARY_DIR}" _BINARY_DIR_REAL)
foreach(_f IN LISTS ALL_SOURCES)
    file(REAL_PATH "${_f}" _f_real)
    string(FIND "${_f_real}" "${_BINARY_DIR_REAL}" _pos)
    if(_pos EQUAL -1)
        # также исключим любые сгенерированные CMake файлы по имени (на всякий случай)
        string(FIND "${_f_real}" "CMakeCXXCompilerId" _idpos)
        if(_idpos EQUAL -1)
            list(APPEND PROJECT_SOURCES "${_f_real}")
        endif()
    endif()
endforeach()

if (PROJECT_SOURCES STREQUAL "")
    message(FATAL_ERROR "No source files found (after filtering). Check your source tree.")
endif()

message(STATUS "Source files discovered (filtered):")
foreach(s ${PROJECT_SOURCES})
    message(STATUS "  ${s}")
endforeach()

add_executable(scanner ${PROJECT_SOURCES})
find_package(Threads REQUIRED)
target_link_libraries(scanner PRIVATE Threads::Threads)

target_include_directories(scanner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# OpenSSL handling (как раньше)
set(OpenSSL_ROOT_DIR "" CACHE PATH "Path to OpenSSL root (optional)")

if (USE_SYSTEM_OPENSSL)
    find_package(OpenSSL QUIET)
endif()

if (NOT OpenSSL_FOUND)
    if (OPENSSL_FETCH_IF_MISSING)
        message(STATUS "System OpenSSL not found — attempting to fetch/build OpenSSL as subproject.")
        include(FetchContent)
        FetchContent_Declare(
            openssl
            GIT_REPOSITORY https://github.com/openssl/openssl.git
            GIT_TAG OpenSSL_3_1_0
        )
        FetchContent_MakeAvailable(openssl)
        if (TARGET OpenSSL::Crypto)
            target_link_libraries(scanner PRIVATE OpenSSL::Crypto)
            target_compile_definitions(scanner PRIVATE USE_OPENSSL=1)
        else()
            find_package(OpenSSL REQUIRED)
            target_link_libraries(scanner PRIVATE OpenSSL::Crypto)
            target_compile_definitions(scanner PRIVATE USE_OPENSSL=1)
        endif()
    else()
        message(FATAL_ERROR "OpenSSL not found and fetching disabled. Install system OpenSSL or enable fetching.")
    endif()
else()
    message(STATUS "Found system OpenSSL: ${OPENSSL_VERSION}")
    target_link_libraries(scanner PRIVATE OpenSSL::Crypto)
    target_compile_definitions(scanner PRIVATE USE_OPENSSL=1)
endif()

install(TARGETS scanner RUNTIME DESTINATION bin)
