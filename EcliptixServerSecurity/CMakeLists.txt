cmake_minimum_required(VERSION 3.20)
project(EcliptixServerSecurity VERSION 1.0.0 LANGUAGES CXX)

# ============================================================================
# Compiler Configuration
# ============================================================================

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Cross-platform library output naming
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# ============================================================================
# Build Options
# ============================================================================

option(ECLIPTIX_SERVER_STATIC_LIBRARY "Build static library instead of shared" OFF)

# ============================================================================
# Dependencies
# ============================================================================

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# ============================================================================
# Compiler Flags for Security and Performance
# ============================================================================

# Security hardening flags
set(SECURITY_FLAGS
    -fstack-protector-strong
    -fPIE
    -fvisibility=hidden
    -D_FORTIFY_SOURCE=2
    -Wformat
    -Wformat-security
    -Wno-deprecated-declarations
)

# Performance and warning flags
set(WARNING_FLAGS
    -Wall
    -Wextra
    -Wpedantic
    -Wconversion
    -Wsign-conversion
    -Wcast-qual
    -Wcast-align
    -Wshadow
    -Wnull-dereference
    -Wdouble-promotion
    -Wmissing-include-dirs
)

# Apply flags to all targets
add_compile_options(${SECURITY_FLAGS} ${WARNING_FLAGS})

# Release-specific optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -flto -DNDEBUG)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# Debug flags
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-g -O0 -DDEBUG)
endif()

# ============================================================================
# Source Files
# ============================================================================

# Core implementation sources
set(ECLIPTIX_SERVER_SOURCES
    src/server_security.cpp
    src/openssl_wrapper.cpp
)

# Server API Headers
set(ECLIPTIX_SERVER_HEADERS
    include/ecliptix/server_security.h
)

# Internal Implementation Headers
set(ECLIPTIX_SERVER_INTERNAL_HEADERS
    include/internal/openssl_wrapper.hpp
    include/internal/sodium_wrapper.hpp
)

# All headers
set(ECLIPTIX_SERVER_ALL_HEADERS
    ${ECLIPTIX_SERVER_HEADERS}
    ${ECLIPTIX_SERVER_INTERNAL_HEADERS}
)

# ============================================================================
# Main Library Target
# ============================================================================

if(ECLIPTIX_SERVER_STATIC_LIBRARY)
    add_library(ecliptix_server_security STATIC ${ECLIPTIX_SERVER_SOURCES} ${ECLIPTIX_SERVER_ALL_HEADERS})
    set_target_properties(ecliptix_server_security PROPERTIES OUTPUT_NAME ecliptix_server_security_static)
else()
    add_library(ecliptix_server_security SHARED ${ECLIPTIX_SERVER_SOURCES} ${ECLIPTIX_SERVER_ALL_HEADERS})
endif()

# Include directories
target_include_directories(ecliptix_server_security
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(ecliptix_server_security
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)

# Library properties
set_target_properties(ecliptix_server_security PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    PUBLIC_HEADER "${ECLIPTIX_SERVER_HEADERS}"
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    PREFIX ""  # Remove 'lib' prefix on Unix for consistency
)

# Platform-specific library naming
if(WIN32)
    set_target_properties(ecliptix_server_security PROPERTIES
        OUTPUT_NAME "ecliptix_server_security"
        SUFFIX ".dll"
    )
elseif(APPLE)
    set_target_properties(ecliptix_server_security PROPERTIES
        OUTPUT_NAME "libecliptix_server_security"
        SUFFIX ".dylib"
    )
else()
    set_target_properties(ecliptix_server_security PROPERTIES
        OUTPUT_NAME "libecliptix_server_security"
        SUFFIX ".so"
    )
endif()

# Define BUILDING_ECLIPTIX_SERVER when building the library
target_compile_definitions(ecliptix_server_security PRIVATE BUILDING_ECLIPTIX_SERVER)

# ============================================================================
# Export Definitions for DLL
# ============================================================================

# Generate export header for cross-platform DLL exports
include(GenerateExportHeader)
generate_export_header(ecliptix_server_security
    BASE_NAME ECLIPTIX_SERVER
    EXPORT_MACRO_NAME ECLIPTIX_SERVER_API
    EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/include/ecliptix/server_exports.h
)

target_include_directories(ecliptix_server_security PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
)

# ============================================================================
# Installation
# ============================================================================

# Install library
install(TARGETS ecliptix_server_security
    EXPORT EcliptixServerSecurityTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/ecliptix
)

# Install all headers with proper structure
install(DIRECTORY include/ecliptix/
    DESTINATION include/ecliptix
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/ecliptix/server_exports.h
    DESTINATION include/ecliptix
)

# Export configuration
install(EXPORT EcliptixServerSecurityTargets
    FILE EcliptixServerSecurityTargets.cmake
    NAMESPACE EcliptixServer::
    DESTINATION lib/cmake/EcliptixServerSecurity
)

# ============================================================================
# Status Summary
# ============================================================================

message(STATUS "")
message(STATUS "==========================================")
message(STATUS "Ecliptix Server Security Library Configuration")
message(STATUS "==========================================")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
if(ECLIPTIX_SERVER_STATIC_LIBRARY)
    message(STATUS "Library type: STATIC")
else()
    message(STATUS "Library type: SHARED")
endif()
message(STATUS "OpenSSL: ${OPENSSL_VERSION}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "==========================================")
message(STATUS "")