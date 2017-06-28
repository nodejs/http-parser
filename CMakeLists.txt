project(http-parser C)

# Required CMake version
cmake_minimum_required(VERSION 2.8)

set(http-parser_MAJOR_VERSION 2)
set(http-parser_MINOR_VERSION 7)
set(http-parser_PATCH_VERSION 1)
set(http-parser_VERSION
    ${http-parser_MAJOR_VERSION}.${http-parser_MINOR_VERSION}.${http-parser_PATCH_VERSION})

# Module search path
set(CMAKE_MODULE_PATH
    ${CMAKE_SOURCE_DIR}/cmake
)

# Some CMake configuration
set(CMAKE_COLOR_MAKEFILE ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE ON)

# Default to release builds w/ debug info
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif (NOT CMAKE_BUILD_TYPE)

# Define the public include directory
set(http-parser_PUBLIC_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}
    CACHE INTERNAL "http parser public include directories"
)

# Shared library target
set(http-parser_SHARED_LIBRARY
    http_parser
    CACHE INTERNAL "http-parser shared library"
)

# Static library target
set(http-parser_STATIC_LIBRARY
    http_parser_s
    CACHE INTERNAL "http-parser static library"
)

# Source translation units
set(http-parser_SRCS
    http_parser.c
)

include_directories(
    .
)

# Main library targets
add_library(${http-parser_SHARED_LIBRARY} SHARED ${http-parser_SRCS})
add_library(${http-parser_STATIC_LIBRARY} STATIC ${http-parser_SRCS})
if(NOT WIN32)
    # Windows needs separate names, but other platforms do not.
    set_target_properties(http_parser_s PROPERTIES OUTPUT_NAME http_parser)
endif(NOT WIN32)

# Version
set_target_properties(${http-parser_SHARED_LIBRARY} PROPERTIES VERSION
    ${http-parser_VERSION})
set_target_properties(${http-parser_STATIC_LIBRARY} PROPERTIES VERSION
    ${http-parser_VERSION})

# Installation
install(TARGETS
    ${http-parser_SHARED_LIBRARY}
    ${http-parser_STATIC_LIBRARY}
    DESTINATION lib
    EXPORT http-parser-targets)
install(EXPORT http-parser-targets DESTINATION lib)

install(FILES
    http_parser.h
    DESTINATION include)
