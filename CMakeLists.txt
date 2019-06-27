cmake_minimum_required(VERSION 3.14)
project(http_parser C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_library(http_parser STATIC
        http_parser.c)
target_include_directories(http_parser
        PUBLIC ./)

add_executable(test test.c)
target_link_libraries(test PUBLIC http_parser)

add_executable(bench bench.c)
target_link_libraries(bench PUBLIC http_parser)

add_executable(url_parser contrib/url_parser.c)
target_link_libraries(url_parser PUBLIC http_parser)