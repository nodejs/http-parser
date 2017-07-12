cmake_minimum_required(VERSION 3.3 FATAL_ERROR)
project(http_parser)

add_library(http_parser SHARED http_parser.c)
target_compile_options(http_parser PUBLIC -Wall -Wextra -Werror)
target_include_directories(http_parser PUBLIC .)

add_executable(bench bench.c)
target_compile_options(http_parser PUBLIC -Wno-unused-parameter)
target_link_libraries(bench http_parser)

add_executable(test_http_parser test.c)
target_link_libraries(test_http_parser http_parser)

add_executable(parsertrace contrib/parsertrace.c)
target_link_libraries(parsertrace http_parser)

add_executable(url_parser contrib/url_parser.c)
target_link_libraries(url_parser http_parser)
