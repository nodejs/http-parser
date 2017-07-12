cmake_minimum_required(VERSION 3.3 FATAL_ERROR)
project(http_parser)

add_library(http_parser SHARED
    http_parser.c
)

target_include_directories(http_parser PUBLIC
    .
)
