cmake_minimum_required(VERSION 3.5)
project(http_io_c C)

set(CMAKE_C_STANDARD 11)

#add_library(http_io_c SHARED httpio.c httpio.h)

add_executable(
        http.io
        src/httpio.c
        src/httpio.h
        src/httpio_types.h
        src/map.c
        src/map.h
        src/http_parser.c
        src/http_parser.h
        src/uri_tree.c
        src/uri_tree.h
        src/list.c src/list.h)

target_link_libraries(
        http.io
        uv
)