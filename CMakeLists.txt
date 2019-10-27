cmake_minimum_required(VERSION 3.5)
project(http.io C)

set(CMAKE_C_STANDARD 11)

add_library(http.io SHARED
        src/httpio.c
        src/httpio.h
        src/httpio_types.h
        src/map.c
        src/map.h
        src/http_parser.c
        src/http_parser.h
        src/uri_tree.c
        src/uri_tree.h
        src/list.c
        src/list.h)

add_executable(
        http.io.comet
        src/httpio.c
        src/httpio.h
        src/httpio_types.h
        src/map.c
        src/map.h
        src/http_parser.c
        src/http_parser.h
        src/uri_tree.c
        src/uri_tree.h
        src/list.c
        src/list.h
        examples/comet.c)

add_executable(
        http.io.settimeout
        src/httpio.c
        src/httpio.h
        src/httpio_types.h
        src/map.c
        src/map.h
        src/http_parser.c
        src/http_parser.h
        src/uri_tree.c
        src/uri_tree.h
        src/list.c
        src/list.h
        examples/set_timeout.c)

target_link_libraries(
        http.io
        uv
)

target_link_libraries(
        http.io.comet
        uv
)

target_link_libraries(
        http.io.settimeout
        uv
)