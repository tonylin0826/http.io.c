cmake_minimum_required(VERSION 3.5)
project(http_io_c C)

set(CMAKE_C_STANDARD 11)

#add_library(http_io_c SHARED httpio.c httpio.h)

add_executable(http.io src/httpio.c src/httpio.h src/httpio_types.h src/map.c src/map.h)

target_link_libraries(
        http.io
        event
)