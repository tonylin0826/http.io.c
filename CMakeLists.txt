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

set_target_properties(http.io PROPERTIES
        PUBLIC_HEADER "src/httpio.h;src/list.h;src/uri_tree.h;src/map.h;src/httpio.h;src/httpio_types.h")

target_link_libraries(
        http.io
        uv
)

install(TARGETS http.io
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib/static
        PUBLIC_HEADER DESTINATION include
)

add_subdirectory(examples)