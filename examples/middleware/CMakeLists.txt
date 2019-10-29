
add_executable(
        http.io.middleware
        ../../src/httpio.c
        ../../src/httpio.h
        ../../src/httpio_types.h
        ../../src/map.c
        ../../src/map.h
        ../../src/http_parser.c
        ../../src/http_parser.h
        ../../src/uri_tree.c
        ../../src/uri_tree.h
        ../../src/list.c
        ../../src/list.h
        middleware.c)

target_link_libraries(
        http.io.middleware
        uv
)