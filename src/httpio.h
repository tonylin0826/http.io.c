#ifndef HTTP_IO_C_HTTPIO_H
#define HTTP_IO_C_HTTPIO_H

#include "httpio_types.h"
#include "uri_tree.h"

#include <stdint.h>

#define httpio_header_set(m, key, value) map_set(m, key, value)

typedef struct {
//    httpio_request_handler_map_t request_handler_maps[6];
    uv_tcp_t uv_server;
    http_parser *parser;
    httpio_request_parse_t tmp;
    uri_tree_t *uri_tree[8];
} httpio_t;

httpio_t *httpio_init();

void httpio_add_route(httpio_t *io, httpio_method_t method, const char *uri, httpio_request_handler_t handler);

int httpio_listen(httpio_t *io, const char *ip, int port);

void httpio_destroy(httpio_t **io);

#endif //HTTP_IO_C_HTTPIO_H