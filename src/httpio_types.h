//
// Created by Tony Lin on 2019/10/15.
//

#ifndef HTTP_IO_C_HTTPIO_TYPES_H
#define HTTP_IO_C_HTTPIO_TYPES_H

#include "map.h"
#include "http_parser.h"
#include <stdint.h>
#include <uv.h>

typedef map_str_t httpio_header_t;

typedef enum http_method httpio_method_t;

typedef struct {
    char *uri;
    char *body;

    httpio_method_t method;
    httpio_header_t headers;
} httpio_request_t;

typedef void (*httpio_request_handler)(httpio_method_t, httpio_request_t *);

typedef struct {
    httpio_request_t *request;
    char *last_header_field;
} httpio_request_parse_t;

typedef struct {
//    httpio_request_handler_map_t request_handler_maps[6];
    uv_tcp_t uv_server;
    http_parser *parser;
    httpio_request_parse_t tmp;
} httpio_t;


#endif //HTTP_IO_C_HTTPIO_TYPES_H
