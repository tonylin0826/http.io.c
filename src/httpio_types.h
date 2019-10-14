//
// Created by Tony Lin on 2019/10/15.
//

#ifndef HTTP_IO_C_HTTPIO_TYPES_H
#define HTTP_IO_C_HTTPIO_TYPES_H

#include "map.h"
#include <stdint.h>
#include <evhttp.h>


typedef enum {
    GET,
    POST,
    PUT,
    DELETE,
    OPTION,
    HEAD
} httpio_method_t;

typedef struct {
    httpio_method_t method;
    const char *uri;
    const char *body;
} httpio_request_t;

typedef void (*httpio_request_handler)(httpio_method_t, httpio_request_t *);

typedef map_t(httpio_request_handler) httpio_request_handler_map_t;

typedef struct {
    httpio_request_handler_map_t request_handler_maps[6];
    struct evhttp *ev_http;
} httpio_t;


#endif //HTTP_IO_C_HTTPIO_TYPES_H
