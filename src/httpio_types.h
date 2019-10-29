//
// Created by Tony Lin on 2019/10/15.
//

#ifndef HTTP_IO_C_HTTPIO_TYPES_H
#define HTTP_IO_C_HTTPIO_TYPES_H

#include "map.h"
#include "http_parser.h"

#include <stdint.h>
#include <stdbool.h>
#include <uv.h>

typedef map_str_t httpio_header_t;
typedef map_str_t httpio_param_t;
typedef map_str_t httpio_query_t;

typedef enum http_method httpio_method_t;
typedef enum http_status httpio_status_t;

#define MIDDLEWARE_STATUS(XX)   \
  XX(0,  NEXT,      NEXT)   \
  XX(1,  DONE,      DONE)

typedef enum middleware_status {
#define XX(num, name, string) MIDDLEWARE_STATUS_##name = num,
    MIDDLEWARE_STATUS(XX)
#undef XX
} middleware_status_t;

typedef struct {
    char *uri;
    char *body;

    httpio_method_t method;
    httpio_header_t headers;
    httpio_param_t params;
    httpio_query_t queries;

    // tmp
    bool is_responsed;

    // uv data
    uv_stream_t *uv_client;
    uv_timer_t *uv_timer;

    char *tmp_body_finger;
    void *data;
} httpio_request_t;

typedef struct {
    httpio_status_t status;
    httpio_header_t headers;

    char *body;
} httpio_response_t;

typedef void (*httpio_request_handler_t)(httpio_request_t *);

typedef middleware_status_t (*httpio_middleware_t)(httpio_request_t *);

typedef struct {
    uv_stream_t *client;
    httpio_request_t *request;
    char *last_header_field;
    http_parser *parser;

    void *data; // point to httpio
} httpio_client_info_t;


#endif //HTTP_IO_C_HTTPIO_TYPES_H
