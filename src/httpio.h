#ifndef HTTP_IO_C_HTTPIO_H
#define HTTP_IO_C_HTTPIO_H

#include "httpio_types.h"
#include "uri_tree.h"

#include <stdint.h>

#define httpio_header_set(m, key, value) map_set(m, key, value)

typedef void (*httpio_timeout_cb_t)(void *data);

typedef struct {
    uv_tcp_t uv_server;
    uri_tree_t *uri_tree[8];
} httpio_t;

httpio_t *httpio_init();

void httpio_use(httpio_t *io, httpio_method_t method, const char *uri, httpio_middleware_t middleware);

void httpio_add_route(httpio_t *io, httpio_method_t method, const char *uri, httpio_request_handler_t handler);

int httpio_listen(httpio_t *io, const char *ip, int port);

void httpio_init_response(httpio_response_t *response);

void httpio_deinit_response(httpio_response_t *response);

void httpio_set_timout(uint64_t time_in_millisecond, void *data, httpio_timeout_cb_t cb);

void httpio_free_request(httpio_request_t **req);

void httpio_free_client_info(httpio_client_info_t **info_to_free);

void httpio_write_response(httpio_request_t *origin_request, httpio_response_t *response);

void httpio_destroy(httpio_t **io_to_free);

#endif //HTTP_IO_C_HTTPIO_H