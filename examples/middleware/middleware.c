//
// Created by Tony Lin on 2019/10/29.
//

#include <stdio.h>
#include "../../src/httpio.h"

bool g_use_middleware = false;

middleware_status_t on_test_middleware(httpio_request_t *req) {
    printf("on_test_middleware %s - [%s], [%p]\n", http_method_str(req->method), req->uri, req);

    g_use_middleware = !g_use_middleware;

    if (g_use_middleware) {
        httpio_response_t response;
        httpio_init_response(&response);

        httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");
        httpio_header_set(&response.headers, "Access-Control-Allow-Origin", "*");

        response.body = strdup("{\"responder\":\"middleware\"}");

        httpio_write_response(req, &response);
        httpio_deinit_response(&response);

        httpio_free_request(&req);

        return MIDDLEWARE_STATUS_DONE;
    }

    return MIDDLEWARE_STATUS_NEXT;
}

void on_test_get(httpio_request_t *req) {
    printf("on_test_get %s - [%s], [%p]\n", http_method_str(req->method), req->uri, req);

    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");
    httpio_header_set(&response.headers, "Access-Control-Allow-Origin", "*");

    response.body = strdup("{\"responder\":\"handler\"}");

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    httpio_free_request(&req);
}

int main() {
    httpio_t *io = httpio_init();

    httpio_use(io, HTTP_GET, "/test", on_test_middleware);
    httpio_add_route(io, HTTP_GET, "/test", on_test_get);

    httpio_listen(io, "0.0.0.0", 8080);

    httpio_destroy(&io);
    return 0;
}