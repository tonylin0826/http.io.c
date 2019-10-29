//
// Created by Tony Lin on 2019/10/27.
//

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include "../../src/httpio.h"

typedef map_t(httpio_request_t*) http_request_map_t;

http_request_map_t request_map;
char *pub_data = NULL;

void on_sub_get_timeout(uv_timer_t *handle) {
    httpio_request_t *req = (httpio_request_t *) handle->data;

    char addr[12] = {0};
    sprintf(addr, "%p", req);
    map_remove(&request_map, addr);

    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");
    httpio_header_set(&response.headers, "Access-Control-Allow-Origin", "*");

    response.body = strdup("[]");

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    httpio_free_request(&req);

    uv_close((uv_handle_t *) handle, (uv_close_cb) free);
}

void on_pub(httpio_request_t *req) {

    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");
    httpio_header_set(&response.headers, "Access-Control-Allow-Origin", "*");

    response.body = pub_data;

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    uv_timer_stop(req->data);
    uv_close((uv_handle_t *) req->data, (uv_close_cb) free);

    httpio_free_request(&req);
}

void on_sub_get(httpio_request_t *req) {
    printf("on_sub_get %s - [%s], [%p]\n", http_method_str(req->method), req->uri, req);

    char addr[12] = {0};
    sprintf(addr, "%p", req);
    map_set(&request_map,addr,req);

    uv_timer_t *uv_timer = calloc(1, sizeof(uv_timer_t));

    uv_timer->data = req;
    req->data = uv_timer;

    uv_timer_init(uv_default_loop(), uv_timer);
    uv_timer_start(uv_timer, on_sub_get_timeout, 10000, 0);
}

void on_pub_post(httpio_request_t *req) {
    printf("on_pub_post %s - [%s]\n", http_method_str(req->method), req->uri);

    pub_data = strdup(req->body);

    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");

    response.body = "{\"success\": true}";

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    httpio_free_request(&req);

    const char *key = NULL;
    map_iter_t iter = map_iter(&request_map);

    while ((key = map_next(&request_map, &iter))) {
        httpio_request_t **r = map_get(&request_map, key);
        on_pub(*r);
    }

    map_deinit(&request_map);
    map_init(&request_map);

    free(pub_data);
    pub_data = NULL;
}

int main() {
    map_init(&request_map);

    httpio_t *io = httpio_init();

    httpio_add_route(io, HTTP_GET, "/sub", on_sub_get);
    httpio_add_route(io, HTTP_POST, "/pub", on_pub_post);

    httpio_listen(io, "0.0.0.0", 8080);

    httpio_destroy(&io);

    return 0;
}