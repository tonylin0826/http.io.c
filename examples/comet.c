//
// Created by Tony Lin on 2019/10/27.
//

#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#include "../src/httpio.h"

list_t *g_list;

char *pub_data = NULL;

void on_sub_get_timeout(uv_timer_t *handle) {
    httpio_request_t *req = (httpio_request_t *) handle->data;

    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");

    if (!pub_data) {
        response.body = "[]";
    } else {
        response.body = pub_data;
    }

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    httpio_free_request(&req);

    uv_timer_stop(handle);
    free(handle);
}

void on_sub_get(httpio_request_t *req) {
    printf("on_sub_get %s - [%s]\n", http_method_str(req->method), req->uri);

    append_to_list(g_list, req);

    uv_timer_t *uv_timer = calloc(1, sizeof(uv_timer_t));

    uv_timer->data = req;
    req->data = uv_timer;

    uv_timer_init(uv_default_loop(), uv_timer);
    uv_timer_start(uv_timer, on_sub_get_timeout, 10000, 0);
}

void on_pub_post(httpio_request_t *req) {
    printf("on_data2_get %s - [%s]\n", http_method_str(req->method), req->uri);

    pub_data = strdup(req->body);

    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");

    response.body = "[30]";

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    httpio_free_request(&req);


    list_node_t *t = NULL;
    list_node_t *c = g_list->head;
    while (c) {
        on_sub_get_timeout(((httpio_request_t *) c->data)->data);
        t = c;
        c = c->next;
        free(t);
    }

    g_list->head = NULL;
    g_list->current = NULL;

    free(pub_data);
}

int main() {

    g_list = new_list();

    httpio_t *io = httpio_init();

    httpio_add_route(io, HTTP_GET, "/sub", on_sub_get);
    httpio_add_route(io, HTTP_POST, "/pub", on_pub_post);

    httpio_listen(io, "0.0.0.0", 8080);

    httpio_destroy(&io);
}