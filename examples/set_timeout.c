#include <stdio.h>
#include "../src/httpio.h"

void on_asd_sss_timeout(void *data) {
    httpio_request_t *req = (httpio_request_t *) data;

    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");

    response.body = "{\"status\":\"ok\",\"extended\":true,\"results\":[{\"value\":0,\"type\":\"int64\"},{\"value\":1000,\"type\":\"decimal\"}]}";

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    httpio_free_request(&req);
}

void on_asd_sss(httpio_request_t *req) {
    printf("on_asd_sss %s - [%s]\n", http_method_str(req->method), req->uri);

    httpio_set_timout(0, req, on_asd_sss_timeout);
}

void on_uri_param(httpio_request_t *req) {
    printf("on_uri_param %s - [%s]\n", http_method_str(req->method), req->uri);

    char *s = *map_get(&req->params, ":ss");

    printf(":ss => %s\n", s);

    httpio_set_timout(0, req, on_asd_sss_timeout);
}

int main() {
    httpio_t *io = httpio_init();

    httpio_add_route(io, HTTP_POST, "/asd/ccc", on_asd_sss);
    httpio_add_route(io, HTTP_POST, "/asd/:ss/ddd", on_uri_param);

    httpio_listen(io, "0.0.0.0", 8080);

    httpio_destroy(&io);

    return 0;
}