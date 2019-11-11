#include <stdio.h>
#include <stdlib.h>
#include "../../src/httpio.h"

void close_server(uv_handle_t *handle) {
    httpio_t *io = handle->data;

    uv_stop(uv_default_loop());

    free(io);
}

void close_client(uv_handle_t *handle) {
    httpio_client_info_t *info = handle->data;
    httpio_t *io = info->data;

    free(info->parser);
    free(info);

    free(handle);

//    uv_close((uv_handle_t *) &io->uv_server, close_server);
}

void on_asd_sss_timeout(void *data) {
    httpio_request_t *req = (httpio_request_t *) data;

    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");

    response.body = "{\"status\":\"ok\",\"extended\":true,\"results\":[{\"value\":0,\"type\":\"int64\"},{\"value\":1000,\"type\":\"decimal\"}]}";

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    uv_close((uv_handle_t *) req->uv_client, close_client);

    httpio_free_request(&req);
}

void on_asd_sss(httpio_request_t *req) {
    printf("on_asd_sss %s - [%s]\n", http_method_str(req->method), req->uri);

    httpio_set_timout(0, req, on_asd_sss_timeout);
}

int main() {
    httpio_t *io = httpio_init();

    httpio_add_route(io, HTTP_POST, "/asd/ccc", on_asd_sss);

    httpio_listen(io, "0.0.0.0", 8080);

//    httpio_destroy(&io);

    return 0;
}