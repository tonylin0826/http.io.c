#include "httpio.h"


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <evhttp.h>
#include <event.h>
#include <signal.h>

void signal_handler(int sig) {
    event_loopbreak();
}

void request_handler(struct evhttp_request *req, void *arg) {
    httpio_t *io = (httpio_t *) arg;

    char output[2048] = "\0";
    char tmp[1024];

    //获取客户端请求的URI(使用evhttp_request_uri或直接req->uri)
    const char *uri = evhttp_request_uri(req);
    sprintf(tmp, "uri=%s\n", uri);
    strcat(output, tmp);

    sprintf(tmp, "uri=%s\n", req->uri);
    strcat(output, tmp);

    char *decoded_uri = evhttp_decode_uri(uri);
    sprintf(tmp, "decoded_uri=%s\n", decoded_uri);
    strcat(output, tmp);

    struct evkeyvalq params;

    evhttp_parse_query(decoded_uri, &params);
    sprintf(tmp, "q=%s\n", evhttp_find_header(&params, "q"));
    strcat(output, tmp);
    sprintf(tmp, "s=%s\n", evhttp_find_header(&params, "s"));
    strcat(output, tmp);
    free(decoded_uri);

    char *post_data = (char *) EVBUFFER_DATA(req->input_buffer);
    sprintf(tmp, "post_data=%s\n", post_data);
    strcat(output, tmp);

    evhttp_add_header(req->output_headers, "Server", "Tony handsome");
    evhttp_add_header(req->output_headers, "Content-Type", "text/plain; charset=UTF-8");
    evhttp_add_header(req->output_headers, "Connection", "close");

    struct evbuffer *buf;
    buf = evbuffer_new();
    evbuffer_add_printf(buf, "It works!\n%s\n", output);
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

httpio_t *httpio_init() {
    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

    event_init();

    httpio_t *io = calloc(1, sizeof(httpio_t));

    for (uint8_t i = 0; i < 6; i++) {
        map_init(&io->request_handler_maps[i]);
    }

    return io;
}

void httpio_add_route(httpio_t *io, httpio_method_t method, const char *uri, httpio_request_handler handler) {
    map_set(&io->request_handler_maps[method], uri, handler);
}

void httpio_listen(httpio_t *io, const char *ip, int port) {

    io->ev_http = evhttp_start(ip, port);
    evhttp_set_timeout(io->ev_http, 120);

    evhttp_set_gencb(io->ev_http, request_handler, io);

    event_dispatch();
}

void httpio_destroy(httpio_t **io) {
    evhttp_free((*io)->ev_http);
}

int main() {
    httpio_t *io = httpio_init();

    httpio_listen(io, "0.0.0.0", 8080);

    httpio_destroy(&io);

    return 0;
}