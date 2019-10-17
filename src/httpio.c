#include "httpio.h"
#include "http_parser.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uv.h>

void on_new_connection(uv_stream_t *server, int status);

int on_message_begin(http_parser *parser) {
    printf("on_message_begin\n");
    httpio_request_parse_t *parsed = (httpio_request_parse_t *) parser->data;

    parsed->request = calloc(1, sizeof(httpio_request_t));

    map_init(&(parsed->request->headers));

    return 0;
}

int on_message_complete(http_parser *parser) {
    printf("on_message_complete\n");

    httpio_request_parse_t *parsed = (httpio_request_parse_t *) parser->data;

    parsed->request->method = parser->method;

    printf("%s - %s\n", http_method_str(parser->method), parsed->request->uri);
    const char *key = NULL;
    map_iter_t iter = map_iter(&parsed.request->headers);

    while ((key = map_next(&parsed->request->headers, &iter))) {
        char **s = map_get(&parsed->request->headers, key);
        printf("%s: %s\n", key, *s);
    }

    printf("%s\n", parsed->request->body);

    return 0;
}

int on_body(http_parser *parser, const char *at, size_t len) {
    httpio_request_parse_t *parsed = (httpio_request_parse_t *) parser->data;

//    printf("body = [%.*s]\n", (int) len, at);

    parsed->request->body = strndup(at, len);
    return 0;
}

int on_header_value(http_parser *parser, const char *at, size_t len) {
    httpio_request_parse_t *parsed = (httpio_request_parse_t *) parser->data;

//    printf("header value = [%.*s], %zu\n", (int) len, at, len);

    if (parsed->last_header_field != NULL) {
        map_set(&parsed->request->headers, parsed->last_header_field, strndup(at, len));
        parsed->last_header_field = NULL;
    }

    return 0;
}

int on_header_field(http_parser *parser, const char *at, size_t len) {
    httpio_request_parse_t *parsed = (httpio_request_parse_t *) parser->data;

//    printf("header field = [%.*s]\n", (int) len, at);

    parsed->last_header_field = strndup(at, len);
    return 0;
}

int on_url(http_parser *parser, const char *at, size_t len) {
    httpio_request_parse_t *parsed = (httpio_request_parse_t *) parser->data;

//    printf("url = [%.*s]\n", (int) len, at);

    parsed->request->uri = strndup(at, len);

    return 0;
}

http_parser_settings settings = {
        .on_message_begin = on_message_begin,
        .on_message_complete = on_message_complete,
        .on_header_field = on_header_field,
        .on_header_value = on_header_value,
        .on_url = on_url,
        .on_body = on_body
};

httpio_t *httpio_init() {
    httpio_t *io = calloc(1, sizeof(httpio_t));

    uv_tcp_init(uv_default_loop(), &io->uv_server);

    io->tmp.request = NULL;
    io->tmp.last_header_field = NULL;

    io->parser = malloc(sizeof(http_parser));
    http_parser_init(io->parser, HTTP_REQUEST);

    io->parser->data = (void *) &io->tmp;

    return io;
}

void httpio_add_route(httpio_t *io, httpio_method_t method, const char *uri, httpio_request_handler handler) {
//    map_set(&io->request_handler_maps[method], uri, handler);
}

int httpio_listen(httpio_t *io, const char *ip, int port) {
    struct sockaddr bind_addr;
    uv_ip4_addr(ip, port, (struct sockaddr_in *) &bind_addr);

    uv_tcp_bind(&io->uv_server, (const struct sockaddr *) &bind_addr, 0);

    io->uv_server.data = (void *) io;

    int r = uv_listen((uv_stream_t *) &io->uv_server, 128, on_new_connection);

    if (r) {
        fprintf(stderr, "Listen error %s\n", uv_strerror(r));
        return -1;
    }

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    return 0;
}

void httpio_destroy(httpio_t **io) {

}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *) malloc(suggested_size);
    buf->len = suggested_size;
}

void route(uv_stream_t *client, httpio_request_t *request) {
    printf("routing to %s - [%s]\n", http_method_str(request->method), request->uri);
}

void on_client_message(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
            uv_close((uv_handle_t *) client, NULL);
        }
    } else if (nread > 0) {
//        printf("read %.*s, %zu\n", (int) nread, buf->base, nread);

        size_t n_parsed = http_parser_execute(
                ((httpio_t *) client->data)->parser,
                &settings,
                buf->base,
                nread
        );

        route(client, (httpio_request_t *) ((httpio_t *) client->data)->parser->data);

        printf("n_parsed = %zu\n", n_parsed);
    }

    if (buf->base) {
        free(buf->base);
    }
}

void on_new_connection(uv_stream_t *server, int status) {
    if (status < 0) {
        fprintf(stderr, "New connection error %s\n", uv_strerror(status));
        return;
    }

    uv_tcp_t *client = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(uv_default_loop(), client);

    client->data = server->data;

    if (uv_accept(server, (uv_stream_t *) client) == 0) {
        uv_read_start((uv_stream_t *) client, alloc_buffer, on_client_message);
    } else {
        uv_close((uv_handle_t *) client, NULL);
    }
}

int main() {
    httpio_t *io = httpio_init();

    httpio_listen(io, "0.0.0.0", 8080);

    httpio_destroy(&io);

    return 0;
}