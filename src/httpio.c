#include "httpio.h"
#include "http_parser.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <uv.h>

void on_write(uv_write_t *req, int status);

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

void parse_uri_path(uri_tree_t *tree, const char *uri, httpio_request_handler_t cb) {

    list_t *current = tree->roots;

    uri_tree_node_t *leaf = NULL;

    int len = (int) strlen(uri);
    char part[256] = {0};
    for (int i = 0, c = 0; i < len && uri[i] != '?'; i++) {
        if (uri[i] == '/') {
            printf("part: [%s]\n", part);

            list_node_t *node = search_in_list(current, part, is_node_match_part);

            if (node) {
                current = ((uri_tree_node_t *) node->data)->children;
                leaf = ((uri_tree_node_t *) node->data);
            } else {
                leaf = new_uri_tree_node(strdup(part), NULL);
                append_to_list(current, leaf);
            }

            memset(part, 0, c);
            c = 0;
        } else {
            part[c++] = uri[i];
        }
    }

    if (strlen(part) > 0) {
        printf("part: [%s]\n", part);

        list_node_t *node = search_in_list(current, part, is_node_match_part);

        if (node) {
            leaf = ((uri_tree_node_t *) node->data);
        } else {
            leaf = new_uri_tree_node(strdup(part), NULL);
            append_to_list(current, leaf);
        }
    }

    if (!leaf) {
        printf("ERROR failed to parse URI");
        return;
    }

    leaf->cb = cb;

    printf("leaf => [%s]\n", leaf->name);
}

httpio_t *httpio_init() {
    httpio_t *io = calloc(1, sizeof(httpio_t));

    uv_tcp_init(uv_default_loop(), &io->uv_server);

    io->tmp.request = NULL;
    io->tmp.last_header_field = NULL;

    io->parser = malloc(sizeof(http_parser));
    http_parser_init(io->parser, HTTP_REQUEST);

    io->parser->data = (void *) &io->tmp;

    for (int i = 0; i <= HTTP_TRACE; i++) {
        io->uri_tree[i] = new_uri_tree();
    }

    return io;
}

void httpio_add_route(httpio_t *io, httpio_method_t method, const char *uri, httpio_request_handler_t handler) {
//    map_set(&io->request_handler_maps[method], uri, handler);
    if (method > HTTP_TRACE) {
        return;
    }

    parse_uri_path(io->uri_tree[method], uri, handler);
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

void httpio_init_response(httpio_response_t *response) {
    response->status = HTTP_STATUS_OK;
    map_init(&response->headers);
}

void httpio_deinit_response(httpio_response_t *response) {
    map_deinit(&response->headers);
}

void uv_write_str(uv_stream_t *uv_client, char *str) {
    uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
    uv_buf_t wrbuf = uv_buf_init(str, strlen(str));
    uv_write(req, uv_client, &wrbuf, 1, on_write);
}

void httpio_write_response(httpio_request_t *origin_request, httpio_response_t *response) {
    // convert response to text;
    size_t content_len = 0;
    if (response->body) {
        content_len = strlen(response->body);
    }

    char buf[256] = {0};
    sprintf(buf, "HTTP/1.1 %u %s\r\n", response->status, http_status_str(response->status));
    uv_write_str(origin_request->uv_client, buf);

    const char *key;
    map_iter_t iter = map_iter(&response->headers);

    while ((key = map_next(&response->headers, &iter))) {
        sprintf(buf, "%s: %s\r\n", key, *map_get(&response->headers, key));
        uv_write_str(origin_request->uv_client, buf);
    }

    if (map_get(&response->headers, "Date") == NULL) {
        uv_write_str(origin_request->uv_client, "Date: Sat, 18 Feb 2017 00:01:57 GMT\r\n");
    }

    if (map_get(&response->headers, "Server") == NULL) {
        sprintf(buf, "Server: nginx/1.11.8\r\n");
        uv_write_str(origin_request->uv_client, "Server: httpio/0.0.1\r\n");
    }

    if (map_get(&response->headers, "Date") == NULL) {
        sprintf(buf, "Content-Length: %zu\r\n", content_len);
        uv_write_str(origin_request->uv_client, buf);
    }

    uv_write_str(origin_request->uv_client, "\r\n");

//    sprintf(buf, "%s", response->body);
    uv_write_str(origin_request->uv_client, response->body);

}

void httpio_destroy(httpio_t **io) {

}


void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *) malloc(suggested_size);
    buf->len = suggested_size;
}

void route(uv_stream_t *client, httpio_request_t *request) {
    httpio_t *io = (httpio_t *) client->data;
    printf("routing to %s - [%s]\n", http_method_str(request->method), request->uri);

    if (request->method > HTTP_TRACE) {
        printf("INVALID Method\n");
        return;
    }

    uri_tree_node_t *node = search_uri_tree_node(io->uri_tree[request->method], request->uri);

    if (!node) {
        printf("PATH Not found\n");
        return;
    }

    request->uv_client = client;

    node->cb(request);
}

void on_write(uv_write_t *req, int status) {
//    printf("on_write\n");
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }

    free(req);
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

        httpio_request_parse_t *parsed = (httpio_request_parse_t *) ((httpio_t *) client->data)->parser->data;

        route(client, parsed->request);

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

void timeout(uv_timer_t *handle) {
    httpio_request_t *req = (httpio_request_t *) handle->data;

    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");

    response.body = "{\"status\":\"ok\",\"extended\":true,\"results\":[{\"value\":0,\"type\":\"int64\"},{\"value\":1000,\"type\":\"decimal\"}]}";

    httpio_write_response((httpio_request_t *) handle->data, &response);

    httpio_deinit_response(&response);

    free(req->uv_timer);
    req->uv_timer = NULL;
}

void on_asd_sss(httpio_request_t *req) {
    printf("on_asd_sss %s - [%s]\n", http_method_str(req->method), req->uri);

    req->uv_timer = calloc(1, sizeof(uv_timer_t));

    req->uv_timer->data = req;

    uv_timer_init(uv_default_loop(), req->uv_timer);
    uv_timer_start(req->uv_timer, timeout, 0, 0);
};

int main() {
    httpio_t *io = httpio_init();

    httpio_add_route(io, HTTP_GET, "/asb/sss", on_asd_sss);

    httpio_listen(io, "0.0.0.0", 8080);

    httpio_destroy(&io);

    return 0;
}