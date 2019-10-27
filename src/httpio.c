#include "httpio.h"
#include "http_parser.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <uv.h>

typedef struct {
    httpio_timeout_cb_t cb;
    void *data;
} timeout_t;

void parse_url_query_params(httpio_request_t *request, char *uri, size_t len) {
    int uri_len = (int) len;
    bool start = false;

    char *key = NULL;
    char *value = NULL;

    size_t key_len = 0;
    size_t value_len = 0;

    char **finger = NULL;
    size_t *finger_len = 0;

    for (int i = 0; i < uri_len; i++) {
        if (uri[i] == '?') {
            start = true;

            finger = &key;
            finger_len = &key_len;

            continue;
        }

        if (start) {

            if (uri[i] == ';' || uri[i] == '&') {

                if (key && value) {
                    char *k = strndup(key, key_len);
                    map_set(&request->queries, k, strndup(value, value_len));
                    free(k);
                }

                key = NULL;
                value = NULL;

                key_len = 0;
                value_len = 0;

                finger = &key;
                finger_len = &key_len;

                continue;
            }

            if (uri[i] == '=') {
                finger = &value;
                finger_len = &value_len;
                continue;
            }

            if (*finger == NULL) {
                *finger = &uri[i];
                *finger_len = 1;
                continue;
            }

            (*finger_len)++;
        }
    }

    if (key && value) {
        char *k = strndup(key, key_len);
        map_set(&request->queries, k, strndup(value, value_len));
        free(k);
    }
}

void on_method_not_allowed(httpio_request_t *req) {
    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");

    response.body = "{\"message\": \"Method not allowed\"}";
    response.status = HTTP_STATUS_METHOD_NOT_ALLOWED;

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    httpio_free_request(&req);
}

void on_not_found(httpio_request_t *req) {
    httpio_response_t response;
    httpio_init_response(&response);

    httpio_header_set(&response.headers, "Content-Type", "application/json; charset=utf-8");

    response.body = "{\"message\": \"URL not found\"}";
    response.status = HTTP_STATUS_NOT_FOUND;

    httpio_write_response(req, &response);
    httpio_deinit_response(&response);

    httpio_free_request(&req);
}

void on_write(uv_write_t *req, int status);

void on_new_connection(uv_stream_t *server, int status);

void route(uv_stream_t *client, httpio_request_t *request);

int on_message_begin(http_parser *parser) {
    printf("on_message_begin\n");
    httpio_client_info_t *info = (httpio_client_info_t *) parser->data;

    info->request = calloc(1, sizeof(httpio_request_t));
    info->last_header_field = NULL;
    info->request->tmp_body_finger = NULL;

    map_init(&(info->request->headers));
    map_init(&(info->request->queries));
    map_init(&(info->request->params));

    return 0;
}

int on_message_complete(http_parser *parser) {
    printf("on_message_complete\n");

    httpio_client_info_t *info = (httpio_client_info_t *) parser->data;

    info->request->method = parser->method;

    printf("%s - %s\n", http_method_str(parser->method), info->request->uri);
    const char *key = NULL;
    map_iter_t iter = map_iter(&info.request->headers);

    while ((key = map_next(&info->request->headers, &iter))) {
        char **s = map_get(&info->request->headers, key);
        printf("%s: %s\n", key, *s);
    }

    iter = map_iter(&info.request->headers);

    while ((key = map_next(&info->request->queries, &iter))) {
        char **s = map_get(&info->request->queries, key);
        printf("%s => %s\n", key, *s);
    }

    if (info->request->body) {
        printf("%s\n", info->request->body);
    }

    route(info->client, info->request);

    return 0;
}

int on_body(http_parser *parser, const char *at, size_t len) {
    httpio_client_info_t *info = (httpio_client_info_t *) parser->data;

    if (!info->request->tmp_body_finger) {
        return 0;
    }

    strncat(info->request->tmp_body_finger, at, len);
    info->request->tmp_body_finger += len;

    return 0;
}

int on_header_value(http_parser *parser, const char *at, size_t len) {
    httpio_client_info_t *info = (httpio_client_info_t *) parser->data;

//    printf("header value = [%.*s], %zu\n", (int) len, at, len);

    if (info->last_header_field != NULL) {

        char *value = strndup(at, len);

        if (strncmp(info->last_header_field, "Content-Length", 14) == 0) {
            uint64_t content_len = strtoul(value, NULL, 10);
            info->request->body = calloc(content_len, sizeof(char));
            info->request->tmp_body_finger = info->request->body;
        }

        map_set(&info->request->headers, info->last_header_field, value);
        info->last_header_field = NULL;
    }

    return 0;
}

int on_header_field(http_parser *parser, const char *at, size_t len) {
    httpio_client_info_t *info = (httpio_client_info_t *) parser->data;

//    printf("header field = [%.*s]\n", (int) len, at);

    info->last_header_field = strndup(at, len);
    return 0;
}

int on_url(http_parser *parser, const char *at, size_t len) {
    httpio_client_info_t *info = (httpio_client_info_t *) parser->data;

    info->request->uri = strndup(at, len);

    // parse url
    parse_url_query_params(info->request, info->request->uri, len);

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

void uv_write_str(uv_stream_t *uv_client, char *str) {
    uv_write_t *req = (uv_write_t *) malloc(sizeof(uv_write_t));
    uv_buf_t wrbuf = uv_buf_init(str, strlen(str));
    uv_write(req, uv_client, &wrbuf, 1, on_write);
}

void parse_uri_path(uri_tree_t *tree, const char *uri, httpio_request_handler_t cb) {

    list_t *current = tree->roots;

    uri_tree_node_t *leaf = NULL;

    int len = (int) strlen(uri);
    char part[256] = {0};
    for (int i = 1, c = 0; i < len && uri[i] != '?'; i++) {
        if (uri[i] == '/') {
            list_node_t *node = search_in_list(current, part, is_node_match_part);

//            printf("%p => %s\n", node, part);

            if (node) {
                current = ((uri_tree_node_t *) node->data)->children;
                leaf = ((uri_tree_node_t *) node->data);

                printf("found %s\n", leaf->name);
            } else {
                leaf = new_uri_tree_node(strdup(part), NULL);
                append_to_list(current, leaf);

                printf("create %s\n", leaf->name);
            }

            memset(part, 0, c);
            c = 0;

            current = leaf->children;
        } else {
            part[c++] = uri[i];
        }
    }

    if (part[0] != 0) {

        list_node_t *node = search_in_list(current, part, is_node_match_part);
//        printf("%p => %s\n", node, part);

        if (node) {
            leaf = ((uri_tree_node_t *) node->data);

            printf("found %s\n", leaf->name);
        } else {
            leaf = new_uri_tree_node(strdup(part), NULL);
            append_to_list(current, leaf);

            printf("create %s\n", leaf->name);
        }
    }

    if (!leaf) {
        printf("ERROR failed to parse URI");
        return;
    }

    leaf->cb = cb;
}

void timeout(uv_timer_t *handle) {

    timeout_t *t = (timeout_t *) handle->data;

    t->cb(t->data);

    free(t);
    free(handle);
}

httpio_t *httpio_init() {
    httpio_t *io = calloc(1, sizeof(httpio_t));

    uv_tcp_init(uv_default_loop(), &io->uv_server);

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

void httpio_set_timout(uint64_t time_in_millisecond, void *data, httpio_timeout_cb_t cb) {
    uv_timer_t *uv_timer = calloc(1, sizeof(uv_timer_t));

    timeout_t *t = calloc(1, sizeof(timeout_t));
    t->data = data;
    t->cb = cb;

    uv_timer->data = t;

    uv_timer_init(uv_default_loop(), uv_timer);
    uv_timer_start(uv_timer, timeout, time_in_millisecond, 0);
}

void httpio_free_request(httpio_request_t **req) {
    free((*req)->uri);
    free((*req)->body);

    const char *key;
    map_iter_t iter = map_iter(&(*req)->headers);

    while ((key = map_next(&(*req)->headers, &iter))) {
        free(*map_get(&(*req)->headers, key));
    }

    map_deinit(&(*req)->headers);
    map_deinit(&(*req)->params);
    map_deinit(&(*req)->queries);

    (*req)->uv_client = NULL;

    free(*req);

    *req = NULL;
}

void httpio_free_client_info(httpio_client_info_t **info_to_free) {
    httpio_client_info_t *info = *info_to_free;

    free(info->last_header_field);

    if (info->request) {
        httpio_free_request(&info->request);
    }

    free(info->client);
    free(info->parser);

    // no need to free io since destroy free it

    free(info);
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

    uv_write_str(origin_request->uv_client, response->body);

}

void httpio_destroy(httpio_t **io_to_free) {
    httpio_t *io = *io_to_free;

    uv_close((uv_handle_t *) &io->uv_server, NULL);

    free(io);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    buf->base = (char *) malloc(suggested_size);
    buf->len = suggested_size;
}

void route(uv_stream_t *client, httpio_request_t *request) {
    httpio_client_info_t *info = (httpio_client_info_t *) client->data;
    httpio_t *io = (httpio_t *) info->data;
    printf("routing to %s - [%s]\n", http_method_str(request->method), request->uri);

    request->uv_client = client;

    if (request->method > HTTP_TRACE) {
        printf("INVALID Method\n");
        on_method_not_allowed(request);
        return;
    }

    uri_tree_node_t *node = search_uri_tree_node(io->uri_tree[request->method], request->uri, request);

    if (!node) {
        printf("PATH Not found\n");
        on_not_found(request);
        return;
    }

    node->cb(request);
}

void on_write(uv_write_t *req, int status) {
    if (status) {
        fprintf(stderr, "Write error %s\n", uv_strerror(status));
    }

    free(req);
}

void on_client_message(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
    httpio_client_info_t *info = (httpio_client_info_t *) client->data;
    if (nread < 0) {
        if (nread != UV_EOF) {

            fprintf(stderr, "Read error %s\n", uv_err_name(nread));
            uv_close((uv_handle_t *) client, NULL);

            if (info) {
                httpio_free_client_info(&info);
            }
        }
    } else if (nread > 0) {
//        printf("read %.*s, %zu\n", (int) nread, buf->base, nread);

        if (!info->parser) {
            info->parser = calloc(1, sizeof(http_parser));
            http_parser_init(info->parser, HTTP_REQUEST);

            info->parser->data = info;
        }

        size_t n_parsed = http_parser_execute(
                info->parser,
                &settings,
                buf->base,
                nread
        );

//        printf("n_parsed = %zu\n", n_parsed);
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

    httpio_client_info_t *info = calloc(1, sizeof(httpio_client_info_t));

    info->data = server->data;
    info->client = (uv_stream_t *) client;
    info->parser = NULL;
    client->data = info;

    if (uv_accept(server, (uv_stream_t *) client) == 0) {
        uv_read_start((uv_stream_t *) client, alloc_buffer, on_client_message);
    } else {
        // free client info in callback
        uv_close((uv_handle_t *) client, NULL);
        httpio_free_client_info(&info);
    }
}