#ifndef HTTP_IO_C_HTTPIO_H
#define HTTP_IO_C_HTTPIO_H

#include "httpio_types.h"

#include <stdint.h>

httpio_t *httpio_init();

void httpio_add_route(httpio_t *io, httpio_method_t method, const char *uri, httpio_request_handler handler);

int httpio_listen(httpio_t *io, const char *ip, int port);

void httpio_destroy(httpio_t **io);

#endif //HTTP_IO_C_HTTPIO_H