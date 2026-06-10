#include <stdbool.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>

#include "common.h"
#include "http.h"
#include <stdlib.h>
#include <string.h>

static void dbg_header(http_header_t *header)
{
    fwrite(header->key.ptr, 1, header->key.len, stdout);
    fprintf(stdout, ": ");
    fwrite(header->value.ptr, 1, header->value.len, stdout);
    fprintf(stdout, "\n");
}

bool string_view_lower_cmp(string_view_t a, string_view_t b)
{
    if (a.len != b.len) {
        return false;
    }

    for (size_t i = 0; i < a.len; i++) {
        if (tolower(a.ptr[i]) != tolower(b.ptr[i])) {
            return false;
        }
    }

    return true;
}

size_t string_view_to_size_t(string_view_t s)
{
    char temp[s.len + 1];
    memcpy(&temp, s.ptr, s.len);
    temp[s.len] = '\0';

    // FIXME: error handling
    long r = strtol(temp, NULL, 10);
    return r;
}

void make_http_request()
{
    SSL_CTX *ctx = http_client_init_ssl_ctx();
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    char scratch_buf[4096];

    http_client_t client = {
        .hostname = "registry.npmjs.org",
        .req_header_buf = scratch_buf,
        .req_header_buf_len = 4096,
    };

    if (http_client_init_ssl_connection(&client, ctx) == -1) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    http_write_control_line(&client, "GET", "/react/latest");
    http_write_header(&client, "Host", "registry.npmjs.org");
    http_write_header(&client, "Connection", "close");
    if (http_complete_request(&client) == 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    stream_t response_stream = {
        .buf = scratch_buf,
        .buf_len = 4096,
        .last_read_count = 0,
        .read_cursor = 0,
        .write_cursor = 0,
        .ssl = client.ssl,
    };

    char response_headers[2048];
    size_t response_headers_len = 0;
    if (http_stream_take_until(&response_stream, "\r\n\r\n", 4, response_headers, 2048,
                               &response_headers_len) == -1) {
        fprintf(stderr, "Could not find end of response headers\n");
        exit(1);
    }
    // now that we've copied all the header bytes into a local buffer, we can recycle the stream
    // buffer to make room for the body later on:
    http_stream_recycle_buffer(&response_stream);

    http_response_parser_t parser = {
        .buffer = response_headers,
        .buffer_len = response_headers_len,
        .read_cursor = 0,
    };
    http_response_parser_skip_line(&parser); // skip header line

    // read content-length so we know how much body to parse
    http_header_t header;
    string_view_t cl_header = str_view_literal("content-length");
    size_t content_length = 0;
    while (http_response_parser_read_next_header(&parser, &header) > 0) {
        dbg_header(&header);
        if (string_view_lower_cmp(header.key, cl_header)) {
            content_length = string_view_to_size_t(header.value);
        }
    }

    printf("decoded content length of %zu\n", content_length);
    printf("Done and closed connection\n");
    http_client_shutdown(&client);
}

int main(int argc, char **argv)
{
    make_http_request();
    return 0;
}
