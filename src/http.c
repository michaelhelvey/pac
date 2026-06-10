#include <assert.h>
#include <netdb.h>
#include <stdbool.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <ctype.h>

#include "common.h"
#include "http.h"

// === HTTP ===

// default chunk size when reading off the socket into a stream buffer
#define HTTP_STREAM_CHUNK_SIZE 1024
// maximum length of a http request/response line (header or control)
#define HTTP_LINE_MAX_LEN 1024

#define _SSL_CHECK(code) \
    if (!code)           \
        goto error;

/**
 * Initializes an SSL_CTX with default settings.  This function should be called once per package
 * manager invocation, and the resulting SSL_CTX pointer should be shared between all created
 * clients.
 * 
 * Returns an SSL_CTX pointer if succeeds, and NULL on error.  If error, check the OpenSSL error
 * stack for details.
 */
SSL_CTX *http_client_init_ssl_ctx(void)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL)
        return NULL;

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (!SSL_CTX_set_default_verify_paths(ctx))
        return NULL;
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION))
        return NULL;

    return ctx;
}

/**
 * Initializes a new https client with an underlying SSL connection to the host. After this function
 * returns, a socket is open and ready to be written to the host server.
 * 
 * Returns 0 on success, and -1 on failure.  The cause of the failure can be found on the OpenSSL
 * error stack and can be retrieved via ERR_get_error(), which can in turn be passed to
 * ERR_error_string() for a human-readable message.
 */
int http_client_init_ssl_connection(struct http_client_t *client, SSL_CTX *ctx)
{
    debug_assert(client->hostname != NULL &&
                 "http_client_init_ssl expects client hostname to be set");
    SSL *ssl;

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        return -1;

    int sock = -1;
    BIO_ADDRINFO *lookup_res;
    _SSL_CHECK(BIO_lookup_ex(client->hostname, "https", BIO_LOOKUP_CLIENT, AF_INET, SOCK_STREAM,
                             IPPROTO_TCP, &lookup_res));

    const BIO_ADDRINFO *ai = NULL;
    for (ai = lookup_res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_STREAM, 0, 0);
        if (sock == -1)
            continue;

        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        break;
    }

    BIO_ADDRINFO_free(lookup_res);

    BIO *bio = BIO_new(BIO_s_socket());
    if (bio == NULL) {
        BIO_closesocket(sock);
        goto error;
    }

    BIO_set_fd(bio, sock, BIO_CLOSE);
    SSL_set_bio(ssl, bio, bio);

    _SSL_CHECK(SSL_set_tlsext_host_name(ssl, client->hostname));
    _SSL_CHECK(SSL_set1_host(ssl, client->hostname));
    _SSL_CHECK(SSL_connect(ssl));

    client->ssl = ssl;

    return 0;
error:
    SSL_free(ssl);
    return -1;
}

/**
 * Sends the TLS close_notify message to the server, closes the socket, and frees memory used for
 * the SSL connection.
 */
void http_client_shutdown(struct http_client_t *client)
{
    // NOTE: not handling return code for close_notify as we're not going to
    // re-use the SSL object anyway. I'm not sure if this is entirely correct.
    SSL_shutdown(client->ssl);
    SSL_free(client->ssl);
}

/**
 * Writes the first control line to the internal scratch buffer used by the client.  e.g. GET
 * /some/path HTTP/1.1
 *
 * FIXME: fails silently if the control line is too long to store in the buffer (e.g. if the path
 * has too many query parameters).
 */
void http_write_control_line(struct http_client_t *client, const char *method, const char *path)
{
    debug_assert(client->req_header_buf != NULL);
    debug_assert(client->req_header_buf_len > 0);
    debug_assert(client->req_header_buf_cursor == 0 &&
                 "you should not write a new request until completing the previous one");

    int written = snprintf(client->req_header_buf + client->req_header_buf_cursor,
                           HTTP_LINE_MAX_LEN, "%s %s HTTP/1.1\r\n", method, path);
    client->req_header_buf_cursor += written;
}

/**
 * Writes a header line (key-value) pair to the internal scratch buffer used by the client.  The
 * header's key and value are passed as-is and are not lowercased or otherwise modified.
 *
 * FIXME: fails silently if the key/value pair is too long to store in the buffer
 */
void http_write_header(struct http_client_t *client, const char *key, const char *value)
{
    debug_assert(client->req_header_buf != NULL);
    debug_assert(client->req_header_buf_len > 0);

    int written = snprintf(client->req_header_buf + client->req_header_buf_cursor,
                           HTTP_LINE_MAX_LEN, "%s: %s\r\n", key, value);
    client->req_header_buf_cursor += written;
}

/**
 * Flushes the internal scratch buffer used by the client for constructing the request (e.g. via
 * http_write_header, etc) to the `ssl` pointer owned by the client, then resets the scratch buffer
 * used by the client to prepare it for the next request (if any).
 *
 * The return value of `SSL_write_ex` is returned without modification, and any error can be
 * inspected using that return code using the standard OpenSSL error stack.
 */
int http_complete_request(struct http_client_t *client)
{
    snprintf(client->req_header_buf + client->req_header_buf_cursor, HTTP_LINE_MAX_LEN, "\r\n");
    client->req_header_buf_cursor += 2;

    // OpenSSL guarantees that SSL_write_ex will only complete successfully after all bytes from the
    // buffer have been written to the connection, unless you set SSL_MODE_ENABLE_PARTIAL_WRITE in
    // the context options, which we do not do.
    size_t _written;
    int r =
        SSL_write_ex(client->ssl, client->req_header_buf, client->req_header_buf_cursor, &_written);

    bzero(client->req_header_buf, client->req_header_buf_len);
    client->req_header_buf_cursor = 0;

    return r;
}

/**
 * Reads up to chunk_size bytes into the stream buffer and increments the write_cursor.  Returns the
 * response of SSL_read_ex (1 for success and 0 for failure).
 */
int http_stream_read_chunk(struct http_stream_t *stream, size_t chunk_size)
{
    debug_assert(chunk_size < stream->buf_len &&
                 "chunk size must be less than total buffer length");
    assert(stream->write_cursor + chunk_size < stream->buf_len &&
           "buffer is full, you must consume some data before writing more");

    int r = SSL_read_ex(stream->ssl, stream->buf + stream->write_cursor, chunk_size,
                        &stream->last_read_count);
    stream->write_cursor += stream->last_read_count;

    return r;
}

/**
 * Recycles the memory in the buffer, discarding the bytes in the buffer prior to read_cursor. This
 * allows us to use a statically sized buffer while continuously reading data into it.
 */
void http_stream_recycle_buffer(struct http_stream_t *stream)
{
    debug_assert(stream->write_cursor >= stream->read_cursor);
    if (stream->read_cursor == 0) {
        return;
    }

    // if the buffer is full and nothing has been consumed, then we can do nothing.  further writes
    // will also fail, but that's not our problem in this routine.
    if (stream->write_cursor >= stream->buf_len && stream->read_cursor == 0) {
        return;
    }

    char *active_bytes = stream->buf + stream->read_cursor;
    size_t active_bytes_len = stream->write_cursor - stream->read_cursor;

    // memmove instead of memcpy because the buffers overlap (copy must be non-destructive)
    memmove(stream->buf, active_bytes, active_bytes_len);
    stream->read_cursor = 0;
    stream->write_cursor = active_bytes_len;

#ifdef DEBUG
    // it makes it easier to visually debug the buffer if we clear the bytes that we're not using.
    // this is useless from a perf perspective so we only do it when debugging.
    size_t inactive_bytes_len = stream->buf_len - stream->write_cursor;
    bzero(stream->buf + stream->write_cursor, inactive_bytes_len);
#endif
}

/**
 * Consumes a single byte from the stream, fetching more data if needed.  
 *
 * Returns -1 on failure. On success, returns the byte value (0-255) in the lower
 * 8 bits, which can be safely cast to unsigned char or read directly as an int.
 *
 */
int http_stream_take_byte(struct http_stream_t *stream)
{
    if (stream->read_cursor == SIZE_T_MAX - 1)
        return -1;

    bool has_available = stream->write_cursor > stream->read_cursor;
    if (!has_available) {
        int r = http_stream_read_chunk(stream, HTTP_STREAM_CHUNK_SIZE);
        if (r == 0)
            return -1;
    }

    unsigned char byte = *(unsigned char *)(stream->buf + stream->read_cursor++);
    return (int)byte;
}

/**
 * Consumes data from the stream into the passed buffer, up to a max of `nbytes`.  Assumes that
 * `buf` is at least `nbytes` long.
 *
 * Returns 0 on success, or -1 on error.  The number of bytes successfully read will be written to
 * the `bytes_written` output parameter (even on error).
 *
 * This routine is intended for use specifically in parsing HTTP response bodies, either with a
 * known Content-Length or with Transfer-Encoding: chunked.
 */
int http_stream_take_nbytes(struct http_stream_t *stream, size_t nbytes, char *buf,
                            size_t *bytes_written)
{
    debug_assert(buf != NULL);
    debug_assert(bytes_written != NULL);

    *bytes_written = 0;
    if (nbytes == 0) {
        return 0;
    }

    size_t idx = 0;
    while (idx < nbytes) {
        int next_byte = http_stream_take_byte(stream);
        if (next_byte == -1)
            return -1;
        buf[idx++] = (unsigned char)next_byte;
        (*bytes_written)++;
    }

    return 0;
}

/**
 * Consumes data from the stream into the passed buffer until `needle` is reached, inclusive.  After
 * this routine completes, stream->read_cursor will be set at the first byte after `needle`.  Places
 * the number of bytes taken from the stream to reach the needle in the `bytes_consumed` output
 * parameter.
 *
 * Returns 0 on success, and -1 on error.
 *
 * This routine is intended for use in parsing the HTTP header block (e.g. consuming data until the
 * first \r\n\r\n).
 *
 * Notable error cases:
 *  - the underlying call to SSL_read_ex failed (either because there were no more bytes to read, or
 *  because of a network error -- it doesn't matter from the perspective of this routine)
 *  - we ran out of space in `buf` before finding the needle
 */
int http_stream_take_until(struct http_stream_t *stream, const char *needle, size_t needle_len,
                           char *buf, size_t buf_len, size_t *bytes_consumed)
{
    debug_assert(buf != NULL);
    debug_assert(buf_len > 0);
    debug_assert(needle_len > 0);

    *bytes_consumed = 0;

    // pre-load at least needle_len into buf:
    if (http_stream_take_nbytes(stream, needle_len, buf, bytes_consumed) == -1)
        goto error;

    size_t window_start = 0;
    while (window_start + needle_len < buf_len) {
        if (memcmp(buf + window_start, needle, needle_len) == 0) {
            return 0;
        }
        int next_byte = http_stream_take_byte(stream);
        if (next_byte == -1)
            goto error;

        (*bytes_consumed)++;
        buf[window_start + needle_len] = (char)next_byte;
        window_start++;
    }

    // our last window_start++ could conceivably have resulted in a match:
    if (memcmp(buf + window_start, needle, needle_len) == 0) {
        return 0;
    }

error:
    return -1;
}

/**
 * Consumes a single line (up to and including the next "\r\n") of the parser buffer.  Returns the
 * number of bytes consumed in order to reach the next line, or -1 on error.
 */
ssize_t http_response_parser_skip_line(http_response_parser_t *parser)
{
    if (parser->buffer_len < 2)
        return -1;

    size_t previous_cursor = parser->read_cursor;
    while (parser->read_cursor < parser->buffer_len - 1) {
        if (parser->buffer[parser->read_cursor] == '\r' &&
            parser->buffer[parser->read_cursor + 1] == '\n') {
            parser->read_cursor += 2;
            return parser->read_cursor - previous_cursor;
        }

        parser->read_cursor++;
    }

    parser->read_cursor = previous_cursor;
    return -1;
}

/**
 * Reads the next key/value header pair from the response header buffer, and sets the internal
 * cursor one character past the trailing "\r\n".  
 *
 * Possible return values:
 *      - A positive integer representing the number of bytes read to consume the header line,
 *      inclusive of the trailing "\r\n"
 *      - 0, if the two characters between the read cursor and the end of the header buffer are
 *      "\r\n", signaling the end of the headers
 *      - Negative one (-1), if we are not at the end of the headers, and we could not parse a
 *      key/value pair before reaching the end of the header buffer.  This indicates a malformed
 *      header buffer.
 */
ssize_t http_response_parser_read_next_header(http_response_parser_t *parser, http_header_t *header)
{
    size_t previous_cursor = parser->read_cursor;

    // malformed buffer: not long enough to even contain \r\n:
    if (parser->buffer_len < 2)
        return -1;

    assert(parser->read_cursor + 2 <= parser->buffer_len &&
           "a previous routine corrupted the response header iterator state");

    // we're at the end of a properly formed buffer:
    if (parser->buffer[parser->read_cursor] == '\r' &&
        parser->buffer[parser->read_cursor + 1] == '\n') {
        return 0;
    }

    // parse a key value pair:
    header->key.ptr = parser->buffer + parser->read_cursor;
    header->key.len = 0;

    while (parser->buffer[parser->read_cursor] != ':') {
        if (parser->read_cursor > parser->buffer_len - 1)
            goto error;

        header->key.len++;
        parser->read_cursor++;
    }
    parser->read_cursor++; // skip ':'

    while (isspace((unsigned char)parser->buffer[parser->read_cursor])) {
        if (parser->read_cursor >= parser->buffer_len - 1)
            goto error;
        parser->read_cursor++;
    }

    header->value.ptr = parser->buffer + parser->read_cursor;
    header->value.len = 0;
    while (parser->buffer[parser->read_cursor] != '\r' ||
           parser->buffer[parser->read_cursor + 1] != '\n') {
        header->value.len++;
        parser->read_cursor++;

        if (parser->read_cursor + 1 > parser->buffer_len)
            goto error;
    }

    parser->read_cursor += 2;
    return (ssize_t)(parser->read_cursor - previous_cursor);

error:
    // we reached the end of the buffer without parsing a key value pair:
    parser->read_cursor = previous_cursor;
    return -1;
}
