#ifndef _MOD_HTTP_HEADER
#define _MOD_HTTP_HEADER

#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h"

/**
 * A HTTPS client that represents a connection to a single registry.  If multiple registries are
 * involved in resolving a project's dependencies, one client should be used per registry, as each
 * client holds a single `SSL*` pointer that should be unique per-hostname.
 *
 * The request header that the client holds is purely used as a scratch buffer for assembling the
 * request.  It can be re-purposed by the caller after `http_complete_request`.
 */
typedef struct http_client_t {
    SSL *ssl;
    const char *hostname;
    char *req_header_buf;
    size_t req_header_buf_len;
    size_t req_header_buf_cursor;
} http_client_t;

/**
 * Initializes an SSL_CTX with default settings.  This function should be called once per package
 * manager invocation, and the resulting SSL_CTX pointer should be shared between all created
 * clients.
 * 
 * Returns an SSL_CTX pointer if succeeds, and NULL on error.  If error, check the OpenSSL error
 * stack for details.
 */
SSL_CTX *http_client_init_ssl_ctx(void);

/**
 * Initializes a new https client with an underlying SSL connection to the host. After this function
 * returns, a socket is open and ready to be written to the host server.
 * 
 * Returns 0 on success, and -1 on failure.  The cause of the failure can be found on the OpenSSL
 * error stack and can be retrieved via ERR_get_error(), which can in turn be passed to
 * ERR_error_string() for a human-readable message.
 */
int http_client_init_ssl_connection(struct http_client_t *client, SSL_CTX *ctx);

/**
 * Sends the TLS close_notify message to the server, closes the socket, and frees memory used for
 * the SSL connection.
 */
void http_client_shutdown(struct http_client_t *client);

/**
 * Writes the first control line to the internal scratch buffer used by the client.  e.g. GET
 * /some/path HTTP/1.1
 */
void http_write_control_line(struct http_client_t *client, const char *method, const char *path);

/**
 * Writes a header line (key-value) pair to the internal scratch buffer used by the client.  The
 * header's key and value are passed as-is and are not lowercased or otherwise modified.
 */
void http_write_header(struct http_client_t *client, const char *key, const char *value);

/**
 * Flushes the internal scratch buffer used by the client for constructing the request (e.g. via
 * http_write_header, etc) to the `ssl` pointer owned by the client, then resets the scratch buffer
 * used by the client to prepare it for the next request (if any).
 *
 * The return value of `SSL_write_ex` is returned without modification, and any error can be
 * inspected using that return code using the standard OpenSSL error stack.
 */
int http_complete_request(struct http_client_t *client);

/**
 * Sliding-window stream buffer used to parse HTTP responses.  Various functions operate on this
 * stream to parse the response headers, or stream the response body.
 */
typedef struct http_stream_t {
    SSL *ssl;
    char *buf;
    size_t buf_len;
    /* how far into the buf we've written data */
    size_t write_cursor;
    /* how far into the buf we've consumed data */
    size_t read_cursor;
    /* how many bytes were read on the last read operation */
    size_t last_read_count;
} stream_t;

/**
 * Reads up to chunk_size bytes into the stream buffer and increments the write_cursor.  Returns the
 * response of SSL_read_ex (1 for success and 0 for failure).
 */
int http_stream_read_chunk(struct http_stream_t *stream, size_t chunk_size);

/**
 * Recycles the memory in the buffer, discarding the bytes in the buffer prior to read_cursor. This
 * allows us to use a statically sized buffer while continuously reading data into it.
 */
void http_stream_recycle_buffer(struct http_stream_t *stream);

/**
 * Consumes a single byte from the stream, fetching more data if needed.  
 *
 * Returns -1 on failure. On success, returns the byte value (0-255) in the lower
 * 8 bits, which can be safely cast to unsigned char or read directly as an int.
 *
 */
int http_stream_take_byte(struct http_stream_t *stream);

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
                            size_t *bytes_written);

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
                           char *buf, size_t buf_len, size_t *bytes_consumed);

typedef struct http_header_t {
    string_view_t key;
    string_view_t value;
} http_header_t;

typedef struct http_response_parser_t {
    size_t read_cursor;
    char *buffer;
    size_t buffer_len;
} http_response_parser_t;

/**
 * Consumes a single line (up to and including the next "\r\n") of the parser buffer.  Returns the
 * number of bytes consumed in order to reach the next line, or -1 on error.
 */
ssize_t http_response_parser_skip_line(http_response_parser_t *parser);

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
ssize_t http_response_parser_read_next_header(http_response_parser_t *parser,
                                              http_header_t *header);

#endif // _MOD_HTTP_HEADER
