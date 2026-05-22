#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/errno.h>

#include <openssl/ssl.h>

#define FATAL(msg, cond)             \
    if (cond) {                      \
        char *str = strerror(errno); \
        if (!str) {                  \
            fprintf(stderr, msg);    \
            fprintf(stderr, "\n");   \
        } else {                     \
            perror(msg);             \
        }                            \
        exit(1);                     \
    }

// The world's very worst http client
void make_https_request()
{
    int r;
    const char *hostname = "registry.npmjs.org";

    // https://docs.openssl.org/master/man7/ossl-guide-tls-client-block/#simple-blocking-tls-client-example
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    FATAL("failed to create ssl ctx", ctx == NULL);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    r = SSL_CTX_set_default_verify_paths(ctx);
    FATAL("failed to set default cert store", !r);

    r = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    FATAL("failed to set min TLS proto version", !r);

    SSL *ssl = SSL_new(ctx);
    FATAL("could not create ssl object", ssl == NULL);

    int s = socket(AF_INET, SOCK_STREAM, 0);
    FATAL("could not create socket", s < 0);

    struct sockaddr_in serveraddr;
    struct hostent *server;

    server = gethostbyname(hostname);
    if (server == NULL) {
        herror("could not find server");
        close(s);
        exit(1);
    }

    bzero(&serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = server->h_addrtype;
    serveraddr.sin_port = htons(443);

    int i = 0;
    int found = 0;
    while (server->h_addr_list[i] != NULL) {
        memcpy(&serveraddr.sin_addr.s_addr, server->h_addr_list[i++], server->h_length);
        printf("trying %s...\n", inet_ntoa(serveraddr.sin_addr));
        r = connect(s, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
        if (r == 0) {
            found = 1;
            break;
        }
    }

    if (found == 0) {
        close(s);
        fprintf(stderr, "could not connect to any server returned by gethostbyname\n");
        exit(1);
    }

    BIO *bio = BIO_new(BIO_s_socket());
    if (bio == NULL) {
        close(s);
        fprintf(stderr, "could not create BIO object for socket\n");
        exit(1);
    }

    BIO_set_fd(bio, s, BIO_CLOSE);
    SSL_set_bio(ssl, bio, bio);

    r = SSL_set_tlsext_host_name(ssl, hostname);
    FATAL("could not set sni hostname", !r);

    r = SSL_set1_host(ssl, hostname);
    FATAL("could not set cert verification hostname", !r);

    if (SSL_connect(ssl) < 1) {
        printf("failed to create ssl connection to server\n");

        if (SSL_get_verify_result(ssl) != X509_V_OK) {
            printf("verify error: %s\n", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        }

        exit(1);
    }

    const char *request = "GET /react/latest HTTP/1.1\r\n"
                          "Host: registry.npmjs.org\r\n" // FIXME don't hard code this but I'm lazy
                          "Connection: close\r\n\r\n";
    int request_len = strlen(request);

    size_t written;
    r = SSL_write_ex(ssl, request, request_len, &written);
    FATAL("couldn't write http request", !r);

    size_t read_bytes_count;
    char buf[1024];

    while (SSL_read_ex(ssl, buf, sizeof(buf), &read_bytes_count)) {
        fwrite(buf, 1, read_bytes_count, stdout);
    }

    printf("\n");
    SSL_free(ssl);
    printf("Done and closed connection\n");
}

int exe_entrypoint(int argc, char **argv)
{
    make_https_request();
    return 1;
}

int test_entrypoint(int argc, char **argv)
{
    return 1;
}

int main(int argc, char **argv)
{
#ifdef TEST
    test_entrypoint(argc, argv);
#else
    exe_entrypoint(argc, argv);
#endif
}
