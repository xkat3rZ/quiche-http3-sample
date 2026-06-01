// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// HTTP/3 Server with Alt-Svc Discovery
//
// This example demonstrates a dual-protocol server that:
// 1. Runs a TCP/TLS HTTP/2 server that advertises HTTP/3 via Alt-Svc header
// 2. Runs a QUIC/HTTP/3 server on the same port
//
// When a client (like Chrome) connects via TCP, it receives the Alt-Svc header
// indicating HTTP/3 is available. The client can then upgrade to HTTP/3 for
// subsequent requests.

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <ev.h>
#include <uthash.h>

#include <quiche.h>

#define LOCAL_CONN_ID_LEN 16

#define MAX_DATAGRAM_SIZE 1350

#define MAX_TOKEN_LEN \
    sizeof("quiche") - 1 + \
    sizeof(struct sockaddr_storage) + \
    QUICHE_MAX_CONN_ID_LEN

#define LISTEN_HOST "127.0.0.1"
#define LISTEN_PORT "4433"

#define CERT_FILE "./cert-quic-chain.crt"
#define KEY_FILE  "./cert-quic.key"

// If 1, the TCP landing page auto-refreshes after 3 seconds, triggering
// an HTTP/3 connection to download the file. If 0, the user must
// manually click the link.
#define DEBUG_FILE 1

// File to serve over HTTP/3.
#define FILE_PATH "./hello.txt"

// HTML response for the TCP landing page when DEBUG_FILE is enabled.
// Auto-refreshes to /hello.txt after 3 seconds via HTTP/3.
static const char HTTP2_RESPONSE_AUTO[] =
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head>\n"
    "<title>HTTP/3 Download</title>\n"
    "<meta http-equiv=\"refresh\" content=\"3;url=https://127.0.0.1:4433/hello.txt\">\n"
    "</head>\n"
    "<body>\n"
    "<h1>HTTP/3 Download</h1>\n"
    "<p>Downloading file via HTTP/3 in 3 seconds...</p>\n"
    "</body>\n"
    "</html>";

// HTML response for the TCP landing page when DEBUG_FILE is disabled.
// User must manually click the link.
static const char HTTP2_RESPONSE_MANUAL[] =
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head><title>HTTP/3 Download</title></head>\n"
    "<body>\n"
    "<h1>HTTP/3 Download</h1>\n"
    "<p><a href=\"https://127.0.0.1:4433/hello.txt\">Click to download "
    "file via HTTP/3</a></p>\n"
    "</body>\n"
    "</html>";

// HTML served over HTTP/3 at / when DEBUG_FILE is enabled.
static const char H3_LANDING_AUTO[] =
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head>\n"
    "<meta http-equiv=\"refresh\" content=\"3;url=/hello.txt\">\n"
    "</head>\n"
    "<body>\n"
    "<h1>HTTP/3 Connected</h1>\n"
    "<p>Downloading file in 3 seconds...</p>\n"
    "</body>\n"
    "</html>";

// HTML served over HTTP/3 at / when DEBUG_FILE is disabled.
static const char H3_LANDING_MANUAL[] =
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<body>\n"
    "<h1>HTTP/3 Connected</h1>\n"
    "<p><a href=\"/hello.txt\">Download file</a></p>\n"
    "</body>\n"
    "</html>";

// Global buffer to hold the file content.
static uint8_t *file_content = NULL;
static size_t file_content_len = 0;

// Load file content into memory.
static bool load_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "failed to open file: %s\n", path);
        return false;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fprintf(stderr, "file is empty or error: %s\n", path);
        fclose(f);
        return false;
    }

    file_content = malloc((size_t) size);
    if (file_content == NULL) {
        fprintf(stderr, "failed to allocate memory for file\n");
        fclose(f);
        return false;
    }

    size_t read = fread(file_content, 1, (size_t) size, f);
    fclose(f);

    if (read != (size_t) size) {
        fprintf(stderr, "failed to read entire file\n");
        free(file_content);
        file_content = NULL;
        return false;
    }

    file_content_len = (size_t) size;
    fprintf(stderr, "loaded %zu bytes from %s\n", file_content_len, path);
    return true;
}

// Alt-Svc header value advertising HTTP/3 on port 4433.
#define ALT_SVC_VALUE "h3=\":4433\"; ma=86400; persist=1"

// Tracks partial HTTP/3 responses that couldn't be sent in one go.
struct partial_response {
    uint64_t stream_id;

    uint8_t *body;
    size_t body_len;
    size_t written;

    bool headers_sent;

    UT_hash_handle hh;
};

// Represents a single QUIC client connection and its associated state.
struct conn_io {
    ev_timer timer;

    int sock;

    uint8_t cid[LOCAL_CONN_ID_LEN];

    quiche_conn *conn;
    quiche_h3_conn *http3;

    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;

    struct partial_response *partial_responses;

    UT_hash_handle hh;
};

struct connections {
    int sock;

    struct sockaddr *local_addr;
    socklen_t local_addr_len;

    struct conn_io *h;
};

static quiche_config *config = NULL;

static quiche_h3_config *http3_config = NULL;

static struct connections *conns = NULL;

static void timeout_cb(EV_P_ ev_timer *w, int revents);

static void debug_log(const char *line, void *argp) {
    fprintf(stderr, "%s\n", line);
}

// Flush all pending QUIC egress packets for a connection.
static void flush_egress(struct ev_loop *loop, struct conn_io *conn_io) {
    static uint8_t out[MAX_DATAGRAM_SIZE];

    quiche_send_info send_info;

    while (1) {
        ssize_t written = quiche_conn_send(conn_io->conn, out, sizeof(out),
                                           &send_info);

        if (written == QUICHE_ERR_DONE) {
            fprintf(stderr, "done writing\n");
            break;
        }

        if (written < 0) {
            fprintf(stderr, "failed to create packet: %zd\n", written);
            return;
        }

        ssize_t sent = sendto(conn_io->sock, out, written, 0,
                              (struct sockaddr *) &send_info.to,
                              send_info.to_len);
        if (sent != written) {
            perror("failed to send");
            return;
        }

        fprintf(stderr, "sent %zd bytes\n", sent);
    }

    double t = quiche_conn_timeout_as_nanos(conn_io->conn) / 1e9f;
    conn_io->timer.repeat = t;
    ev_timer_again(loop, &conn_io->timer);
}

// Validates a stateless retry token.
static bool validate_token(const uint8_t *token, size_t token_len,
                           struct sockaddr_storage *addr, socklen_t addr_len,
                           uint8_t *odcid, size_t *odcid_len) {
    if ((token_len < sizeof("quiche") - 1) ||
         memcmp(token, "quiche", sizeof("quiche") - 1)) {
        return false;
    }

    token += sizeof("quiche") - 1;
    token_len -= sizeof("quiche") - 1;

    if ((token_len < addr_len) || memcmp(token, addr, addr_len)) {
        return false;
    }

    token += addr_len;
    token_len -= addr_len;

    if (*odcid_len < token_len) {
        return false;
    }

    memcpy(odcid, token, token_len);
    *odcid_len = token_len;

    return true;
}

static uint8_t *gen_cid(uint8_t *cid, size_t cid_len) {
    int rng = open("/dev/urandom", O_RDONLY);
    if (rng < 0) {
        perror("failed to open /dev/urandom");
        return NULL;
    }

    ssize_t rand_len = read(rng, cid, cid_len);
    close(rng);
    if (rand_len < 0) {
        perror("failed to create connection ID");
        return NULL;
    }

    return cid;
}

// Create a new QUIC connection and add it to the connection map.
static struct conn_io *create_conn(uint8_t *scid, size_t scid_len,
                                   uint8_t *odcid, size_t odcid_len,
                                   struct sockaddr *local_addr,
                                   socklen_t local_addr_len,
                                   struct sockaddr_storage *peer_addr,
                                   socklen_t peer_addr_len)
{
    struct conn_io *conn_io = calloc(1, sizeof(*conn_io));
    if (conn_io == NULL) {
        fprintf(stderr, "failed to allocate connection IO\n");
        return NULL;
    }

    if (scid_len != LOCAL_CONN_ID_LEN) {
        fprintf(stderr, "failed, scid length too short\n");
    }

    memcpy(conn_io->cid, scid, LOCAL_CONN_ID_LEN);

    quiche_conn *conn = quiche_accept(conn_io->cid, LOCAL_CONN_ID_LEN,
                                      odcid, odcid_len,
                                      local_addr,
                                      local_addr_len,
                                      (struct sockaddr *) peer_addr,
                                      peer_addr_len,
                                      config);

    if (conn == NULL) {
        fprintf(stderr, "failed to create connection\n");
        free(conn_io);
        return NULL;
    }

    conn_io->sock = conns->sock;
    conn_io->conn = conn;
    conn_io->http3 = NULL;
    conn_io->partial_responses = NULL;

    memcpy(&conn_io->peer_addr, peer_addr, peer_addr_len);
    conn_io->peer_addr_len = peer_addr_len;

    ev_init(&conn_io->timer, timeout_cb);
    conn_io->timer.data = conn_io;

    HASH_ADD(hh, conns->h, cid, LOCAL_CONN_ID_LEN, conn_io);

    fprintf(stderr, "new connection\n");

    return conn_io;
}

// Log HTTP headers for debugging.
static int for_each_header(uint8_t *name, size_t name_len,
                           uint8_t *value, size_t value_len,
                           void *argp) {
    fprintf(stderr, "got HTTP header: %.*s=%.*s\n",
            (int) name_len, name, (int) value_len, value);

    return 0;
}

// Extract the :path pseudo-header from an HTTP/3 event.
static int for_each_header_path(uint8_t *name, size_t name_len,
                                uint8_t *value, size_t value_len,
                                void *argp) {
    if (name_len == 5 && memcmp(name, ":path", 5) == 0) {
        char **path = (char **) argp;
        *path = strndup((const char *) value, value_len);
    }

    return 0;
}

// Handle an incoming HTTP/3 request by sending a response with Alt-Svc.
static void handle_request(struct conn_io *conn_io, int64_t stream_id,
                           quiche_h3_event *ev) {
    quiche_h3_event_for_each_header(ev, for_each_header, NULL);

    // Extract the request path.
    char *path = NULL;
    quiche_h3_event_for_each_header(ev, for_each_header_path, &path);

    // Stop reading the request stream since we only need headers.
    quiche_conn_stream_shutdown(conn_io->conn, stream_id,
                                QUICHE_SHUTDOWN_READ, 0);

    // Serve landing page HTML on /, file content on any other path.
    const uint8_t *body;
    size_t body_len;
    const char *content_type;

    if (path == NULL || strcmp(path, "/") == 0) {
        if (DEBUG_FILE) {
            body = (const uint8_t *) H3_LANDING_AUTO;
            body_len = sizeof(H3_LANDING_AUTO) - 1;
        } else {
            body = (const uint8_t *) H3_LANDING_MANUAL;
            body_len = sizeof(H3_LANDING_MANUAL) - 1;
        }
        content_type = "text/html";
    } else {
        body = file_content;
        body_len = file_content_len;
        content_type = "application/octet-stream";
    }

    free(path);

    char content_length[32];
    snprintf(content_length, sizeof(content_length), "%zu", body_len);

    quiche_h3_header headers[] = {
        {
            .name = (const uint8_t *) ":status",
            .name_len = sizeof(":status") - 1,
            .value = (const uint8_t *) "200",
            .value_len = sizeof("200") - 1,
        },
        {
            .name = (const uint8_t *) "server",
            .name_len = sizeof("server") - 1,
            .value = (const uint8_t *) "quiche",
            .value_len = sizeof("quiche") - 1,
        },
        {
            .name = (const uint8_t *) "content-type",
            .name_len = sizeof("content-type") - 1,
            .value = (const uint8_t *) content_type,
            .value_len = strlen(content_type),
        },
        {
            .name = (const uint8_t *) "content-length",
            .name_len = sizeof("content-length") - 1,
            .value = (const uint8_t *) content_length,
            .value_len = strlen(content_length),
        },
        {
            .name = (const uint8_t *) "alt-svc",
            .name_len = sizeof("alt-svc") - 1,
            .value = (const uint8_t *) ALT_SVC_VALUE,
            .value_len = sizeof(ALT_SVC_VALUE) - 1,
        },
    };

    // Send response headers.
    int rc = quiche_h3_send_response(conn_io->http3, conn_io->conn,
                                     stream_id, headers, 5, false);

    if (rc == QUICHE_H3_ERR_STREAM_BLOCKED) {
        // Stream blocked - save partial response for later.
        struct partial_response *resp = calloc(1, sizeof(*resp));
        if (resp == NULL) {
            fprintf(stderr, "failed to allocate partial response\n");
            return;
        }

        resp->stream_id = stream_id;
        resp->body = malloc(body_len);
        if (resp->body == NULL) {
            free(resp);
            return;
        }
        memcpy(resp->body, body, body_len);
        resp->body_len = body_len;
        resp->written = 0;
        resp->headers_sent = false;

        HASH_ADD(hh, conn_io->partial_responses, stream_id,
                 sizeof(uint64_t), resp);
        return;
    }

    if (rc != 0) {
        fprintf(stderr, "failed to send response headers: %d\n", rc);
        return;
    }

    // Send response body.
    ssize_t written = quiche_h3_send_body(conn_io->http3, conn_io->conn,
                                          stream_id, body, body_len, true);

    if (written == QUICHE_H3_ERR_DONE || written == 0) {
        written = 0;
    } else if (written < 0) {
        fprintf(stderr, "failed to send response body: %zd\n", written);
        return;
    }

    // If we couldn't send the entire body, save the remainder.
    if ((size_t) written < body_len) {
        struct partial_response *resp = calloc(1, sizeof(*resp));
        if (resp == NULL) {
            fprintf(stderr, "failed to allocate partial response\n");
            return;
        }

        resp->stream_id = stream_id;
        resp->body = malloc(body_len);
        if (resp->body == NULL) {
            free(resp);
            return;
        }
        memcpy(resp->body, body, body_len);
        resp->body_len = body_len;
        resp->written = (size_t) written;
        resp->headers_sent = true;

        HASH_ADD(hh, conn_io->partial_responses, stream_id,
                 sizeof(uint64_t), resp);
    }
}

// Handle writable streams by continuing partial responses.
static void handle_writable(struct conn_io *conn_io, uint64_t stream_id) {
    struct partial_response *resp = NULL;

    HASH_FIND(hh, conn_io->partial_responses, &stream_id,
              sizeof(uint64_t), resp);

    if (resp == NULL) {
        return;
    }

    // Send headers if they haven't been sent yet.
    if (!resp->headers_sent) {
        size_t body_len = resp->body_len;

        char content_length[32];
        snprintf(content_length, sizeof(content_length), "%zu", body_len);

        quiche_h3_header headers[] = {
            {
                .name = (const uint8_t *) ":status",
                .name_len = sizeof(":status") - 1,
                .value = (const uint8_t *) "200",
                .value_len = sizeof("200") - 1,
            },
            {
                .name = (const uint8_t *) "server",
                .name_len = sizeof("server") - 1,
                .value = (const uint8_t *) "quiche",
                .value_len = sizeof("quiche") - 1,
            },
            {
                .name = (const uint8_t *) "content-type",
                .name_len = sizeof("content-type") - 1,
                .value = (const uint8_t *) "application/octet-stream",
                .value_len = sizeof("application/octet-stream") - 1,
            },
            {
                .name = (const uint8_t *) "content-length",
                .name_len = sizeof("content-length") - 1,
                .value = (const uint8_t *) content_length,
                .value_len = strlen(content_length),
            },
            {
                .name = (const uint8_t *) "alt-svc",
                .name_len = sizeof("alt-svc") - 1,
                .value = (const uint8_t *) ALT_SVC_VALUE,
                .value_len = sizeof(ALT_SVC_VALUE) - 1,
            },
        };

        int rc = quiche_h3_send_response(conn_io->http3, conn_io->conn,
                                         stream_id, headers, 5, false);

        if (rc == QUICHE_H3_ERR_STREAM_BLOCKED) {
            return;
        }

        if (rc != 0) {
            fprintf(stderr, "failed to send response headers: %d\n", rc);
            HASH_DELETE(hh, conn_io->partial_responses, resp);
            free(resp->body);
            free(resp);
            return;
        }

        resp->headers_sent = true;
    }

    // Send remaining body.
    const uint8_t *remaining = resp->body + resp->written;
    size_t remaining_len = resp->body_len - resp->written;

    ssize_t written = quiche_h3_send_body(conn_io->http3, conn_io->conn,
                                          stream_id, remaining,
                                          remaining_len, true);

    if (written == QUICHE_H3_ERR_DONE) {
        written = 0;
    } else if (written < 0) {
        fprintf(stderr, "failed to send body: %zd\n", written);
        HASH_DELETE(hh, conn_io->partial_responses, resp);
        free(resp->body);
        free(resp);
        return;
    }

    resp->written += (size_t) written;

    // Remove the partial response if completely sent.
    if (resp->written >= resp->body_len) {
        HASH_DELETE(hh, conn_io->partial_responses, resp);
        free(resp->body);
        free(resp);
    }
}

// Free all partial responses for a connection.
static void free_partial_responses(struct conn_io *conn_io) {
    struct partial_response *resp, *tmp;

    HASH_ITER(hh, conn_io->partial_responses, resp, tmp) {
        HASH_DELETE(hh, conn_io->partial_responses, resp);
        free(resp->body);
        free(resp);
    }
}

// Main QUIC receive callback - reads packets and processes HTTP/3 events.
static void recv_cb(EV_P_ ev_io *w, int revents) {
    struct conn_io *tmp, *conn_io = NULL;

    static uint8_t buf[65535];
    static uint8_t out[MAX_DATAGRAM_SIZE];

    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);
        memset(&peer_addr, 0, peer_addr_len);

        ssize_t read = recvfrom(conns->sock, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_addr,
                                &peer_addr_len);

        if (read < 0) {
            if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
                fprintf(stderr, "recv would block\n");
                break;
            }

            perror("failed to read");
            return;
        }

        uint8_t type;
        uint32_t version;

        uint8_t scid[QUICHE_MAX_CONN_ID_LEN];
        size_t scid_len = sizeof(scid);

        uint8_t dcid[QUICHE_MAX_CONN_ID_LEN];
        size_t dcid_len = sizeof(dcid);

        uint8_t odcid[QUICHE_MAX_CONN_ID_LEN];
        size_t odcid_len = sizeof(odcid);

        uint8_t token[MAX_TOKEN_LEN];
        size_t token_len = sizeof(token);

        int rc = quiche_header_info(buf, read, LOCAL_CONN_ID_LEN, &version,
                                    &type, scid, &scid_len, dcid, &dcid_len,
                                    token, &token_len);
        if (rc < 0) {
            fprintf(stderr, "failed to parse header: %d\n", rc);
            return;
        }

        HASH_FIND(hh, conns->h, dcid, dcid_len, conn_io);

        if (conn_io == NULL) {
            // New connection - must be an Initial packet.
            if (!quiche_version_is_supported(version)) {
                fprintf(stderr, "version negotiation\n");

                ssize_t written = quiche_negotiate_version(scid, scid_len,
                                                           dcid, dcid_len,
                                                           out, sizeof(out));

                if (written < 0) {
                    fprintf(stderr, "failed to create vneg packet: %zd\n",
                            written);
                    continue;
                }

                ssize_t sent = sendto(conns->sock, out, written, 0,
                                      (struct sockaddr *) &peer_addr,
                                      peer_addr_len);
                if (sent != written) {
                    perror("failed to send");
                    continue;
                }

                fprintf(stderr, "sent %zd bytes\n", sent);
                continue;
            }

            // Skip stateless retry for better browser interop.
            // Production servers should use stateless retry for DDoS
            // protection, but Chrome has interop issues with Retry packets.
            if (token_len == 0) {
                // No token - accept directly (skip retry).
                odcid_len = 0;
            } else {
                if (!validate_token(token, token_len, &peer_addr,
                                    peer_addr_len, odcid, &odcid_len)) {
                    fprintf(stderr, "invalid address validation token\n");
                    continue;
                }

                if (LOCAL_CONN_ID_LEN != dcid_len) {
                    fprintf(stderr, "invalid destination connection ID\n");
                    continue;
                }
            }

            uint8_t new_cid[LOCAL_CONN_ID_LEN];
            if (gen_cid(new_cid, LOCAL_CONN_ID_LEN) == NULL) {
                continue;
            }

            conn_io = create_conn(new_cid, LOCAL_CONN_ID_LEN,
                                  odcid_len > 0 ? odcid : NULL,
                                  odcid_len > 0 ? odcid_len : 0,
                                  conns->local_addr, conns->local_addr_len,
                                  &peer_addr, peer_addr_len);

            if (conn_io == NULL) {
                continue;
            }
        }

        quiche_recv_info recv_info = {
            (struct sockaddr *)&peer_addr,
            peer_addr_len,

            conns->local_addr,
            conns->local_addr_len,
        };

        ssize_t done = quiche_conn_recv(conn_io->conn, buf, read, &recv_info);

        if (done < 0) {
            fprintf(stderr, "failed to process packet: %zd\n", done);
            continue;
        }

        fprintf(stderr, "recv %zd bytes\n", done);

        if (quiche_conn_is_established(conn_io->conn) ||
            quiche_conn_is_in_early_data(conn_io->conn)) {
            // Create HTTP/3 connection once QUIC handshake completes.
            if (conn_io->http3 == NULL) {
                conn_io->http3 = quiche_h3_conn_new_with_transport(
                    conn_io->conn, http3_config);
                if (conn_io->http3 == NULL) {
                    fprintf(stderr, "failed to create HTTP/3 connection\n");
                    continue;
                }
            }

            // Handle writable streams for partial responses.
            quiche_stream_iter *writable =
                quiche_conn_writable(conn_io->conn);

            uint64_t stream_id;
            while (quiche_stream_iter_next(writable, &stream_id)) {
                handle_writable(conn_io, stream_id);
            }

            quiche_stream_iter_free(writable);

            // Process HTTP/3 events.
            quiche_h3_event *ev;

            while (1) {
                int64_t s = quiche_h3_conn_poll(conn_io->http3,
                                                conn_io->conn,
                                                &ev);

                if (s < 0) {
                    break;
                }

                switch (quiche_h3_event_type(ev)) {
                    case QUICHE_H3_EVENT_HEADERS: {
                        handle_request(conn_io, s, ev);
                        break;
                    }

                    case QUICHE_H3_EVENT_DATA: {
                        fprintf(stderr, "got HTTP data\n");
                        break;
                    }

                    case QUICHE_H3_EVENT_FINISHED:
                        break;

                    case QUICHE_H3_EVENT_RESET:
                        break;

                    case QUICHE_H3_EVENT_PRIORITY_UPDATE:
                        break;

                    case QUICHE_H3_EVENT_GOAWAY: {
                        fprintf(stderr, "got GOAWAY\n");
                        break;
                    }
                }

                quiche_h3_event_free(ev);
            }
        }
    }

    // Flush egress and garbage collect closed connections.
    HASH_ITER(hh, conns->h, conn_io, tmp) {
        flush_egress(loop, conn_io);

        if (quiche_conn_is_closed(conn_io->conn)) {
            quiche_stats stats;
            quiche_path_stats path_stats;

            quiche_conn_stats(conn_io->conn, &stats);
            quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

            fprintf(stderr, "connection closed, recv=%zu sent=%zu "
                    "lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
                    stats.recv, stats.sent, stats.lost,
                    path_stats.rtt, path_stats.cwnd);

            HASH_DELETE(hh, conns->h, conn_io);

            ev_timer_stop(loop, &conn_io->timer);

            free_partial_responses(conn_io);
            quiche_h3_conn_free(conn_io->http3);
            quiche_conn_free(conn_io->conn);
            free(conn_io);
        }
    }
}

// Timeout callback for QUIC connections.
static void timeout_cb(EV_P_ ev_timer *w, int revents) {
    struct conn_io *conn_io = w->data;
    quiche_conn_on_timeout(conn_io->conn);

    fprintf(stderr, "timeout\n");

    flush_egress(loop, conn_io);

    if (quiche_conn_is_closed(conn_io->conn)) {
        quiche_stats stats;
        quiche_path_stats path_stats;

        quiche_conn_stats(conn_io->conn, &stats);
        quiche_conn_path_stats(conn_io->conn, 0, &path_stats);

        fprintf(stderr, "connection closed, recv=%zu sent=%zu "
                "lost=%zu rtt=%" PRIu64 "ns cwnd=%zu\n",
                stats.recv, stats.sent, stats.lost,
                path_stats.rtt, path_stats.cwnd);

        HASH_DELETE(hh, conns->h, conn_io);

        ev_timer_stop(loop, &conn_io->timer);

        free_partial_responses(conn_io);
        quiche_h3_conn_free(conn_io->http3);
        quiche_conn_free(conn_io->conn);
        free(conn_io);

        return;
    }
}

// --- HTTP/2 over TCP/TLS server ---

// Construct an HTTP/2 frame (9-byte header + payload).
static void write_h2_frame(uint8_t *buf, uint8_t frame_type, uint8_t flags,
                           uint32_t stream_id, const uint8_t *payload,
                           size_t payload_len, size_t *offset) {
    buf[*offset + 0] = (payload_len >> 16) & 0xff;
    buf[*offset + 1] = (payload_len >> 8) & 0xff;
    buf[*offset + 2] = payload_len & 0xff;
    buf[*offset + 3] = frame_type;
    buf[*offset + 4] = flags;
    buf[*offset + 5] = (stream_id >> 24) & 0x7f;
    buf[*offset + 6] = (stream_id >> 16) & 0xff;
    buf[*offset + 7] = (stream_id >> 8) & 0xff;
    buf[*offset + 8] = stream_id & 0xff;
    *offset += 9;

    if (payload_len > 0) {
        memcpy(buf + *offset, payload, payload_len);
        *offset += payload_len;
    }
}

// Read exactly n bytes from an SSL connection.
static bool ssl_read_exact(SSL *ssl, uint8_t *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        int n = SSL_read(ssl, buf + total, (int)(len - total));
        if (n <= 0) {
            return false;
        }
        total += (size_t) n;
    }
    return true;
}

// Handle a single HTTP/1.1 connection over TLS.
// Reads the request and sends an HTTP/1.1 response with Alt-Svc.
static void handle_http11_connection(SSL *ssl) {
    char request[4096];
    int n = SSL_read(ssl, request, sizeof(request) - 1);
    if (n <= 0) {
        fprintf(stderr, "H1: failed to read request\n");
        return;
    }
    request[n] = '\0';

    fprintf(stderr, "H1: received request:\n%s\n", request);

    // Build HTTP/1.1 response with Alt-Svc header.
    const char *body = DEBUG_FILE ? HTTP2_RESPONSE_AUTO : HTTP2_RESPONSE_MANUAL;
    size_t body_len = strlen(body);

    char response[8192];
    int resp_len = snprintf(response, sizeof(response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %zu\r\n"
        "Alt-Svc: %s\r\n"
        "Server: quiche\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        body_len, ALT_SVC_VALUE, body);

    if (SSL_write(ssl, response, resp_len) <= 0) {
        fprintf(stderr, "H1: failed to send response\n");
        return;
    }

    fprintf(stderr, "H1: sent response with Alt-Svc: %s\n", ALT_SVC_VALUE);
}

// Handle a single HTTP/2 connection over TLS.
// Performs a minimal HTTP/2 handshake and serves a response with Alt-Svc.
static void handle_http2_connection(SSL_CTX *ssl_ctx, int client_fd) {
    SSL *ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        fprintf(stderr, "H2: failed to create SSL object\n");
        close(client_fd);
        return;
    }

    SSL_set_fd(ssl, client_fd);

    // Perform TLS handshake.
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "H2: TLS handshake failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    fprintf(stderr, "H2: TLS handshake complete\n");

    // Check what ALPN protocol was negotiated.
    const unsigned char *alpn_proto = NULL;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn_proto, &alpn_len);

    if (alpn_len == 0 || (alpn_len != 2 || memcmp(alpn_proto, "h2", 2) != 0)) {
        // No ALPN or not HTTP/2 - handle as HTTP/1.1.
        fprintf(stderr, "H2: ALPN did not select h2, handling as HTTP/1.1\n");
        handle_http11_connection(ssl);
        goto cleanup;
    }

    fprintf(stderr, "H2: ALPN selected h2\n");

    // Read the HTTP/2 connection preface (24 bytes).
    uint8_t preface[24];
    if (!ssl_read_exact(ssl, preface, 24)) {
        fprintf(stderr, "H2: failed to read connection preface\n");
        goto cleanup;
    }

    if (memcmp(preface, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24) != 0) {
        fprintf(stderr, "H2: invalid connection preface\n");
        goto cleanup;
    }

    fprintf(stderr, "H2: connection preface received\n");

    // Read the client's SETTINGS frame header.
    uint8_t frame_header[9];
    if (!ssl_read_exact(ssl, frame_header, 9)) {
        fprintf(stderr, "H2: failed to read SETTINGS frame header\n");
        goto cleanup;
    }

    size_t payload_len = ((size_t) frame_header[0] << 16) |
                         ((size_t) frame_header[1] << 8) |
                         ((size_t) frame_header[2]);
    uint8_t frame_type = frame_header[3];

    if (frame_type != 0x04) {
        fprintf(stderr, "H2: expected SETTINGS frame, got type %u\n",
                frame_type);
        goto cleanup;
    }

    // Consume the SETTINGS payload.
    if (payload_len > 0) {
        uint8_t *settings_payload = malloc(payload_len);
        if (settings_payload == NULL) {
            goto cleanup;
        }
        if (!ssl_read_exact(ssl, settings_payload, payload_len)) {
            free(settings_payload);
            goto cleanup;
        }
        free(settings_payload);
    }

    // Send our SETTINGS frame.
    uint8_t settings_buf[512];
    size_t settings_off = 0;

    // Build SETTINGS payload: 4 settings, each 6 bytes (2 ID + 4 value).
    uint8_t settings_payload[24];
    size_t sp_off = 0;

    // SETTINGS_HEADER_TABLE_SIZE (0x1) = 4096
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x01;
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x00;
    settings_payload[sp_off++] = 0x10; settings_payload[sp_off++] = 0x00;

    // SETTINGS_ENABLE_PUSH (0x2) = 0
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x02;
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x00;
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x00;

    // SETTINGS_MAX_CONCURRENT_STREAMS (0x3) = 100
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x03;
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x00;
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x64;

    // SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 65535
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x04;
    settings_payload[sp_off++] = 0x00; settings_payload[sp_off++] = 0x00;
    settings_payload[sp_off++] = 0xff; settings_payload[sp_off++] = 0xff;

    write_h2_frame(settings_buf, 0x04, 0x00, 0,
                   settings_payload, sp_off, &settings_off);

    if (SSL_write(ssl, settings_buf, (int) settings_off) <= 0) {
        goto cleanup;
    }

    // ACK the client's SETTINGS.
    uint8_t ack_buf[9];
    size_t ack_off = 0;
    write_h2_frame(ack_buf, 0x04, 0x01, 0, NULL, 0, &ack_off);

    if (SSL_write(ssl, ack_buf, (int) ack_off) <= 0) {
        goto cleanup;
    }

    // Read frames until we see a HEADERS frame.
    uint32_t request_stream_id = 0;
    bool headers_seen = false;

    while (!headers_seen) {
        if (!ssl_read_exact(ssl, frame_header, 9)) {
            goto cleanup;
        }

        payload_len = ((size_t) frame_header[0] << 16) |
                      ((size_t) frame_header[1] << 8) |
                      ((size_t) frame_header[2]);
        frame_type = frame_header[3];
        uint8_t flags = frame_header[4];
        uint32_t stream_id =
            ((uint32_t)(frame_header[5] & 0x7f) << 24) |
            ((uint32_t) frame_header[6] << 16) |
            ((uint32_t) frame_header[7] << 8) |
            ((uint32_t) frame_header[8]);

        // Consume the frame payload.
        if (payload_len > 0) {
            uint8_t *payload = malloc(payload_len);
            if (payload == NULL) {
                goto cleanup;
            }
            if (!ssl_read_exact(ssl, payload, payload_len)) {
                free(payload);
                goto cleanup;
            }
            free(payload);
        }

        if (frame_type == 0x01 && (flags & 0x04)) {
            // HEADERS frame with END_HEADERS flag.
            headers_seen = true;
            request_stream_id = stream_id;
        }
        // SETTINGS ACK and other frames are ignored.
    }

    // Build the response body.
    const char *body = DEBUG_FILE ? HTTP2_RESPONSE_AUTO : HTTP2_RESPONSE_MANUAL;
    size_t body_len = strlen(body);

    char body_len_str[32];
    snprintf(body_len_str, sizeof(body_len_str), "%zu", body_len);
    size_t body_len_str_len = strlen(body_len_str);

    // Encode response headers with HPACK.
    uint8_t hpack[256];
    size_t hpack_len = 0;

    // :status: 200 (indexed, static table index 8).
    hpack[hpack_len++] = 0x88;

    // content-type: text/html (literal with indexed name, index 31).
    hpack[hpack_len++] = 0x40 | 31; // 0x5f
    hpack[hpack_len++] = 0x09;
    memcpy(hpack + hpack_len, "text/html", 9);
    hpack_len += 9;

    // alt-svc header advertising HTTP/3 (literal, new name).
    hpack[hpack_len++] = 0x40;
    hpack[hpack_len++] = 0x07;
    memcpy(hpack + hpack_len, "alt-svc", 7);
    hpack_len += 7;
    hpack[hpack_len++] = (uint8_t)(sizeof(ALT_SVC_VALUE) - 1);
    memcpy(hpack + hpack_len, ALT_SVC_VALUE, sizeof(ALT_SVC_VALUE) - 1);
    hpack_len += sizeof(ALT_SVC_VALUE) - 1;

    // server: quiche (literal with indexed name, index 54).
    hpack[hpack_len++] = 0x40 | 54; // 0x76
    hpack[hpack_len++] = 0x06;
    memcpy(hpack + hpack_len, "quiche", 6);
    hpack_len += 6;

    // content-length (literal with indexed name, index 28).
    hpack[hpack_len++] = 0x40 | 28; // 0x5c
    hpack[hpack_len++] = (uint8_t) body_len_str_len;
    memcpy(hpack + hpack_len, body_len_str, body_len_str_len);
    hpack_len += body_len_str_len;

    // Send HEADERS frame with END_HEADERS flag.
    uint8_t resp_buf[4096];
    size_t resp_off = 0;
    write_h2_frame(resp_buf, 0x01, 0x04, request_stream_id,
                   hpack, hpack_len, &resp_off);

    if (SSL_write(ssl, resp_buf, (int) resp_off) <= 0) {
        fprintf(stderr, "H2: failed to send HEADERS frame\n");
        goto cleanup;
    }

    fprintf(stderr, "H2: sent HEADERS with alt-svc: %s\n", ALT_SVC_VALUE);

    // Send DATA frame with END_STREAM flag.
    resp_off = 0;
    write_h2_frame(resp_buf, 0x00, 0x01, request_stream_id,
                   (const uint8_t *) body, body_len, &resp_off);

    if (SSL_write(ssl, resp_buf, (int) resp_off) <= 0) {
        fprintf(stderr, "H2: failed to send DATA frame\n");
        goto cleanup;
    }

    fprintf(stderr, "H2: sent DATA frame with %zu bytes\n", body_len);

    // Shutdown TLS to force the browser to make a new connection,
    // which will trigger Alt-Svc evaluation.
    SSL_shutdown(ssl);
    fprintf(stderr, "H2: connection closed\n");

cleanup:
    SSL_free(ssl);
    close(client_fd);
}

// ALPN selection callback - select "h2" or "http/1.1" from client's list.
static int alpn_select_cb(SSL *ssl,
                          const unsigned char **out,
                          unsigned char *outlen,
                          const unsigned char *in,
                          unsigned int inlen,
                          void *arg) {
    (void) ssl;
    (void) arg;

    // Parse ALPN wire format: length-prefixed strings.
    unsigned int i = 0;
    while (i < inlen) {
        unsigned int len = in[i];
        if (i + 1 + len <= inlen) {
            // Prefer h2 if available.
            if (len == 2 && memcmp(in + i + 1, "h2", 2) == 0) {
                *out = in + i + 1;
                *outlen = 2;
                return SSL_TLSEXT_ERR_OK;
            }
        }
        i += 1 + len;
    }

    // Fall back to http/1.1 if h2 not available.
    i = 0;
    while (i < inlen) {
        unsigned int len = in[i];
        if (i + 1 + len <= inlen) {
            if (len == 8 && memcmp(in + i + 1, "http/1.1", 8) == 0) {
                *out = in + i + 1;
                *outlen = 8;
                return SSL_TLSEXT_ERR_OK;
            }
        }
        i += 1 + len;
    }

    return SSL_TLSEXT_ERR_NOACK;
}

// TCP/TLS HTTP/2 server thread entry point.
static void *http2_server_thread(void *arg) {
    (void) arg;

    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_server_method());
    if (ssl_ctx == NULL) {
        fprintf(stderr, "H2: failed to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, CERT_FILE) != 1) {
        fprintf(stderr, "H2: failed to load certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE,
                                     SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "H2: failed to load private key\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
        fprintf(stderr, "H2: private key check failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    // Disable session tickets to prevent TLS 1.3 resumption issues.
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);

    // Set ALPN to select h2.
    SSL_CTX_set_alpn_select_cb(ssl_ctx, alpn_select_cb, NULL);

    // Create TCP listening socket.
    const struct addrinfo hints = {
        .ai_family = PF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
        .ai_flags = AI_PASSIVE,
    };

    struct addrinfo *local;
    if (getaddrinfo(LISTEN_HOST, LISTEN_PORT, &hints, &local) != 0) {
        perror("H2: failed to resolve host");
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    int listen_fd = socket(local->ai_family, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("H2: failed to create socket");
        freeaddrinfo(local);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(listen_fd, local->ai_addr, local->ai_addrlen) < 0) {
        perror("H2: failed to bind socket");
        close(listen_fd);
        freeaddrinfo(local);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    if (listen(listen_fd, 128) < 0) {
        perror("H2: failed to listen");
        close(listen_fd);
        freeaddrinfo(local);
        SSL_CTX_free(ssl_ctx);
        return NULL;
    }

    fprintf(stderr, "H2: listening on %s:%s (TCP)\n", LISTEN_HOST, LISTEN_PORT);

    freeaddrinfo(local);

    // Accept incoming TCP connections.
    while (1) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(peer_addr);

        int client_fd = accept(listen_fd,
                               (struct sockaddr *) &peer_addr,
                               &peer_addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("H2: accept failed");
            break;
        }

        fprintf(stderr, "H2: new TCP connection\n");

        // Handle each connection synchronously in this thread.
        // This is acceptable for an example server.
        handle_http2_connection(ssl_ctx, client_fd);
    }

    close(listen_fd);
    SSL_CTX_free(ssl_ctx);

    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        fprintf(stderr, "\nSee tools/apps/ for more complete "
                "implementations.\n");
        return 0;
    }

    // Load the file to serve over HTTP/3.
    if (!load_file(FILE_PATH)) {
        fprintf(stderr, "failed to load %s\n", FILE_PATH);
        return -1;
    }

    // Ignore SIGPIPE to avoid crashes from broken TCP connections.
    signal(SIGPIPE, SIG_IGN);

    // Initialize OpenSSL.
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Start TCP/TLS HTTP/2 server in a separate thread.
    pthread_t h2_thread;
    if (pthread_create(&h2_thread, NULL, http2_server_thread, NULL) != 0) {
        perror("failed to create HTTP/2 server thread");
        return -1;
    }

    // Setup QUIC/HTTP/3 server.
    const struct addrinfo hints = {
        .ai_family = PF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = IPPROTO_UDP
    };

    quiche_enable_debug_logging(debug_log, NULL);

    struct addrinfo *local;
    if (getaddrinfo(LISTEN_HOST, LISTEN_PORT, &hints, &local) != 0) {
        perror("failed to resolve host");
        return -1;
    }

    int sock = socket(local->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("failed to create socket");
        return -1;
    }

    if (fcntl(sock, F_SETFL, O_NONBLOCK) != 0) {
        perror("failed to make socket non-blocking");
        return -1;
    }

    if (bind(sock, local->ai_addr, local->ai_addrlen) < 0) {
        perror("failed to bind socket");
        return -1;
    }

    fprintf(stderr, "QUIC: listening on %s:%s (UDP)\n",
            LISTEN_HOST, LISTEN_PORT);

    // Create the QUIC configuration.
    config = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    if (config == NULL) {
        fprintf(stderr, "failed to create config\n");
        return -1;
    }

    quiche_config_load_cert_chain_from_pem_file(config, CERT_FILE);
    quiche_config_load_priv_key_from_pem_file(config, KEY_FILE);

    quiche_config_set_application_protos(config,
        (uint8_t *) QUICHE_H3_APPLICATION_PROTOCOL,
        sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1);

    quiche_config_set_max_idle_timeout(config, 5000);
    quiche_config_set_max_recv_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_max_send_udp_payload_size(config, MAX_DATAGRAM_SIZE);
    quiche_config_set_initial_max_data(config, 10000000);
    quiche_config_set_initial_max_stream_data_bidi_local(config, 1000000);
    quiche_config_set_initial_max_stream_data_bidi_remote(config, 1000000);
    quiche_config_set_initial_max_stream_data_uni(config, 1000000);
    quiche_config_set_initial_max_streams_bidi(config, 100);
    quiche_config_set_initial_max_streams_uni(config, 100);
    quiche_config_set_disable_active_migration(config, true);
    quiche_config_enable_early_data(config);

    // Create the HTTP/3 configuration.
    http3_config = quiche_h3_config_new();
    if (http3_config == NULL) {
        fprintf(stderr, "failed to create HTTP/3 config\n");
        return -1;
    }

    struct connections c;
    c.sock = sock;
    c.h = NULL;
    c.local_addr = local->ai_addr;
    c.local_addr_len = local->ai_addrlen;

    conns = &c;

    ev_io watcher;

    struct ev_loop *loop = ev_default_loop(0);

    ev_io_init(&watcher, recv_cb, sock, EV_READ);
    ev_io_start(loop, &watcher);
    watcher.data = &c;

    // Run the event loop.
    ev_loop(loop, 0);

    freeaddrinfo(local);

    quiche_h3_config_free(http3_config);
    quiche_config_free(config);

    free(file_content);

    return 0;
}
