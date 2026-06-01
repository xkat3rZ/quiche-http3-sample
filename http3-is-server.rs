// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
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

//! HTTP/3 Server with Alt-Svc Discovery
//!
//! This example demonstrates a dual-protocol server that:
//! 1. Runs a TCP/TLS HTTP/2 server that advertises HTTP/3 via Alt-Svc header
//! 2. Runs a QUIC/HTTP/3 server on the same port
//!
//! When a client (like Chrome) connects via TCP, it receives the Alt-Svc header
//! indicating HTTP/3 is available. The client can then upgrade to HTTP/3 for
//! subsequent requests.

#[macro_use]
extern crate log;

use std::io::Read;
use std::io::Write;
use std::net;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

use std::collections::HashMap;

use ring::rand::*;

use quiche::h3::NameValue;

/// Maximum UDP payload size for QUIC packets.
const MAX_DATAGRAM_SIZE: usize = 1350;

/// Address to listen on for both TCP and UDP.
const LISTEN_ADDR: &str = "127.0.0.1:4433";

/// HTML response served when the client connects via HTTP/2 (TCP).
const HTTP11_RESPONSE: &str = r#"<!DOCTYPE html>
<html>
<head><title>Not HTTP/3</title></head>
<body>
<h1>HTTP/3 was not used to request this page.</h1>
<p>By visiting this page, your client might have learned that HTTP/3 is available.</p>
<p><a href="/">Try reloading?</a></p>
</body>
</html>"#;

/// HTML response served when the client connects via HTTP/3 (QUIC).
const HTTP3_RESPONSE: &str = r#"<!DOCTYPE html>
<html>
<head><title>HTTP/3!</title></head>
<body>
<h1>HTTP/3! Success!</h1>
<p>This page was served over HTTP/3.</p>
</body>
</html>"#;

/// Tracks partial HTTP/3 responses that couldn't be sent in one go.
///
/// When the send buffer is full, we store the remaining headers/body
/// and continue sending when the stream becomes writable again.
struct PartialResponse {
    /// Response headers (if not yet sent).
    headers: Option<Vec<quiche::h3::Header>>,

    /// Response body bytes.
    body: Vec<u8>,

    /// Number of body bytes already sent.
    written: usize,
}

/// Represents a single QUIC client connection and its associated state.
struct Client {
    /// The underlying QUIC connection.
    conn: quiche::Connection,

    /// The HTTP/3 connection (created after QUIC handshake completes).
    http3_conn: Option<quiche::h3::Connection>,

    /// Pending partial responses keyed by stream ID.
    partial_responses: HashMap<u64, PartialResponse>,
}

/// Map of connection IDs to client state.
type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 0 {
        println!("Usage: {cmd}");
        println!("\nSee tools/apps/ for more complete implementations.");
        return;
    }

    // Start TCP/TLS HTTP/2 server in a separate thread.
    // This server advertises HTTP/3 via Alt-Svc headers.
    let listen_addr = LISTEN_ADDR;
    thread::spawn(move || {
        start_http2_server(listen_addr, Arc::new(Mutex::new(HashMap::new())));
    });

    // Setup the event loop for QUIC/HTTP/3.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // Create the UDP listening socket, and register it with the event loop.
    let mut socket =
        mio::net::UdpSocket::bind(LISTEN_ADDR.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    // Create the configuration for the QUIC connections.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    // Load TLS certificate and private key.
    // These must exist in the examples/ directory (see README for generation).
    config
        .load_cert_chain_from_pem_file("examples/cert-quic-chain.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert-quic.key")
        .unwrap();

    // Configure ALPN to negotiate HTTP/3.
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    // Set transport parameters.
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();

    let h3_config = quiche::h3::Config::new().unwrap();

    // Generate a seed for deriving connection IDs from the client's DCID.
    // This allows us to route packets to the correct connection.
    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();

    let local_addr = socket.local_addr().unwrap();

    // Main event loop.
    loop {
        // Find the shortest timeout from all active connections.
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        poll.poll(&mut events, timeout).unwrap();

        // Read incoming UDP packets and feed them to quiche.
        'read: loop {
            // If no events, the timeout expired - handle it without reading.
            if events.is_empty() {
                debug!("timed out");

                clients.values_mut().for_each(|c| c.conn.on_timeout());

                break 'read;
            }

            let (len, from) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    // No more packets to read.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {e:?}");
                },
            };

            debug!("Received {} bytes from {}", len, from);

            let pkt_buf = &mut buf[..len];

            // Parse the QUIC packet header.
            let hdr = match quiche::Header::from_slice(
                pkt_buf,
                quiche::MAX_CONN_ID_LEN,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {e:?}");
                    continue 'read;
                },
            };

            trace!("got packet {hdr:?}");

            // Derive a connection ID from the packet's DCID using HMAC.
            let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
            let conn_id = conn_id.to_vec().into();

            // Lookup or create a connection based on the packet's connection ID.
            let client = if !clients.contains_key(&hdr.dcid) &&
                !clients.contains_key(&conn_id)
            {
                // New connection - must be an Initial packet.
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue 'read;
                }

                // Check if we support the QUIC version.
                if !quiche::version_is_supported(hdr.version) {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();

                    let out = &out[..len];

                    if let Err(e) = socket.send_to(out, from) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {e:?}");
                    }
                    continue 'read;
                }

                let scid = conn_id.clone();

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                // Skip stateless retry for better browser interop.
                // Production servers should use stateless retry for DDoS
                // protection, but Chrome has interop issues with Retry
                // packets that can cause it to abandon QUIC and fall back
                // to TCP, breaking Alt-Svc discovery.
                let odcid = if token.is_empty() {
                    None
                } else {
                    let odcid = validate_token(&from, token);

                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue 'read;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue 'read;
                    }

                    odcid
                };

                debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                let conn = quiche::accept(
                    &scid,
                    odcid.as_ref(),
                    local_addr,
                    from,
                    &mut config,
                )
                .unwrap();

                let client = Client {
                    conn,
                    http3_conn: None,
                    partial_responses: HashMap::new(),
                };

                clients.insert(scid.clone(), client);

                clients.get_mut(&scid).unwrap()
            } else {
                // Existing connection - look up by DCID or derived conn_id.
                match clients.get_mut(&hdr.dcid) {
                    Some(v) => v,

                    None => clients.get_mut(&conn_id).unwrap(),
                }
            };

            let recv_info = quiche::RecvInfo {
                to: socket.local_addr().unwrap(),
                from,
            };

            // Process potentially coalesced packets.
            let read = match client.conn.recv(pkt_buf, recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed for {}: {:?}", client.conn.trace_id(), e);
                    continue 'read;
                },
            };

            debug!("Processed {} bytes for {}", read, client.conn.trace_id());

            // Create HTTP/3 connection once QUIC handshake completes.
            if (client.conn.is_in_early_data() || client.conn.is_established()) &&
                client.http3_conn.is_none()
            {
                debug!(
                    "Handshake completed for {}, creating HTTP/3 connection",
                    client.conn.trace_id()
                );

                let h3_conn = match quiche::h3::Connection::with_transport(
                    &mut client.conn,
                    &h3_config,
                ) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("failed to create HTTP/3 connection: {e}");
                        continue 'read;
                    },
                };

                client.http3_conn = Some(h3_conn);
            }

            // Handle writable streams (for partial responses).
            if client.http3_conn.is_some() {
                for stream_id in client.conn.writable() {
                    handle_writable(client, stream_id);
                }
            }

            // Process HTTP/3 events.
            if let Some(http3_conn) = client.http3_conn.as_mut() {
                loop {
                    match http3_conn.poll(&mut client.conn) {
                        Ok((
                            stream_id,
                            quiche::h3::Event::Headers { list, .. },
                        )) => {
                            handle_request(
                                &mut client.conn,
                                http3_conn,
                                stream_id,
                                &list,
                                &mut client.partial_responses,
                            );
                        },

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            info!(
                                "{} got data on stream id {}",
                                client.conn.trace_id(),
                                stream_id
                            );
                        },

                        Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                        Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),

                        Ok((
                            _prioritized_element_id,
                            quiche::h3::Event::PriorityUpdate,
                        )) => (),

                        Ok((_goaway_id, quiche::h3::Event::GoAway)) => (),

                        Err(quiche::h3::Error::Done) => {
                            break;
                        },

                        Err(e) => {
                            error!(
                                "{} HTTP/3 error {:?}",
                                client.conn.trace_id(),
                                e
                            );

                            break;
                        },
                    }
                }
            }
        }

        // Send outgoing QUIC packets for all active connections.
        for client in clients.values_mut() {
            loop {
                let (write, send_info) = match client.conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", client.conn.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!(
                            "send failed for {}: {:?}",
                            client.conn.trace_id(),
                            e
                        );

                        client.conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send() would block");
                        break;
                    }

                    panic!("send() failed: {e:?}");
                }

                debug!("{} written {} bytes", client.conn.trace_id(), write);
            }
        }

        // Remove closed connections.
        clients.retain(|_, ref mut c| {
            if c.conn.is_closed() {
                let peer_error = c.conn.peer_error();
                let local_error = c.conn.local_error();
                info!(
                    "Connection {} closed - peer_error={:?}, local_error={:?}",
                    c.conn.trace_id(),
                    peer_error,
                    local_error,
                );
            }

            !c.conn.is_closed()
        });
    }
}

/// Starts the TCP/TLS HTTP/2 server.
///
/// This server listens on the same port as the QUIC server and serves
/// HTTP/2 responses with an Alt-Svc header advertising HTTP/3.
fn start_http2_server(
    addr: &str, _connection_tracker: Arc<Mutex<HashMap<net::IpAddr, usize>>>,
) {
    use boring::ssl::SslAcceptor;
    use boring::ssl::SslFiletype;
    use boring::ssl::SslMethod;

    let listener = net::TcpListener::bind(addr).unwrap();

    let mut acceptor =
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
    acceptor
        .set_certificate_chain_file("examples/cert-quic-chain.crt")
        .unwrap();
    acceptor
        .set_private_key_file("examples/cert-quic.key", SslFiletype::PEM)
        .unwrap();
    acceptor.check_private_key().unwrap();

    // Disable session tickets to prevent Chrome from attempting TLS 1.3
    // session resumption, which fails with certificate_unknown (alert 46)
    // when the acceptor has no ticket key configured.
    acceptor.set_options(boring::ssl::SslOptions::NO_TICKET);

    // Set ALPN to select h2 (HTTP/2).
    acceptor.set_alpn_select_callback(|_, client| {
        // Parse ALPN wire format: length-prefixed strings.
        let mut i = 0;
        while i < client.len() {
            let len = client[i] as usize;
            if i + 1 + len <= client.len() {
                let proto = &client[i + 1..i + 1 + len];
                if proto == b"h2" {
                    return Ok(b"h2");
                }
            }
            i += 1 + len;
        }
        Err(boring::ssl::AlpnError::NOACK)
    });

    let acceptor = Arc::new(acceptor.build());

    // Accept incoming TCP connections.
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone();
                thread::spawn(move || {
                    handle_http2_connection(acceptor, stream);
                });
            },
            Err(e) => {
                error!("TCP accept failed: {:?}", e);
            },
        }
    }
}

/// Handles a single HTTP/2 connection over TLS.
///
/// Performs a minimal HTTP/2 handshake and serves a single response
/// with the Alt-Svc header to advertise HTTP/3 availability.
fn handle_http2_connection(
    acceptor: Arc<boring::ssl::SslAcceptor>, stream: net::TcpStream,
) {
    debug!("New TCP connection from {:?}", stream.peer_addr());

    // Perform TLS handshake.
    let mut ssl_stream = match acceptor.accept(stream) {
        Ok(s) => s,
        Err(e) => {
            error!("TLS handshake failed: {:?}", e);
            return;
        },
    };

    // Read the HTTP/2 connection preface (24 bytes magic).
    let mut preface = [0u8; 24];
    if ssl_stream.read_exact(&mut preface).is_err() {
        error!("Failed to read connection preface");
        return;
    }
    if &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        error!("Invalid connection preface");
        return;
    }

    // Read the client's SETTINGS frame.
    let mut frame_header = [0u8; 9];
    if ssl_stream.read_exact(&mut frame_header).is_err() {
        error!("Failed to read SETTINGS frame header");
        return;
    }
    let payload_len = ((frame_header[0] as usize) << 16) |
        ((frame_header[1] as usize) << 8) |
        (frame_header[2] as usize);
    let frame_type = frame_header[3];

    // Expect SETTINGS frame (type 0x4).
    if frame_type != 0x04 {
        error!("Expected SETTINGS frame, got type {}", frame_type);
        return;
    }

    // Consume the SETTINGS payload.
    let mut settings_payload = vec![0u8; payload_len];
    if ssl_stream.read_exact(&mut settings_payload).is_err() {
        error!("Failed to read SETTINGS payload");
        return;
    }

    // Send our SETTINGS frame.
    let mut settings_payload_out = Vec::new();
    // SETTINGS_HEADER_TABLE_SIZE (0x1) = 4096
    settings_payload_out.extend_from_slice(&0x1u16.to_be_bytes());
    settings_payload_out.extend_from_slice(&4096u32.to_be_bytes());
    // SETTINGS_ENABLE_PUSH (0x2) = 0
    settings_payload_out.extend_from_slice(&0x2u16.to_be_bytes());
    settings_payload_out.extend_from_slice(&0u32.to_be_bytes());
    // SETTINGS_MAX_CONCURRENT_STREAMS (0x3) = 100
    settings_payload_out.extend_from_slice(&0x3u16.to_be_bytes());
    settings_payload_out.extend_from_slice(&100u32.to_be_bytes());
    // SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 65535
    settings_payload_out.extend_from_slice(&0x4u16.to_be_bytes());
    settings_payload_out.extend_from_slice(&65535u32.to_be_bytes());

    let settings_frame = make_h2_frame(0x04, 0x00, 0, &settings_payload_out);
    if ssl_stream.write_all(&settings_frame).is_err() {
        return;
    }

    // ACK the client's SETTINGS.
    let settings_ack = make_h2_frame(0x04, 0x01, 0, &[]);
    if ssl_stream.write_all(&settings_ack).is_err() {
        return;
    }

    // Flush to ensure the client sees our SETTINGS.
    if ssl_stream.flush().is_err() {
        return;
    }

    // Read frames until we see a HEADERS frame.
    let headers_seen;
    let request_stream_id;
    loop {
        if ssl_stream.read_exact(&mut frame_header).is_err() {
            return;
        }
        let payload_len = ((frame_header[0] as usize) << 16) |
            ((frame_header[1] as usize) << 8) |
            (frame_header[2] as usize);
        let frame_type = frame_header[3];
        let flags = frame_header[4];
        let stream_id = u32::from_be_bytes([
            frame_header[5] & 0x7f,
            frame_header[6],
            frame_header[7],
            frame_header[8],
        ]);

        let mut payload = vec![0u8; payload_len];
        if ssl_stream.read_exact(&mut payload).is_err() {
            return;
        }

        if frame_type == 0x01 {
            // HEADERS frame with END_HEADERS flag.
            if flags & 0x04 != 0 {
                headers_seen = true;
                request_stream_id = stream_id;
                break;
            }
        } else if frame_type == 0x04 && flags & 0x01 != 0 {
            // SETTINGS ACK - ignore.
            continue;
        }
        // Ignore other frames (WINDOW_UPDATE, etc).
    }

    if !headers_seen {
        return;
    }

    // Build the response body.
    let body = HTTP11_RESPONSE.as_bytes();
    let body_len = body.len();
    let body_len_str = body_len.to_string();

    // Encode response headers with HPACK.
    let mut hpack = Vec::new();

    // :status: 200 (indexed, static table index 8).
    hpack.push(0x88);

    // content-type: text/html (literal with indexed name).
    hpack.push(0x5f);
    hpack.push(0x09);
    hpack.extend_from_slice(b"text/html");

    // alt-svc header advertising HTTP/3.
    hpack.push(0x40); // literal with incremental indexing, new name
    hpack.push(0x07);
    hpack.extend_from_slice(b"alt-svc");
    let alt_svc_value = b"h3=\":4433\"; ma=86400; persist=1";
    hpack.push(alt_svc_value.len() as u8);
    hpack.extend_from_slice(alt_svc_value);

    // server: quiche
    hpack.push(0x40 | 54);
    hpack.push(0x06);
    hpack.extend_from_slice(b"quiche");

    // content-length
    hpack.push(0x40 | 28);
    hpack.push(body_len_str.len() as u8);
    hpack.extend_from_slice(body_len_str.as_bytes());

    // Send HEADERS frame with END_HEADERS flag.
    let headers_frame = make_h2_frame(0x01, 0x04, request_stream_id, &hpack);
    if ssl_stream.write_all(&headers_frame).is_err() {
        error!("Failed to send HEADERS frame");
        return;
    }

    // Send DATA frame with END_STREAM flag.
    let data_frame = make_h2_frame(0x00, 0x01, request_stream_id, body);
    if ssl_stream.write_all(&data_frame).is_err() {
        error!("Failed to send DATA frame");
        return;
    }

    let _ = ssl_stream.flush();

    // Shutdown TLS to force the browser to make a new connection,
    // which will trigger Alt-Svc evaluation.
    let _ = ssl_stream.shutdown();
    debug!("HTTP/2 connection closed");
}

/// Constructs an HTTP/2 frame with the given type, flags, stream ID, and
/// payload.
fn make_h2_frame(
    frame_type: u8, flags: u8, stream_id: u32, payload: &[u8],
) -> Vec<u8> {
    let len = payload.len();
    let mut frame = Vec::with_capacity(9 + len);
    frame.push(((len >> 16) & 0xff) as u8);
    frame.push(((len >> 8) & 0xff) as u8);
    frame.push((len & 0xff) as u8);
    frame.push(frame_type);
    frame.push(flags);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Validates a stateless retry token.
///
/// Returns the original connection ID if the token is valid for the
/// given source address, or None if validation fails.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}

/// Handles incoming HTTP/3 requests.
///
/// Sends an HTTP/3 response with the Alt-Svc header. If the response
/// cannot be sent completely, stores the remainder for later transmission.
fn handle_request(
    conn: &mut quiche::Connection, http3_conn: &mut quiche::h3::Connection,
    stream_id: u64, headers: &[quiche::h3::Header],
    partial_responses: &mut HashMap<u64, PartialResponse>,
) {
    info!(
        "{} got request {:?} on stream id {}",
        conn.trace_id(),
        hdrs_to_strings(headers),
        stream_id
    );

    // Stop reading the request stream since we only need headers.
    conn.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
        .unwrap();

    let body = HTTP3_RESPONSE.as_bytes().to_vec();

    let response_headers = vec![
        quiche::h3::Header::new(b":status", b"200"),
        quiche::h3::Header::new(b"server", b"quiche"),
        quiche::h3::Header::new(b"content-type", b"text/html"),
        quiche::h3::Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ),
        quiche::h3::Header::new(b"alt-svc", b"h3=\":4433\"; ma=86400; persist=1"),
    ];

    // Try to send the response headers.
    match http3_conn.send_response(conn, stream_id, &response_headers, false) {
        Ok(v) => v,

        Err(quiche::h3::Error::StreamBlocked) => {
            // Stream blocked - save for later.
            let response = PartialResponse {
                headers: Some(response_headers),
                body,
                written: 0,
            };

            partial_responses.insert(stream_id, response);
            return;
        },

        Err(e) => {
            error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        },
    }

    // Try to send the response body.
    let written = match http3_conn.send_body(conn, stream_id, &body, true) {
        Ok(v) => v,

        Err(quiche::h3::Error::Done) => 0,

        Err(e) => {
            error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        },
    };

    // If we couldn't send the entire body, save the remainder.
    if written < body.len() {
        let response = PartialResponse {
            headers: None,
            body,
            written,
        };

        partial_responses.insert(stream_id, response);
    }
}

/// Handles newly writable streams.
///
/// Called when a stream that was previously blocked becomes writable.
/// Continues sending any pending partial response.
fn handle_writable(client: &mut Client, stream_id: u64) {
    let conn = &mut client.conn;
    let http3_conn = &mut client.http3_conn.as_mut().unwrap();

    debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();

    // Send headers if they haven't been sent yet.
    if let Some(ref headers) = resp.headers {
        match http3_conn.send_response(conn, stream_id, headers, false) {
            Ok(_) => (),

            Err(quiche::h3::Error::StreamBlocked) => {
                return;
            },

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        }
    }

    resp.headers = None;

    // Send remaining body.
    let body = &resp.body[resp.written..];

    let written = match http3_conn.send_body(conn, stream_id, body, true) {
        Ok(v) => v,

        Err(quiche::h3::Error::Done) => 0,

        Err(e) => {
            client.partial_responses.remove(&stream_id);

            error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        },
    };

    resp.written += written;

    // Remove the partial response if completely sent.
    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}

/// Converts HTTP/3 headers to a vector of string tuples for logging.
pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}
