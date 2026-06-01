# HTTP/3 Server with Alt-Svc Discovery

This example demonstrates a dual-protocol server that enables HTTP/3 discovery via Alt-Svc headers.

## Overview

The server runs two protocols simultaneously on the same port (4433):

1. **TCP/TLS HTTP/2 Server** - Serves an HTML page with an `Alt-Svc` header advertising HTTP/3 availability
2. **QUIC/HTTP/3 Server** - Serves content over HTTP/3 when clients upgrade

When a browser (like Chrome) connects via TCP, it receives the Alt-Svc header indicating HTTP/3 is available. The browser can then upgrade to HTTP/3 for subsequent requests.

## Prerequisites

- Rust toolchain (rustup/cargo)
- OpenSSL (for certificate generation)
- cmake (required by boring-sys to build BoringSSL)

## Certificate Setup

The server requires TLS certificates. You can use the provided certificates or generate your own.

### Option 1: Use Existing Certificates

The `examples/` directory contains pre-generated certificates:
- `cert-quic-chain.crt` - Certificate chain
- `cert-quic.key` - Private key

### Option 2: Generate New Certificates

Run the certificate generation script:

```bash
cd quiche/examples
./gen-certs.sh
```

This creates:
- `rootca.crt` / `rootca.key` - Root CA certificate
- `cert.crt` / `cert.key` - Server certificate

Then create the chain file:

```bash
cat cert.crt > cert-quic-chain.crt
cp cert.key cert-quic.key
```

### Option 3: Use mkcert (Recommended for Local Development)

[mkcert](https://github.com/FiloSottile/mkcert) creates locally-trusted certificates:

```bash
# Install mkcert (Ubuntu/Debian)
sudo apt install mkcert

# Create local CA
mkcert -install

# Generate certificates for localhost
mkcert -cert-file cert-quic-chain.crt -key-file cert-quic.key localhost 127.0.0.1 ::1
```

## Building

From the `quiche/` directory:

```bash
cargo build --example http3-is-server
```

For release mode:

```bash
cargo build --release --example http3-is-server
```

## Running

```bash
cargo run --example http3-is-server
```

Or run the compiled binary directly:

```bash
./target/debug/examples/http3-is-server
```

The server will listen on `127.0.0.1:4433` for both TCP and UDP traffic.

## Testing

### With curl (HTTP/3 support required)

```bash
# HTTP/2 connection (will receive Alt-Svc header)
curl -k https://127.0.0.1:4433/

# HTTP/3 connection (if curl supports it)
curl --http3 -k https://127.0.0.1:4433/
```

### With Chrome

1. Navigate to `https://127.0.0.1:4433/`
2. The first request uses HTTP/2 and receives the Alt-Svc header
3. Chrome may automatically upgrade to HTTP/3 for subsequent requests

Note: You may need to add the certificate to your browser's trust store or use mkcert for locally-trusted certificates.

### With quiche-client

```bash
cargo run --bin quiche-client -- --no-verify https://127.0.0.1:4433/
```

## How It Works

1. **TCP Connection**: When a client connects via TCP, the HTTP/2 server responds with:
   ```
   HTTP/2 200 OK
   alt-svc: h3=":4433"; ma=86400; persist=1
   content-type: text/html
   ```

2. **Alt-Svc Discovery**: The client learns that HTTP/3 is available on port 4433.

3. **QUIC Connection**: The client can then establish a QUIC connection to the same port over UDP, negotiating HTTP/3 via ALPN.

4. **HTTP/3 Response**: Subsequent requests are served over HTTP/3 with lower latency.

## Troubleshooting

### Certificate Errors

If you see TLS certificate errors in your browser:
- Use mkcert to generate locally-trusted certificates
- Or add `rootca.crt` to your browser's certificate authority list

### "recv() would block" Messages

These are normal debug messages indicating no more UDP packets are available to read.

### Chrome Falls Back to TCP

Chrome may abandon QUIC and fall back to TCP if:
- The certificate is not trusted
- There are connection issues during the QUIC handshake
- Stateless retry is enabled (this example disables it for better browser interop)

## See Also

- [quiche HTTP/3 documentation](https://docs.quic.tech/quiche/h3/)
- [RFC 9114 - HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 7838 - HTTP Alternative Services](https://www.rfc-editor.org/rfc/rfc7838)
