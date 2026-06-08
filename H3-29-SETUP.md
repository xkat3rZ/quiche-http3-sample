# http3-is-server with h3-29 — Setup & Replication Guide

This documents everything needed to build and run `http3-is-server.c` with
**HTTP/3 over QUIC draft-29 (`h3-29`, wire version `0xff00001d`)** on a fresh
machine.

> **Caveat:** h3-29 is obsolete. Current Chrome/Firefox negotiate `h3` (QUIC v1,
> RFC 9000). This setup only makes sense for testing against a draft-29-capable
> peer. h3-29 support was **removed from quiche in 0.18.0** — the last release
> that still has it is **0.17.2**, which is what this guide pins.

---

## Table of Contents

1. [Prerequisites](#0-prerequisites-system-packages)
2. [Get quiche 0.17.2](#1-get-quiche-at-version-0172)
3. [Fix yanked boring dependency](#2-fix-the-yanked-boring-dependency)
4. [Source changes to http3-is-server.c](#3-source-changes-to-quicheexampleshttp3-is-serverc)
5. [Makefile changes](#4-makefile-changes-quicheexamplesmakefile)
6. [Build](#5-build)
7. [Certificate generation](#6-certificate-generation)
8. [Runtime setup](#7-runtime-setup)
9. [Running with Chrome](#8-running-with-chrome)
10. [Summary](#9-summary-of-why-each-change-is-needed)

---

## 0. Prerequisites (system packages)

```bash
sudo apt install build-essential cmake git libev-dev uthash-dev openssl libnss3-tools
# Rust toolchain (needed to build libquiche):
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

## 1. Get quiche at version 0.17.2

```bash
git clone --recursive https://github.com/cloudflare/quiche.git
cd quiche
git checkout 0.17.2
git submodule update --init quiche/deps/boringssl   # vendored BoringSSL, required to build
```

## 2. Fix the yanked `boring` dependency

0.17.2's `quiche/Cargo.toml` pins `boring = "2.0.0"`, and **both 2.x releases
are yanked** on crates.io, so a fresh resolve fails. `boring` is optional and
not enabled by the default `boringssl-vendored` feature, so it is only resolved,
never compiled — bumping it just satisfies the lockfile.

In **`quiche/Cargo.toml`** (line 64):

```diff
-boring = { version = "2.0.0", optional = true }
+boring = { version = "4", optional = true }
```

Then remove any stale lockfile so it regenerates (note: `Cargo.lock` is
gitignored in quiche, so `git checkout` does NOT reset it):

```bash
rm -f Cargo.lock
```

## 3. Source changes to `quiche/examples/http3-is-server.c`

### a) Enable h3-29 (ALPN + wire version)

Add these defines after the existing `#include` statements (around line 77):

```c
#define QUICHE_H3_APPLICATION_PROTOCOL_CUSTOM "\x05h3-29"
// #define QUICHE_H3_APPLICATION_PROTOCOL_CUSTOM "\x02h3"

// #define QUICHE_PROTOCOL_VERSION_CUSTOM 0x00000001
// #define QUICHE_PROTOCOL_VERSION_CUSTOM 0x00000002
#define QUICHE_PROTOCOL_VERSION_CUSTOM 0xff00001d
```

Then use them in `main()` (around line 1449):

```c
// Create the QUIC configuration.
config = quiche_config_new(QUICHE_PROTOCOL_VERSION_CUSTOM);
if (config == NULL) {
    fprintf(stderr, "failed to create config\n");
    return -1;
}

quiche_config_load_cert_chain_from_pem_file(config, CERT_FILE);
quiche_config_load_priv_key_from_pem_file(config, KEY_FILE);

quiche_config_set_application_protos(config,
    (uint8_t *) QUICHE_H3_APPLICATION_PROTOCOL_CUSTOM,
    sizeof(QUICHE_H3_APPLICATION_PROTOCOL_CUSTOM) - 1);
```

### b) Const casts on `quiche_h3_send_body`

0.17.2's `quiche_h3_send_body` takes a non-const `uint8_t *body`, but the file
passes `const`. Cast at both call sites:

**In `handle_request()` (around line 504):**

```c
// Send response body.
ssize_t written = quiche_h3_send_body(conn_io->http3, conn_io->conn,
                                      stream_id, (uint8_t *) body,
                                      body_len, true);
```

**In `handle_writable()` (around line 612):**

```c
// Send remaining body.
const uint8_t *remaining = resp->body + resp->written;
size_t remaining_len = resp->body_len - resp->written;

ssize_t written = quiche_h3_send_body(conn_io->http3, conn_io->conn,
                                      stream_id, (uint8_t *) remaining,
                                      remaining_len, true);
```

### c) Handle the extra event enum

0.17.2 has `QUICHE_H3_EVENT_DATAGRAM`, and `-Werror=switch` rejects the
unhandled value. Add to the `switch` in `recv_cb` (around line 832):

```c
case QUICHE_H3_EVENT_DATAGRAM:
    break;
```

### d) Crash fix — null H3 handle

Connections that close before the H3 handshake completes have `http3 == NULL`
(e.g. Chrome's coalesced/duplicate Initial packets, or idle-timed-out
connections). `quiche_h3_conn_free(NULL)` does `Box::from_raw(NULL)`, which
aborts the process with:

```
NonNull::new_unchecked requires that the pointer is non-null
```

Guard **both** free sites (the GC loop in `recv_cb` and `timeout_cb`):

**In `recv_cb` (around line 867):**

```c
free_partial_responses(conn_io);
if (conn_io->http3 != NULL) {
    quiche_h3_conn_free(conn_io->http3);
}
quiche_conn_free(conn_io->conn);
free(conn_io);
```

**In `timeout_cb` (around line 902):**

```c
free_partial_responses(conn_io);
if (conn_io->http3 != NULL) {
    quiche_h3_conn_free(conn_io->http3);
}
quiche_conn_free(conn_io->conn);
free(conn_io);
```

### e) Change LISTEN_HOST to quic.local

Change the listen host to use a hostname instead of IP (around line 71):

```c
#define LISTEN_HOST "quic.local"
#define LISTEN_PORT "4433"
```

## 4. Makefile changes (`quiche/examples/Makefile`)

### a) Fix the `-L` path bug

`find` matches `libssl.a`/`libcrypto.a` in two build dirs, which breaks the
linker (the second path is passed without `-L`):

```diff
-LIBCRYPTO_DIR = $(dir $(shell find ${BUILD_DIR} -name libcrypto.a))
-LIBSSL_DIR = $(dir $(shell find ${BUILD_DIR} -name libssl.a))
+LIBCRYPTO_DIR = $(dir $(shell find ${BUILD_DIR} -name libcrypto.a | head -1))
+LIBSSL_DIR = $(dir $(shell find ${BUILD_DIR} -name libssl.a | head -1))
```

### b) Add `http3-is-server` to `all` and `clean`

```diff
-all: client server http3-client http3-server
+all: client server http3-client http3-server http3-is-server
...
-	@$(RM) -rf client server http3-client http3-server build/ *.dSYM/
+	@$(RM) -rf client server http3-client http3-server http3-is-server build/ *.dSYM/
```

### c) Add the build target with BoringSSL headers/libs

`http3-is-server` is the only example that uses `<openssl/ssl.h>` directly (for
its TCP/TLS HTTP/2 side), so it needs the vendored BoringSSL headers and libs.
Insert before the `$(LIB_DIR)/libquiche.a:` rule:

```makefile
# http3-is-server also uses the (Boring)SSL API directly for its TCP/TLS
# HTTP/2 side, so it needs the vendored BoringSSL headers and libs.
BORINGSSL_INC = ../deps/boringssl/src/include
BORINGSSL_LIB = $(dir $(shell find $(BUILD_DIR) -path '*/out/build/libssl.a' | head -1))

http3-is-server: http3-is-server.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) -L$(BORINGSSL_LIB) $< -o $@ \
		$(INCS) -I$(BORINGSSL_INC) $(LIBS) -lssl -lcrypto
```

### Complete Makefile

Here is the complete updated `Makefile` for reference:

```makefile
OS := $(shell uname)

SOURCE_DIR = ../src
BUILD_DIR = $(CURDIR)/build
LIB_DIR = $(BUILD_DIR)/debug
INCLUDE_DIR = ../include

INCS = -I$(INCLUDE_DIR)
CFLAGS = -I. -Wall -Werror -pedantic -fsanitize=address -g

LIBCRYPTO_DIR = $(dir $(shell find ${BUILD_DIR} -name libcrypto.a | head -1))
LIBSSL_DIR = $(dir $(shell find ${BUILD_DIR} -name libssl.a | head -1))

LDFLAGS = -L$(LIBCRYPTO_DIR) -L$(LIBSSL_DIR) -L$(LIB_DIR)

ifeq ($(OS), Darwin)
# Default prefix of Apple Silicon macOS homebrew.
# Intel will use /usr/local which is included by default.
BREW_INC_DIR = /opt/homebrew/include/
BREW_LIB_DIR = /opt/homebrew/lib/

CFLAGS += -framework Security -I$(BREW_INC_DIR)
LDFLAGS += -L$(BREW_LIB_DIR)
endif

LIBS = $(LIB_DIR)/libquiche.a -lev -ldl -pthread -lm

all: client server http3-client http3-server http3-is-server

client: client.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

server: server.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

http3-client: http3-client.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

http3-server: http3-server.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ $(INCS) $(LIBS)

# http3-is-server also uses the (Boring)SSL API directly for its TCP/TLS
# HTTP/2 side, so it needs the vendored BoringSSL headers and libs.
BORINGSSL_INC = ../deps/boringssl/src/include
BORINGSSL_LIB = $(dir $(shell find $(BUILD_DIR) -path '*/out/build/libssl.a' | head -1))

http3-is-server: http3-is-server.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) -L$(BORINGSSL_LIB) $< -o $@ \
		$(INCS) -I$(BORINGSSL_INC) $(LIBS) -lssl -lcrypto

$(LIB_DIR)/libquiche.a: $(shell find $(SOURCE_DIR) -type f -name '*.rs')
	cd .. && cargo build --target-dir $(BUILD_DIR) --features ffi

clean:
	@$(RM) -rf client server http3-client http3-server http3-is-server build/ *.dSYM/
```

## 5. Build

```bash
cd quiche/examples
make http3-is-server
```

The first run compiles libquiche + vendored BoringSSL (~1 minute).

## 6. Certificate generation

Chrome requires a locally-trusted certificate with proper extensions. The
certificate must include:

- **Subject Alternative Names (SANs):** `DNS:quic.local`, `DNS:localhost`,
  `IP:127.0.0.1`, `IP:::1`
- **Key Usage:** `Digital Signature`, `Key Encipherment` (critical)
- **Extended Key Usage:** `TLS Web Server Authentication`
- **Basic Constraints:** `CA:FALSE` (critical)

The root CA must have:
- **Key Usage:** `Certificate Sign`, `CRL Sign` (critical)
- **Basic Constraints:** `CA:TRUE` (critical)

### Option A: Using OpenSSL (recommended)

Create a script `gen-quic-certs.sh`:

```bash
#!/bin/bash
set -ex
cd $(dirname $0)

# Create root CA config
cat > rootca.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
[req_distinguished_name]
[v3_ca]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF

# Create leaf CSR config
cat > leaf_csr.cnf << 'EOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
subjectKeyIdentifier = hash
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = quic.local
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Create leaf signing config
cat > leaf_sign.cnf << 'EOF'
[v3_req]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = quic.local
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate root CA
openssl genrsa -out rootca.key 2048
openssl req -new -x509 -days 3650 -key rootca.key -out rootca.crt \
    -subj "/C=US/O=Test/CN=Test Root CA" -config rootca.cnf

# Generate leaf key and CSR
openssl genrsa -out cert-quic.key 2048
openssl req -new -key cert-quic.key -out cert-quic.csr \
    -subj "/C=US/O=Test/CN=quic.local" -config leaf_csr.cnf

# Sign leaf cert with root CA
openssl x509 -req -in cert-quic.csr -CA rootca.crt -CAkey rootca.key \
    -CAcreateserial -out cert-quic.crt -days 3650 \
    -extensions v3_req -extfile leaf_sign.cnf

# Build chain file (leaf + root)
cat cert-quic.crt rootca.crt > cert-quic-chain.crt

# Clean up temp files
rm -f cert-quic.csr rootca.key rootca.crt rootca.srl rootca.cnf leaf_csr.cnf leaf_sign.cnf

echo "Generated:"
echo "  cert-quic.crt        - leaf certificate"
echo "  cert-quic-chain.crt  - chain (leaf + root)"
echo "  cert-quic.key        - private key"
echo "  rootca.crt           - root CA (extract from chain if needed)"
```

Make it executable and run:

```bash
chmod +x gen-quic-certs.sh
./gen-quic-certs.sh
```

### Option B: Using mkcert

```bash
# Install mkcert (Ubuntu/Debian)
sudo apt install mkcert

# Create local CA
mkcert -install

# Generate certificates
mkcert -cert-file cert-quic-chain.crt -key-file cert-quic.key \
    quic.local localhost 127.0.0.1 ::1

# Append root CA to chain
cat ~/.local/share/mkcert/rootCA.pem >> cert-quic-chain.crt
```

### Install CA to trust stores

**System trust store (for curl, etc.):**

```bash
sudo cp rootca.crt /usr/local/share/ca-certificates/quiche-test-root.crt
sudo update-ca-certificates
```

**Chrome/Chromium NSS database:**

```bash
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "quiche Test CA" -i rootca.crt
```

**Firefox:**

Option A: Use system trust store by setting `security.enterprise_roots.enabled = true` in `about:config`.

Option B: Preferences → Privacy & Security → Certificates → View Certificates → Import → select `rootca.crt` → check "Trust this CA to identify websites".

### Verify certificates

```bash
# Check leaf cert SANs
openssl x509 -in cert-quic.crt -noout -text | grep -A5 "Subject Alternative Name"
# Expected: DNS:quic.local, DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1

# Check leaf cert Key Usage
openssl x509 -in cert-quic.crt -noout -text | grep -A2 "Key Usage"
# Expected: Digital Signature, Key Encipherment

# Check root CA Key Usage
awk '/-----BEGIN CERTIFICATE-----/{n++} n==2,/-----END CERTIFICATE-----/' cert-quic-chain.crt | \
    openssl x509 -noout -text | grep -A2 "Key Usage"
# Expected: Certificate Sign, CRL Sign

# Verify chain
openssl verify -CAfile rootca.crt cert-quic.crt
# Expected: cert-quic.crt: OK
```

## 7. Runtime setup

### Add hostname to /etc/hosts

```bash
echo "127.0.0.1 quic.local" | sudo tee -a /etc/hosts
```

### Create hello.txt

```bash
echo "Hello from HTTP/3!" > hello.txt
```

### Run the server

```bash
cd quiche/examples
./http3-is-server
```

The server listens on:
- **TCP:** `quic.local:4433` (HTTP/2 with Alt-Svc header)
- **UDP:** `quic.local:4433` (QUIC/HTTP/3)

## 8. Running with Chrome

### Option A: Force QUIC for this origin

```bash
google-chrome --enable-quic \
  --origin-to-force-quic-on=quic.local:4433 \
  --quic-version=h3-29 \
  https://quic.local:4433/
```

### Option B: Let Alt-Svc trigger upgrade

1. Visit `https://quic.local:4433/` in Chrome
2. First request is over TCP, receives Alt-Svc header
3. Reload the page — Chrome should upgrade to HTTP/3

### Verify HTTP/3 is being used

- Check `chrome://net-internals/#http3` for active QUIC connections
- In DevTools Network tab, look for `h3-29` in the Protocol column
- Server logs should show "new connection" and QUIC packet processing

### Troubleshooting

**"version negotiation" loop:**

If you see repeated version negotiation messages, Chrome is trying h3 (QUIC v1)
but the server only supports h3-29. Use `--quic-version=h3-29` flag.

**Certificate errors:**

- Verify root CA is in Chrome's NSS database: `certutil -d sql:$HOME/.pki/nssdb -L | grep quiche`
- Re-import root CA and restart Chrome completely: `pkill -f chrome`

**Alt-Svc not working:**

- Clear Alt-Svc cache: `chrome://net-internals/#alt-svc` → "Clear cached mappings"
- Ensure hostname is `quic.local` (not IP address) — Chrome doesn't use Alt-Svc for IPs

---

## 9. Summary of why each change is needed

| Change | Reason |
|--------|--------|
| Pin quiche 0.17.2 | Last release with h3-29 (`0xff00001d`) support |
| `boring` 2.0.0 → 4 | 2.x are yanked on crates.io; optional dep, never compiled |
| `rm Cargo.lock` | Lockfile is gitignored; checkout leaves a mismatched one |
| Submodule init | Vendored BoringSSL needed to build libquiche |
| ALPN + version defines | Actually selects h3-29 / draft-29 wire version |
| `quiche_h3_send_body` casts | 0.17.2 API takes non-const body (`-Werror`) |
| `QUICHE_H3_EVENT_DATAGRAM` case | New enum value in 0.17.2 (`-Werror=switch`) |
| Null `http3` guards | Prevents abort on connections that close pre-handshake |
| Makefile `head -1` | `find` matched two lib dirs, breaking the linker |
| Makefile target + SSL flags | Example wasn't in the build; needs BoringSSL headers/libs |
| `LISTEN_HOST` = `quic.local` | Chrome doesn't use Alt-Svc for IP addresses |
| Cert with proper extensions | Chrome requires Key Usage, Extended Key Usage, SANs |
| Root CA in trust stores | Chrome/Firefox must trust the certificate |
| `--quic-version=h3-29` | Forces Chrome to use draft-29 instead of QUIC v1 |
