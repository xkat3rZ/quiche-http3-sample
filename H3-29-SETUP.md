# http3-is-server with h3-29 — Setup & Replication Guide

This documents everything needed to build and run `http3-is-server.c` with
**HTTP/3 over QUIC draft-29 (`h3-29`, wire version `0xff00001d`)** on a fresh
machine.

> **Caveat:** h3-29 is obsolete. Current Chrome/Firefox negotiate `h3` (QUIC v1,
> RFC 9000). This setup only makes sense for testing against a draft-29-capable
> peer. h3-29 support was **removed from quiche in 0.18.0** — the last release
> that still has it is **0.17.2**, which is what this guide pins.

---

## 0. Prerequisites (system packages)

```bash
sudo apt install build-essential cmake git libev-dev uthash-dev
# Rust toolchain (needed to build libquiche):
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
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

In **`quiche/Cargo.toml`**:

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

```c
#define QUICHE_H3_APPLICATION_PROTOCOL_CUSTOM "\x05h3-29"
#define QUICHE_PROTOCOL_VERSION_CUSTOM 0xff00001d
```

### b) Const casts on `quiche_h3_send_body`

0.17.2's `quiche_h3_send_body` takes a non-const `uint8_t *body`, but the file
passes `const`. Cast at both call sites:

```c
// in handle_request():
quiche_h3_send_body(conn_io->http3, conn_io->conn, stream_id,
                    (uint8_t *) body, body_len, true);

// in handle_writable():
quiche_h3_send_body(conn_io->http3, conn_io->conn, stream_id,
                    (uint8_t *) remaining, remaining_len, true);
```

### c) Handle the extra event enum

0.17.2 has `QUICHE_H3_EVENT_DATAGRAM`, and `-Werror=switch` rejects the
unhandled value. Add to the `switch` in `recv_cb`:

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

```c
if (conn_io->http3 != NULL) {
    quiche_h3_conn_free(conn_io->http3);
}
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
BORINGSSL_LIB = $(dir $(shell find $(BUILD_DIR) -path '*boring-sys*' -name libssl.a | head -1))

http3-is-server: http3-is-server.c $(INCLUDE_DIR)/quiche.h $(LIB_DIR)/libquiche.a
	$(CC) $(CFLAGS) $(LDFLAGS) -L$(BORINGSSL_LIB) $< -o $@ \
		$(INCS) -I$(BORINGSSL_INC) $(LIBS) -lssl -lcrypto
```

## 5. Build

```bash
cd quiche/examples
make http3-is-server
```

The first run compiles libquiche + vendored BoringSSL (~1 minute).

## 6. Runtime files (in `quiche/examples/`)

The binary expects these in its working directory:

- `cert-quic-chain.crt` and `cert-quic.key` — TLS cert/key (see the `#define`s
  at the top of the source). Use a locally-trusted cert (e.g. `mkcert`) so
  Chrome accepts it.
- `hello.txt` — the file served over HTTP/3.
- Host `quic.local` resolving to your machine (e.g. add `127.0.0.1 quic.local`
  to `/etc/hosts`), since the server binds and serves on `quic.local:4433`.

Run it and browse to `https://quic.local:4433/`:

```bash
./http3-is-server
```

---

## Summary of why each change is needed

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
