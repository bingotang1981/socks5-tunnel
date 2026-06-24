# SecureSOCKS5 Tunnel

A lightweight SOCKS5 proxy with AES-256-GCM encrypted transport between client and server.

## Architecture

```
Local App ──SOCKS5──> Client ──Encrypted TCP──> Server ──Plain TCP──> Target
                      (:1080)                    (:443)
```

- **Client** (`tunnel client`) receives local SOCKS5 connections, encrypts all data with AES-256-GCM, forwards to Server.
- **Server** (`tunnel server`) decrypts the traffic, connects to the real target, relays data back encrypted.

Pre-shared key (32 bytes) is configured on both sides.

## Usage

### 1. Prepare config

Create `client.json` for the client and `server.json` for the server:

```json
{
    "key": "change-me-32-byte-secret-key!!!!",
    "listen_addr": "127.0.0.1:1080",
    "server_addr": "your-server.com:443",
    "sniff_domain": true
}
```

Server config (`server.json`):

```json
{
    "key": "change-me-32-byte-secret-key!!!!",
    "listen_addr": "0.0.0.0:443"
}
```

> **The key must be exactly 32 bytes for AES-256.**

### 2. Start server

```bash
go run ./cmd/tunnel server -config server.json
```

### 3. Start client

```bash
go run ./cmd/tunnel client -config client.json
```

### 4. Use the proxy

```bash
curl --socks5 127.0.0.1:1080 https://example.com
```

Or configure your browser to use `127.0.0.1:1080` as SOCKS5 proxy.

## Domain Sniffing

When enabled (`sniff_domain: true`), the client inspects the first data from the local connection:

- **HTTP**: extracts the `Host` header
- **HTTPS/TLS**: extracts the SNI (Server Name Indication) from ClientHello

If a domain is found, it is used as the target address in the CONNECT frame instead of the original SOCKS5 address. If no domain is detected, the SOCKS5 address is used as-is.

## Wire Protocol

Each encrypted frame on the TCP stream:

```
[4B PayloadLen (BE)] [12B Random Nonce] [AES-256-GCM Ciphertext + 16B Tag]
```

Message types (inside decrypted payload, 1st byte):

| Type | Code | Direction | Purpose |
|------|------|-----------|---------|
| CONNECT | 0x01 | Client → Server | Target address request (uses sniffed domain when available) |
| DATA | 0x03 | Bidirectional | Raw TCP payload |

## Build

```bash
go build ./cmd/tunnel
```

## Limitations

- 1:1 connection mapping (one SOCKS5 connection = one encrypted TCP connection)
- Pre-shared key only (no online key rotation)
- SOCKS5 CONNECT command only (no BIND or UDP ASSOCIATE)
