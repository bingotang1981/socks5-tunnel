# SecureSOCKS5 Tunnel — Design Document

## 1. Project Overview

SecureSOCKS5 Tunnel is a lightweight SOCKS5 encrypted proxy tunnel tool. It consists of a **client** and a **server**:

- **Client** — Listens for local SOCKS5 requests, encrypts traffic via AES-256-GCM and sends it to the server
- **Server** — Receives encrypted traffic, decrypts it, connects to the real target server, and returns the response encrypted

All transmissions are authenticated encrypted, ensuring data confidentiality, integrity, and authenticity.

### System Architecture

```
Local App ──SOCKS5──> Client ──Encrypted TCP──> Server ──Plain TCP──> Target
                      (:1080)                    (:443)
```

### Entry Points

| Entry | Path | Responsibility |
|-------|------|----------------|
| `cmd/tunnel/main.go` | Unified entry | Routes to the corresponding logic based on subcommand (`client` / `server`) |
| `runClient()` | Client logic | Reads JSON config, validates key length (must be 32 bytes), starts `Client` |
| `runServer()` | Server logic | Reads JSON config, validates key length, starts `Server` |

The entry uses `os.Args` to identify the subcommand, each subcommand uses `flag.NewFlagSet` to accept the `-config` parameter, with no external dependencies.

---

## 2. Encryption Layer (`internal/crypto`)

### Algorithm Choice

Uses **AES-256-GCM** (Galois/Counter Mode) authenticated encryption. GCM mode provides:

- **Confidentiality** — Data is not visible
- **Integrity** — Data cannot be tampered with
- **Authenticity** — Data source is verifiable

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `KeySize` | 32 bytes | AES-256 key length |
| `NonceLen` | 12 bytes | GCM standard random nonce length |
| `TagLen` | 16 bytes | GCM authentication tag length |

### Data Format

```
Encrypted output: [Nonce (12B)] [Ciphertext + AuthTag (16B)]
```

- Each encryption generates a random 12-byte nonce (`crypto/rand`)
- The nonce is prepended to the ciphertext for transmission
- Decryption extracts the nonce first, then performs GCM decryption (auto-verifies the authentication tag)

### API

```go
func Encrypt(key []byte, plaintext []byte) ([]byte, error)
func Decrypt(key []byte, data []byte) ([]byte, error)
```

### Errors

| Error | Trigger Condition |
|-------|-------------------|
| `ErrInvalidKey` | Key is not 32 bytes |
| `ErrDecrypt` | Decryption failed (wrong key or data tampered) |
| `ErrShortCipher` | Data length < minimum nonce + tag length |
| `ErrShortNonce` | Nonce length insufficient (reserved) |

---

## 3. Wire Protocol Layer (`internal/protocol`)

### Encrypted Frame Format

Each encrypted frame on the TCP stream has the following format:

```
[PayloadLen (4B, BigEndian)] [Nonce (12B)] [AES-256-GCM Ciphertext + Tag (16B)]
```

- `PayloadLen` — Number of bytes of the subsequent nonce + ciphertext (big-endian)
- Frame reading and writing are handled by `WriteFrame` / `ReadFrame`, which internally call `crypto.Encrypt` / `crypto.Decrypt`

### Message Types

The first byte of the decrypted plaintext identifies the message type:

| Type | Code | Direction | Usage |
|------|------|-----------|-------|
| CONNECT | `0x01` | Client → Server | Request to connect to a target address |
| DATA | `0x03` | Bidirectional | Raw TCP payload |

### Address Encoding

Address encoding format (used in CONNECT message body):

```
[AddrType (1B)] [Addr...] [Port (2B, BigEndian)]
```

| Address Type | Code | Address Length | Description |
|-------------|------|----------------|-------------|
| IPv4 | `0x01` | 4 bytes | Raw IP address |
| Domain | `0x03` | 1 byte length + N bytes domain | Domain ≤ 255 bytes |
| IPv6 | `0x04` | 16 bytes | Raw IP address |

### Message Construction and Parsing

| Function | Description |
|----------|-------------|
| `BuildConnectMsg(addr)` → `[]byte` | Encodes the target address into CONNECT frame plaintext |
| `ParseConnectMsg(plaintext)` → `(string, error)` | Parses the target address from a CONNECT frame |
| `BuildDataMsg(payload)` → `[]byte` | Wraps TCP payload into DATA frame plaintext |
| `ParseDataMsg(plaintext)` → `([]byte, error)` | Extracts TCP payload from a DATA frame |
| `PeekMsgType(plaintext)` → `byte` | Reads the message type from plaintext (without parsing) |

### Connection Lifecycle (Wire Protocol View)

```
Client                              Server
  │                                  │
  ├── CONNECT(target addr) ────────► │
  │                                  ├── Connect to target
  │                                  │
  ├── DATA(pre-read data) ────────►  ├── Forward to target
  │   (optional)                     │
  ├── DATA(more data) ───────────►  ├── Forward to target
  │                                  │
  │◄── DATA(target response) ───────├── Read from target
  │         ...                     │
```

---

## 4. Client Module (`internal/client`)

### Struct

```go
type Client struct {
    listenAddr string      // SOCKS5 listen address
    serverAddr string      // Remote server address
    key        []byte      // 32-byte pre-shared key
    sniff      bool        // Whether to enable domain sniffing
    Logger     *log.Logger // Optional logger
}
```

### Connection Lifecycle (Full Flow)

```
Client receives SOCKS5 connection
  │
  1. SOCKS5 handshake
  │   ├── Read auth negotiation (VER, NMETHODS, METHODS)
  │   ├── Reply NO AUTH (0x00)
  │   ├── Read request header (VER, CMD, RSV, ATYP)
  │   ├── Read address + port → obtain targetAddr
  │   └── Only CONNECT command supported (CMD=0x01)
  │
  2. Reply SOCKS5 success (0x00)
  │   Reply immediately without waiting for server connection result
  │
  3. Domain sniffing (if enabled)
  │   ├── Read first data chunk (up to 8192 bytes)
  │   ├── Attempt to sniff HTTP Host header or TLS SNI
  │   ├── Sniffed → connectAddr = domain:port
  │   └── Not sniffed → connectAddr = targetAddr
  │
  4. Connect to server
  │   └── net.Dial("tcp", serverAddr)
  │
  5. Send CONNECT frame
  │   └── Use connectAddr as target address
  │
  6. Send pre-read data (if any)
  │   └── Send first DATA frame
  │
  7. Bidirectional relay
      ├── goroutine A: local → encrypt → server
      └── goroutine B: server → decrypt → local
```

### SOCKS5 Handshake Implementation

Function `socks5Handshake`:

1. Read auth negotiation (`VER=5`, `NMETHODS`, `METHODS`)
2. Reply `[5, 0]` (NO AUTH)
3. Read request (`VER`, `CMD`, `RSV`, `ATYP`)
4. Parse target address based on address type (IPv4 / Domain / IPv6)
5. Only `CMD=0x01` (CONNECT) is supported

Function `socks5Reply`: Sends a standard SOCKS5 response (10 bytes).

### Bidirectional Relay

Function `relay(plain, encrypted, key, logf)`:

- Starts two goroutines, synchronized with `sync.WaitGroup`
- **Direction A**: Read plaintext from local → encrypt and send via `BuildDataMsg` + `WriteFrame`
- **Direction B**: Read encrypted frames from server → decrypt and write to local via `ReadFrame` + `ParseDataMsg`
- Any direction error causes exit, triggering connection closure on the other side

---

## 5. Server Module (`internal/server`)

### Struct

```go
type Server struct {
    addr   string      // Listen address
    key    []byte      // 32-byte pre-shared key
    Logger *log.Logger // Optional logger
}
```

### Connection Lifecycle

```
Server receives encrypted connection
  │
  1. Read CONNECT frame
  │   ├── protocol.ReadFrame → decrypt
  │   ├── protocol.ParseConnectMsg → obtain targetAddr
  │   └── Verify message type is CONNECT (0x01)
  │
  2. Connect to target
  │   └── net.Dial("tcp", targetAddr)
  │
  3. Bidirectional relay
      ├── goroutine A: encrypted frame → decrypt → write to target
      └── goroutine B: target → encrypt → write to connection
```

### Bidirectional Relay

The server relay is symmetric to the client:

- **Direction A**: Read frames from encrypted connection → extract payload via `ParseDataMsg` → write to target
- **Direction B**: Read from target → encrypt and send via `BuildDataMsg` + `WriteFrame`

---

## 6. Domain Sniffing Module (`internal/sniffer`)

### Overview

The `SniffDomain` function extracts a domain name from the first data chunk of a TCP stream. It uses a dual-protocol detection strategy:

1. **HTTP first** — Detects the `Host` header in HTTP requests
2. **TLS fallback** — Detects SNI (Server Name Indication) in TLS ClientHello

```go
func SniffDomain(data []byte) (string, bool)
```

### HTTP Sniffing

1. Check if data starts with a known HTTP method (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `TRACE`, `CONNECT`)
2. Split lines by `\n`, search for `Host:` header line by line (case-insensitive)
3. If a port number is found (all digits after the colon), strip the port
4. Return the plain hostname

### TLS Sniffing

Parses according to the TLS 1.0~1.3 ClientHello structure:

1. Check ContentType = `0x16` (Handshake)
2. Check protocol version is in range `0x0301` ~ `0x0304`
3. Check Handshake Type = `0x01` (ClientHello)
4. Skip fixed fields: ProtocolVersion(2B) + Random(32B)
5. Parse Session ID → Cipher Suites → Compression Methods
6. Iterate through Extensions, looking for type `0x0000` (SNI)
7. Within the SNI extension, look for `name_type=0x00` (host_name)

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `MaxPeekBytes` | 8192 | Maximum bytes to read when sniffing |

---

## 7. Configuration Examples & Usage

### Client Configuration (`client.json`)

```json
{
    "key": "change-me-32-byte-secret-key!!!!",
    "listen_addr": "127.0.0.1:1080",
    "server_addr": "your-server.com:443",
    "sniff_domain": true
}
```

### Server Configuration (`server.json`)

```json
{
    "key": "change-me-32-byte-secret-key!!!!",
    "listen_addr": "0.0.0.0:443"
}
```

> **The key must be exactly 32 bytes**, required for AES-256.

### Build & Run

```bash
# Build
go build ./cmd/tunnel

# Start server
./tunnel server -config server.json

# Start client
./tunnel client -config client.json

# Use the proxy
curl --socks5 127.0.0.1:1080 https://example.com
```

---

## 8. Known Limitations

- **1:1 connection mapping** — One SOCKS5 connection corresponds to one encrypted TCP connection, no connection multiplexing
- **Pre-shared key** — No support for online key rotation or certificate-based authentication
- **CONNECT only** — Does not support SOCKS5 BIND or UDP ASSOCIATE
- **No reconnection** — The client-to-server TCP connection will not automatically reconnect after disconnection
- **Sniffing race condition** — If sniffing fails after pre-reading a data chunk, the data is sent as the first DATA frame without affecting functionality
