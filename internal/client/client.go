// Package client implements the SecureSOCKS5 client side.
// It listens for SOCKS5 connections from local applications, performs
// the SOCKS5 handshake, then establishes an encrypted tunnel to the
// server, optionally sniffing HTTP/HTTPS domains from the first data.
package client

import (
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"strconv"
	"sync"

	"github.com/bingotang1981/socks5-tunnel/internal/protocol"
	"github.com/bingotang1981/socks5-tunnel/internal/sniffer"
)

// Client handles incoming SOCKS5 connections and proxies them through
// an encrypted tunnel to the SecureSOCKS5 server.
type Client struct {
	listenAddr string
	serverAddr string
	key        []byte
	sniff      bool
	Logger     *log.Logger
}

// New creates a new Client.
func New(listenAddr, serverAddr string, key []byte, sniff bool) *Client {
	return &Client{
		listenAddr: listenAddr,
		serverAddr: serverAddr,
		key:        key,
		sniff:      sniff,
	}
}

func (c *Client) logf(format string, v ...interface{}) {
	l := c.Logger
	if l == nil {
		l = log.Default()
	}
	l.Printf(format, v...)
}

// Run starts the SOCKS5 listener and accepts connections.
func (c *Client) Run() error {
	listener, err := net.Listen("tcp", c.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	c.logf("Client listening for SOCKS5 on %s", c.listenAddr)
	c.logf("Server address: %s", c.serverAddr)
	c.logf("Domain sniffing: %v", c.sniff)

	for {
		localConn, err := listener.Accept()
		if err != nil {
			c.logf("accept error: %v", err)
			continue
		}
		go c.handleConn(localConn)
	}
}

// handleConn processes one SOCKS5 connection from a local application.
func (c *Client) handleConn(local net.Conn) {
	defer local.Close()
	clientAddr := local.RemoteAddr().String()

	// Step 1: SOCKS5 handshake
	targetAddr, err := socks5Handshake(local)
	if err != nil {
		c.logf("SOCKS5 handshake from %s: %v", clientAddr, err)
		return
	}
	// Step 2: SOCKS5 response: success immediately
	socks5Reply(local, 0x00)

	// Step 3: Peek at first data and sniff domain (if enabled).
	// If a domain is found, use it as the CONNECT address; otherwise
	// fall back to the original SOCKS5 target address.
	var preReadData []byte
	connectAddr := targetAddr
	if c.sniff {
		buf := make([]byte, sniffer.MaxPeekBytes)
		n, err := local.Read(buf)
		if err == nil && n > 0 {
			preReadData = buf[:n]
			if domain, ok := sniffer.SniffDomain(preReadData); ok && domain != "" {
				_, portStr, _ := net.SplitHostPort(targetAddr)
				connectAddr = net.JoinHostPort(domain, portStr)
			}
		}
	}

	// Step 4: Connect to the remote server (encrypted tunnel)
	serverConn, err := net.Dial("tcp", c.serverAddr)
	if err != nil {
		c.logf("connect to server %s: %v", c.serverAddr, err)
		return
	}
	defer serverConn.Close()

	// Step 5: Send CONNECT frame with the chosen address
	connectMsg, err := protocol.BuildConnectMsg(connectAddr)
	if err != nil {
		c.logf("build CONNECT msg: %v", err)
		return
	}
	if err := protocol.WriteFrame(serverConn, c.key, connectMsg); err != nil {
		c.logf("send CONNECT frame: %v", err)
		return
	}

	// Step 6: Send the buffered first data chunk (if we pre-read one)
	if len(preReadData) > 0 {
		dataMsg := protocol.BuildDataMsg(preReadData)
		if err := protocol.WriteFrame(serverConn, c.key, dataMsg); err != nil {
			c.logf("send first DATA frame: %v", err)
			return
		}
	}

	// Step 7: Bidirectional relay
	relay(local, serverConn, c.key, c.logf)
}

// --- SOCKS5 Helpers ---

// socks5Handshake performs a SOCKS5 NO-AUTH handshake and extracts the target address.
// It sends appropriate SOCKS5 errors on failure.
func socks5Handshake(conn net.Conn) (string, error) {
	// Read auth negotiation
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != 5 { // VER must be 5
		return "", errors.New("not a SOCKS5 request")
	}

	nMethods := int(header[1])
	if nMethods < 1 {
		return "", errors.New("no auth methods")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}

	// Respond: NO AUTH (0x00)
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return "", err
	}

	// Read the request
	// Minimum: VER(1) + CMD(1) + RSV(1) + ATYP(1) = 4 bytes
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return "", err
	}

	if reqHeader[0] != 5 { // VER
		return "", errors.New("bad SOCKS5 request version")
	}
	if reqHeader[1] != 1 { // CMD: only CONNECT (0x01) is supported
		return "", errors.New("only CONNECT command is supported")
	}
	// reqHeader[2] = RSV (must be 0x00)

	atyp := reqHeader[3]
	var host string

	switch atyp {
	case 1: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case 3: // Domain name
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return "", err
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}
		host = string(domain)

	case 4: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	default:
		return "", errors.New("unknown address type")
	}

	// Read port (2 bytes)
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// socks5Reply sends a SOCKS5 response with the given reply code.
func socks5Reply(conn net.Conn, rep byte) {
	// VER=5, REP, RSV=0, ATYP=1(IPv4), BND.ADDR=0.0.0.0, BND.PORT=0
	_, _ = conn.Write([]byte{5, rep, 0, 1, 0, 0, 0, 0, 0, 0})
}

// --- Relay ---

// relay performs bidirectional copy between a plain TCP connection and an
// encrypted frame-based connection.
func relay(plain net.Conn, encrypted net.Conn, key []byte, logf func(string, ...interface{})) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Direction: plain -> encrypted (read from local, encrypt, send frame)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := plain.Read(buf)
			if err != nil {
				return
			}
			dataMsg := protocol.BuildDataMsg(buf[:n])
			if err := protocol.WriteFrame(encrypted, key, dataMsg); err != nil {
				logf("relay local->server: write frame error: %v", err)
				return
			}
		}
	}()

	// Direction: encrypted -> plain (read frame, decrypt, write to local)
	go func() {
		defer wg.Done()
		for {
			plaintext, err := protocol.ReadFrame(encrypted, key)
			if err != nil {
				return
			}
			payload, err := protocol.ParseDataMsg(plaintext)
			if err != nil {
				logf("relay server->local: parse error: %v", err)
				return
			}
			if _, err := plain.Write(payload); err != nil {
				logf("relay server->local: write error: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}
