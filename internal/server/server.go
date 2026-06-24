// Package server implements the SecureSOCKS5 server side.
// It listens for encrypted connections from the client, decrypts SOCKS5-style
// CONNECT requests, connects to the target server, and relays data
// bidirectionally with AES-256-GCM encryption.
package server

import (
	"log"
	"net"
	"sync"

	"github.com/bingotang1981/socks5-tunnel/internal/protocol"
)

// Server handles incoming encrypted proxy connections.
type Server struct {
	addr string
	key  []byte
	// Optional logger; if nil, uses log.Default().
	Logger *log.Logger
}

// New creates a new Server.
func New(addr string, key []byte) *Server {
	return &Server{
		addr: addr,
		key:  key,
	}
}

func (s *Server) logf(format string, v ...interface{}) {
	l := s.Logger
	if l == nil {
		l = log.Default()
	}
	l.Printf(format, v...)
}

// Run starts the TCP listener and accepts connections.
func (s *Server) Run() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	s.logf("Server listening on %s", s.addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.logf("accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// handleConn processes one encrypted client connection.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()

	// Step 1: Read CONNECT frame
	plaintext, err := protocol.ReadFrame(conn, s.key)
	if err != nil {
		s.logf("read CONNECT frame from %s: %v", remoteAddr, err)
		return
	}

	targetAddr, err := protocol.ParseConnectMsg(plaintext)
	if err != nil {
		s.logf("parse CONNECT from %s: %v", remoteAddr, err)
		return
	}

	// Step 2: Connect to target
	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		s.logf("connect to target %s from %s: %v", targetAddr, remoteAddr, err)
		return
	}
	defer target.Close()

	// Step 3: Bidirectional relay
	relay(conn, target, s.key, s.logf)
}

// relay performs bidirectional copy between an encrypted connection (using frames)
// and a plain TCP connection.
// encrypted -> read frame, decrypt, write to target
// target -> read, encrypt, write frame to encrypted
func relay(encrypted net.Conn, target net.Conn, key []byte, logf func(string, ...interface{})) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Direction: encrypted frames -> target (plain)
	go func() {
		defer wg.Done()
		for {
			plaintext, err := protocol.ReadFrame(encrypted, key)
			if err != nil {
				// Connection closed or error
				return
			}
			payload, err := protocol.ParseDataMsg(plaintext)
			if err != nil {
				logf("relay encrypted->target: parse error: %v", err)
				return
			}
			if _, err := target.Write(payload); err != nil {
				logf("relay encrypted->target: write error: %v", err)
				return
			}
		}
	}()

	// Direction: target (plain) -> encrypted frames
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := target.Read(buf)
			if err != nil {
				return
			}
			dataMsg := protocol.BuildDataMsg(buf[:n])
			if err := protocol.WriteFrame(encrypted, key, dataMsg); err != nil {
				logf("relay target->encrypted: write frame error: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}
