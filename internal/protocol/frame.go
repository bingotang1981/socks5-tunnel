// Package protocol defines the wire protocol between Client and Server.
// Each encrypted frame: [4B PayloadLen][12B Nonce][Variable Ciphertext+Tag]
// The plaintext inside always starts with a 1-byte message type.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/bingotang1981/socks5-tunnel/internal/crypto"
)

// Message types (1st byte of plaintext).
const (
	MsgTypeConnect = byte(0x01) // Client → Server: target address request
	MsgTypeData    = byte(0x03) // bidirectional: raw TCP payload
)

// Address types (used in CONNECT and address encoding).
const (
	AddrTypeIPv4 = byte(1)
	AddrTypeDomain = byte(3)
	AddrTypeIPv6 = byte(4)
)

var (
	ErrShortFrame  = errors.New("protocol: frame too short")
	ErrUnknownMsg  = errors.New("protocol: unknown message type")
	ErrUnknownAddr = errors.New("protocol: unknown address type")
)

// --- Frame I/O (encrypted framing on a TCP stream) ---

// WriteFrame encrypts plaintext and writes one frame to w.
func WriteFrame(w io.Writer, key []byte, plaintext []byte) error {
	ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt frame: %w", err)
	}

	// length prefix (4 bytes, big-endian)
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(ciphertext)))

	if _, err := w.Write(header); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := w.Write(ciphertext); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

// ReadFrame reads one encrypted frame from r and returns the decrypted plaintext.
func ReadFrame(r io.Reader, key []byte) ([]byte, error) {
	// read 4-byte length prefix
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("read frame header: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(header)
	if payloadLen < crypto.NonceLen+crypto.TagLen {
		return nil, ErrShortFrame
	}

	// read the nonce + ciphertext
	ciphertext := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, ciphertext); err != nil {
		return nil, fmt.Errorf("read frame body: %w", err)
	}

	plaintext, err := crypto.Decrypt(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt frame: %w", err)
	}
	return plaintext, nil
}

// --- Address Encoding ---

// EncodeAddress serializes an address into the wire format:
// [AddrType][Addr...][Port(2B)]
func EncodeAddress(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host:port: %w", err)
	}

	port := make([]byte, 2)
	p, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, fmt.Errorf("parse port: %w", err)
	}
	binary.BigEndian.PutUint16(port, uint16(p))

	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4
			out := make([]byte, 1+4+2)
			out[0] = AddrTypeIPv4
			copy(out[1:], ip4)
			copy(out[5:], port)
			return out, nil
		}
		// IPv6
		ip16 := ip.To16()
		out := make([]byte, 1+16+2)
		out[0] = AddrTypeIPv6
		copy(out[1:], ip16)
		copy(out[17:], port)
		return out, nil
	}

	// Domain name
	if len(host) > 255 {
		return nil, errors.New("protocol: domain name too long (>255)")
	}
	out := make([]byte, 1+1+len(host)+2)
	out[0] = AddrTypeDomain
	out[1] = byte(len(host))
	copy(out[2:], []byte(host))
	copy(out[2+len(host):], port)
	return out, nil
}

// DecodeAddress parses an address from wire format.
func DecodeAddress(data []byte) (string, error) {
	if len(data) < 4 {
		return "", ErrShortFrame
	}

	atyp := data[0]
	var host string
	var offset int

	switch atyp {
	case AddrTypeIPv4:
		if len(data) < 1+4+2 {
			return "", ErrShortFrame
		}
		host = net.IP(data[1:5]).String()
		offset = 1 + 4
	case AddrTypeIPv6:
		if len(data) < 1+16+2 {
			return "", ErrShortFrame
		}
		host = net.IP(data[1:17]).String()
		offset = 1 + 16
	case AddrTypeDomain:
		if len(data) < 2 {
			return "", ErrShortFrame
		}
		domainLen := int(data[1])
		if len(data) < 1+1+domainLen+2 {
			return "", ErrShortFrame
		}
		host = string(data[2 : 2+domainLen])
		offset = 1 + 1 + domainLen
	default:
		return "", ErrUnknownAddr
	}

	port := binary.BigEndian.Uint16(data[offset : offset+2])
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// --- Message Builders / Parsers ---

// BuildConnectMsg builds a CONNECT frame plaintext.
func BuildConnectMsg(addr string) ([]byte, error) {
	addrBytes, err := EncodeAddress(addr)
	if err != nil {
		return nil, err
	}
	msg := make([]byte, 1+len(addrBytes))
	msg[0] = MsgTypeConnect
	copy(msg[1:], addrBytes)
	return msg, nil
}

// ParseConnectMsg parses a CONNECT frame plaintext and returns the target address.
func ParseConnectMsg(plaintext []byte) (string, error) {
	if len(plaintext) < 2 || plaintext[0] != MsgTypeConnect {
		return "", ErrUnknownMsg
	}
	return DecodeAddress(plaintext[1:])
}

// BuildDataMsg builds a DATA frame plaintext.
func BuildDataMsg(payload []byte) []byte {
	msg := make([]byte, 1+len(payload))
	msg[0] = MsgTypeData
	copy(msg[1:], payload)
	return msg
}

// ParseDataMsg extracts the payload from a DATA frame.
func ParseDataMsg(plaintext []byte) ([]byte, error) {
	if len(plaintext) < 1 || plaintext[0] != MsgTypeData {
		return nil, ErrUnknownMsg
	}
	return plaintext[1:], nil
}

// PeekMsgType returns the message type from a decrypted plaintext.
func PeekMsgType(plaintext []byte) byte {
	if len(plaintext) == 0 {
		return 0
	}
	return plaintext[0]
}
