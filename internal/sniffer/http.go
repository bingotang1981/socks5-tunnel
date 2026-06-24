// Package sniffer provides application-layer domain name detection
// from the first bytes of a TCP connection (HTTP Host header or TLS SNI).
package sniffer

import (
	"bytes"
	"strings"
)

// MaxPeekBytes is the maximum number of bytes we'll read to sniff the protocol.
const MaxPeekBytes = 8192

// httpMethods are the HTTP request methods we recognise.
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("TRACE "),
	[]byte("CONNECT "),
}

// SniffDomain attempts to extract a domain name from raw bytes.
// Returns the domain (without port) and a boolean indicating success.
// It checks for HTTP first, then TLS.
func SniffDomain(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}

	// Try HTTP first
	if domain, ok := sniffHTTP(data); ok {
		return domain, true
	}

	// Try TLS/HTTPS
	if domain, ok := sniffTLS(data); ok {
		return domain, true
	}

	return "", false
}

// sniffHTTP extracts the Host header from an HTTP request.
func sniffHTTP(data []byte) (string, bool) {
	// Check if it looks like an HTTP request (starts with a method)
	isHTTP := false
	for _, method := range httpMethods {
		if bytes.HasPrefix(data, method) {
			isHTTP = true
			break
		}
	}
	if !isHTTP {
		return "", false
	}

	// Split into lines (CRLF or LF)
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimRight(line, "\r")
		if len(line) < 5 {
			continue
		}
		// Look for "Host:" (case-insensitive)
		if !strings.HasPrefix(strings.ToLower(string(line)), "host:") {
			continue
		}
		hostVal := strings.TrimSpace(string(line[5:])) // after "Host:"
		// Remove port if present
		if idx := strings.LastIndex(hostVal, ":"); idx >= 0 {
			// Check it's actually a port (all digits after colon)
			portPart := hostVal[idx+1:]
			isPort := true
			for _, c := range portPart {
				if c < '0' || c > '9' {
					isPort = false
					break
				}
			}
			if isPort {
				hostVal = hostVal[:idx]
			}
		}
		if hostVal != "" {
			return hostVal, true
		}
	}

	return "", false
}
