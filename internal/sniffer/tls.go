package sniffer

import (
	"encoding/binary"
)

// sniffTLS attempts to extract the SNI (Server Name Indication) from a TLS ClientHello.
func sniffTLS(data []byte) (string, bool) {
	// Minimum valid ClientHello size (~50 bytes for basic header)
	if len(data) < 50 {
		return "", false
	}

	// Check ContentType: 0x16 = Handshake
	if data[0] != 0x16 {
		return "", false
	}

	// Check protocol version (TLS 1.0 = 0x0301, 1.1 = 0x0302, 1.2 = 0x0303, 1.3 = 0x0304)
	version := binary.BigEndian.Uint16(data[1:3])
	if version < 0x0301 || version > 0x0304 {
		return "", false
	}

	// Handshake message length (bytes 3-5)
	handshakeLen := int(binary.BigEndian.Uint16(data[3:5]))
	if handshakeLen < 4 || len(data) < 5+handshakeLen {
		return "", false
	}

	// Handshake type (byte 5): 0x01 = ClientHello
	if data[5] != 0x01 {
		return "", false
	}

	// ClientHello length (3 bytes, big-endian, starting at byte 6)
	helloLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	if helloLen < 38 || len(data) < 9+helloLen {
		return "", false
	}

	pos := 9 + 2 // skip Protocol Version (2 bytes after handshake header)
	pos += 32   // skip Random (32 bytes)

	if pos+1 > len(data) {
		return "", false
	}

	// Session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(data) {
		return "", false
	}

	// Cipher Suites
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLen
	if pos+1 > len(data) {
		return "", false
	}

	// Compression Methods
	compressionLen := int(data[pos])
	pos += 1 + compressionLen
	if pos+2 > len(data) {
		return "", false
	}

	// Extensions
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	if pos+extLen > len(data) {
		return "", false
	}

	end := pos + extLen

	// Walk through extensions
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+extDataLen > end {
			break
		}

		if extType == 0x0000 { // SNI (Server Name Indication)
			return parseSNI(data[pos : pos+extDataLen])
		}

		pos += extDataLen
	}

	return "", false
}

// parseSNI parses the SNI extension data and returns the hostname.
func parseSNI(data []byte) (string, bool) {
	// Server Name List Length (2 bytes)
	if len(data) < 3 {
		return "", false
	}

	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if listLen < 3 || len(data) < 2+listLen {
		return "", false
	}

	pos := 2
	end := 2 + listLen

	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if pos+nameLen > end {
			break
		}

		if nameType == 0x00 { // host_name
			return string(data[pos : pos+nameLen]), true
		}

		pos += nameLen
	}

	return "", false
}
