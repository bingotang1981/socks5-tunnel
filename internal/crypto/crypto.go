// Package crypto provides AES-256-GCM encryption and decryption.
// Each message uses a random 12-byte nonce (IV).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	KeySize  = 32 // AES-256
	NonceLen = 12 // GCM standard nonce size
	TagLen   = 16 // GCM auth tag
)

var (
	ErrInvalidKey   = errors.New("crypto: key must be exactly 32 bytes")
	ErrDecrypt      = errors.New("crypto: decryption failed (wrong key or tampered data)")
	ErrShortCipher  = errors.New("crypto: ciphertext too short")
	ErrShortNonce   = errors.New("crypto: nonce too short")
)

// Encrypt encrypts plaintext with AES-256-GCM using a random nonce.
// Returns nonce || ciphertext (where ciphertext includes the 16-byte GCM tag).
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends the encrypted data (with tag) to nonce[:0]
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Return nonce || ciphertext
	out := make([]byte, NonceLen+len(ciphertext))
	copy(out[:NonceLen], nonce)
	copy(out[NonceLen:], ciphertext)
	return out, nil
}

// Decrypt decrypts data produced by Encrypt.
// Expects: nonce (12B) || ciphertext (with 16B GCM tag appended).
func Decrypt(key []byte, data []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKey
	}

	if len(data) < NonceLen+TagLen {
		return nil, ErrShortCipher
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := data[:NonceLen]
	ciphertext := data[NonceLen:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrDecrypt
	}

	return plaintext, nil
}
