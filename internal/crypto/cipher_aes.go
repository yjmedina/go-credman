package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// Cipher provides authenticated encryption (AEAD). Implementations must
// generate a fresh nonce per Seal call and verify integrity in Open.
type AESCipher struct{}

func (_c *AESCipher) Seal(key []byte, plaintext []byte, additionalData []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)

	// Prepend nonce for storage/transmission
	return append(nonce, ciphertext...), nil
}

func (_c *AESCipher) Open(key []byte, ciphertext []byte, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()

	nonce := ciphertext[:nonceSize]
	encrypted := ciphertext[nonceSize:]

	// Verifies authentication tag automatically
	return gcm.Open(nil, nonce, encrypted, additionalData)
}
