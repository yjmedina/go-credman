package crypto

// Cipher provides authenticated encryption (AEAD). Implementations must
// generate a fresh nonce per Seal call and verify integrity in Open.
type Cipher interface {
	Seal(key []byte, plaintext []byte, additionalData []byte) ([]byte, error)
	Open(key []byte, ciphertext []byte, additionalData []byte) ([]byte, error)
}
