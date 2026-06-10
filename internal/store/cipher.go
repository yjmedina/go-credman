package store

// Key derivation Function Parameters. This are defined once
type Cipher interface {
	Seal(key []byte, plaintext []byte, additionalData []byte) ([]byte, error)
	Open(key []byte, ciphertext []byte, additionalData []byte) ([]byte, error)
}
