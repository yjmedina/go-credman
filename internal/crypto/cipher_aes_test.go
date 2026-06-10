package crypto

import (
	"crypto/rand"
	"testing"
)

func TestAESCipher(t *testing.T) {

	cipher := AESCipher{}

	masterKey := make([]byte, 32) // AES-256 key
	plaintext := []byte("Hello, World!")

	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("generating key: %v", err)
	}

	t.Run("Encrypt and Decrypt", func(t *testing.T) {
		additionalData := make([]byte, 0)

		ciphertext, err := cipher.Seal(masterKey, plaintext, additionalData)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		decrypted, err := cipher.Open(masterKey, ciphertext, additionalData)

		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decrypted text does not match original plaintext. want: %s, got: %s", plaintext, decrypted)
		}
	})

	t.Run("Encrypt and Decrypt with Additional Data", func(t *testing.T) {
		additionalData := []byte("id:12345")

		ciphertext, err := cipher.Seal(masterKey, plaintext, additionalData)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		decrypted, err := cipher.Open(masterKey, ciphertext, additionalData)

		if err != nil {
			t.Fatalf("Open failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Fatalf("Decrypted text does not match original plaintext. want: %s, got: %s", plaintext, decrypted)
		}
	})

	t.Run("Encrypt and Fail Decrypt with wrong master key", func(t *testing.T) {

		additionalData := make([]byte, 0)
		ciphertext, err := cipher.Seal(masterKey, plaintext, additionalData)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		wrongMasterKey := make([]byte, 32)
		if _, err := rand.Read(wrongMasterKey); err != nil {
			t.Fatalf("generating wrong key: %v", err)
		}

		decrypted, err := cipher.Open(wrongMasterKey, ciphertext, additionalData)
		if err == nil {
			t.Fatalf("Open should have failed with wrong master key")
		}

		if decrypted != nil {
			t.Fatalf("Decrypted data should be nil on failure")
		}

	})

	t.Run("Encrypt and Fail Decrypt with Additional Data", func(t *testing.T) {
		additionalData := []byte("id:12345")

		ciphertext, err := cipher.Seal(masterKey, plaintext, additionalData)
		if err != nil {
			t.Fatalf("Seal failed: %v", err)
		}

		wrongAdditionalData := []byte("id:54321")

		decrypted, err := cipher.Open(masterKey, ciphertext, wrongAdditionalData)
		if err == nil {
			t.Fatalf("Open should have failed with wrong additional data")
		}

		if decrypted != nil {
			t.Fatalf("Decrypted data should be nil on failure")
		}

	})

}
