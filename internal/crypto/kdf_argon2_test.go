package crypto

import (
	"testing"
)

func TestArgon2KeyDeriver(t *testing.T) {

	password := []byte("my_secure_password")
	params := KDFParams{
		Salt:        []byte("random_salt"),
		Time:        3,
		Memory:      32 * 1024,
		Parallelism: 4,
	}
	t.Run("Keys should be 32 bytes long", func(t *testing.T) {
		key1, err := Argon2KeyDeriver(password, params)
		if err != nil {
			t.Fatalf("Argon2KeyDeriver failed: %v", err)
		}

		if len(key1) != 32 {
			t.Fatalf("Expected key length of 32 bytes, got %d", len(key1))
		}
	})

	t.Run("Generate Keys with same parameters twice", func(t *testing.T) {
		key1, err := Argon2KeyDeriver(password, params)
		if err != nil {
			t.Fatalf("Argon2KeyDeriver failed: %v", err)
		}

		key2, err := Argon2KeyDeriver(password, params)
		if err != nil {
			t.Fatalf("Argon2KeyDeriver failed: %v", err)
		}

		if string(key1) != string(key2) {
			t.Fatalf("Keys derived with same password and params should match. want: %x, got: %x", key1, key2)
		}

	})
	t.Run("Generate Keys with different salt", func(t *testing.T) {
		key1, err := Argon2KeyDeriver(password, params)
		if err != nil {
			t.Fatalf("Argon2KeyDeriver failed: %v", err)
		}

		// Change salt
		differentParams := KDFParams{
			Salt:        []byte("different_salt"),
			Time:        3,
			Memory:      32 * 1024,
			Parallelism: 4,
		}

		key2, err := Argon2KeyDeriver(password, differentParams)
		if err != nil {
			t.Fatalf("Argon2KeyDeriver failed: %v", err)
		}

		if string(key1) == string(key2) {
			t.Fatalf("Keys derived with different params should not match. want: %x, got: %x", key1, key2)
		}

	})
}
