package vault

import (
	"encoding/json"
	"fmt"
	"time"
)

type CredentialID string

type Field struct {
	Name      string
	Value     string
	Sensitive bool
}

// Credentials represents the structure of a credential entry in the vault.
type Credentials struct {
	ID        CredentialID
	VaultID   VaultID
	Name      string
	Fields    []Field
	CreatedAt time.Time
	UpdatedAt time.Time
}

type EncryptedCredential struct {
	ID         CredentialID
	VaultID    VaultID
	Name       string
	ciphertext []byte
	UpdatedAt  time.Time
}

func serializeCredentials(creds Credentials) ([]byte, error) {
	data, err := json.Marshal(creds)
	if err != nil {
		return nil, fmt.Errorf("serialize credentials: %w", err)
	}
	return data, nil
}

func deserializeCredentials(data []byte) (*Credentials, error) {
	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("deserialize credentials: %w", err)
	}
	return &creds, nil
}
