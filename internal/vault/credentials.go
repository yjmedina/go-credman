package vault

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

type CredentialID string

type Field struct {
	Value     string
	Sensitive bool
}

type NamedField struct {
	Name      string
	Value     string
	Sensitive bool
}

// Credentials represents the structure of a credential entry in the vault.
type Credentials struct {
	ID        CredentialID
	VaultID   VaultID
	Name      string
	Fields    map[string]Field
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (c *Credentials) GetFieldNames() []string {
	names := make([]string, 0, len(c.Fields))
	for name := range c.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type EncryptedCredential struct {
	ID         CredentialID
	VaultID    VaultID
	Name       string
	ciphertext []byte
	UpdatedAt  time.Time
}

type NewCredential struct {
	Name   string
	Fields []NamedField
}

type EditCredential struct {
	Name      string
	NewName   string
	Fields    []NamedField
	Deletions []string
}

func serializeCredentials(creds *Credentials) ([]byte, error) {
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
