package store

import "time"

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
	Title     string
	Fields    []Field
	CreatedAt time.Time
	UpdatedAt time.Time
}
