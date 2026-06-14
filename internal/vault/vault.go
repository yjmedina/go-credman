package vault

import (
	"credman/internal/crypto"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type VaultID string

func CredentialUUIDGenerator() CredentialID {
	return CredentialID(uuid.New().String())
}

// LockedVault contains the encrypted Data Encryption Key (DEK) to encrypt data
type LockedVault struct {
	ID         VaultID
	KDFParams  crypto.KDFParams
	WrappedDEK []byte
}

// UnlockedVault contains the encrypted Data Encryption Key (DEK) to encrypt data
type UnlockedVault struct {
	ID         VaultID
	dek        []byte
	cipher     crypto.Cipher
	repository CredentialRepository
}

// validateName accepts ASCII letters, digits, and '-'. Empty or nil is rejected.
func validateName(name *string) error {
	if name == nil || *name == "" {
		return errors.New("name is required")
	}
	for _, r := range *name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return fmt.Errorf("name contains invalid character %q (allowed: a-z, A-Z, 0-9, -)", r)
		}
	}
	return nil
}

// validateFieldName accepts ASCII letters, digits, '-', and '_'. Empty is rejected.
func validateFieldName(name string) error {
	if name == "" {
		return errors.New("field name is required")
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return fmt.Errorf("field name contains invalid character %q (allowed: a-z, A-Z, 0-9, -, _)", r)
		}
	}
	return nil
}

func (v *UnlockedVault) New(newCreds NewCredential) (*Credentials, error) {

	err := validateName(&newCreds.Name)
	if err != nil {
		return nil, err
	}
	fields := make(map[string]Field, len(newCreds.Fields))
	for _, field := range newCreds.Fields {
		if err := validateFieldName(field.Name); err != nil {
			return nil, err
		}
		if _, exists := fields[field.Name]; exists {
			return nil, fmt.Errorf("duplicate field name: %q", field.Name)
		}
		fields[field.Name] = Field{Value: field.Value, Sensitive: field.Sensitive}
	}

	creds := Credentials{
		ID:        CredentialUUIDGenerator(),
		VaultID:   v.ID,
		Name:      newCreds.Name,
		Fields:    fields,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	plaintext, err := serializeCredentials(creds)
	if err != nil {
		return nil, err
	}

	additionalData := []byte(creds.ID) // Using CredentialID as additional authenticated data
	ciphertext, err := v.cipher.Seal(v.dek, plaintext, additionalData)
	if err != nil {
		return nil, err
	}

	encryptedCreds := EncryptedCredential{
		ID:         creds.ID,
		Name:       creds.Name,
		VaultID:    v.ID,
		ciphertext: ciphertext,
		UpdatedAt:  creds.UpdatedAt,
	}

	err = v.repository.SaveCredential(encryptedCreds)
	if err != nil {
		return nil, err
	}

	return &creds, nil
}

func (v *UnlockedVault) Get(id CredentialID) (*Credentials, error) {
	encryptedCreds, err := v.repository.GetCredential(id)
	if err != nil {
		return nil, err
	}
	additionalData := []byte(encryptedCreds.ID)
	plaintext, err := v.cipher.Open(v.dek, encryptedCreds.ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	return deserializeCredentials(plaintext)
}

func (v *UnlockedVault) GetByName(name string) (*Credentials, error) {
	encryptedCreds, err := v.repository.GetCredentialByName(name)
	if err != nil {
		return nil, err
	}
	additionalData := []byte(encryptedCreds.ID)
	plaintext, err := v.cipher.Open(v.dek, encryptedCreds.ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	return deserializeCredentials(plaintext)
}

func (v *UnlockedVault) Delete(id CredentialID) error {
	return v.repository.DeleteCredential(id)
}

func (v *UnlockedVault) Update(id CredentialID, fields []Field) error {
	return nil
}

func (v *UnlockedVault) Search(pattern string) ([]string, error) {
	return v.repository.SearchCredentials(pattern)
}
