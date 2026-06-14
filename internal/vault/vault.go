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

func (v *UnlockedVault) New(newCreds NewCredential) error {

	err := validateName(&newCreds.Name)
	if err != nil {
		return err
	}

	creds := Credentials{
		ID:        CredentialUUIDGenerator(),
		VaultID:   v.ID,
		Name:      newCreds.Name,
		Fields:    newCreds.Fields,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	plaintext, err := serializeCredentials(creds)
	if err != nil {
		return err
	}

	additionalData := []byte(creds.ID) // Using CredentialID as additional authenticated data
	ciphertext, err := v.cipher.Seal(v.dek, plaintext, additionalData)
	if err != nil {
		return err
	}

	encryptedCreds := EncryptedCredential{
		ID:         creds.ID,
		Name:       creds.Name,
		VaultID:    v.ID,
		ciphertext: ciphertext,
		UpdatedAt:  creds.UpdatedAt,
	}

	return v.repository.SaveCredential(encryptedCreds)
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

func (v *UnlockedVault) Delete(id CredentialID) error {
	return v.repository.DeleteCredential(id)
}

func (v *UnlockedVault) Update(id CredentialID, fields []Field) error {
	return nil
}
