package vault

import (
	"credman/internal/crypto"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type VaultID string

func CredentialUUIDGenerator() CredentialID {
	return CredentialID(uuid.New().String())
}

// vaultRecord is the persisted form of a vault: the encrypted Data Encryption
// Key (DEK) together with the KDF parameters needed to unwrap it.
type vaultRecord struct {
	ID         VaultID
	KDFParams  crypto.KDFParams
	WrappedDEK []byte
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
