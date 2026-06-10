package vault

import "credman/internal/crypto"

type VaultID string

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

func (v *UnlockedVault) Save(creds Credentials) error {
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
		VaultID:    v.ID,
		ciphertext: ciphertext,
	}

	return v.repository.save(encryptedCreds)
}

func (v *UnlockedVault) Get(id CredentialID) (*Credentials, error) {
	encryptedCreds, err := v.repository.get(id)
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
	return v.repository.delete(id)
}

func (v *UnlockedVault) Update(id CredentialID, fields []Field) error {
	return nil
}
