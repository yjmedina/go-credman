package store

type VaultID string

func serializeCredentials(creds Credentials) ([]byte, error) {
	return nil, nil
}

func deserializeCredentials(data []byte) (*Credentials, error) {
	return nil, nil
}

type EncryptedCredential struct {
	ID         CredentialID
	VaultID    VaultID
	ciphertext []byte
}

type CredentialRepository interface {
	save(creds EncryptedCredential) error
	get(id CredentialID) (*EncryptedCredential, error)
	delete(id CredentialID) error
	update(creds EncryptedCredential) error
}

// Vault contains the encrypted Data Encryption Key (DEK) to encrypt data
type UnlockedVault struct {
	ID         VaultID
	dek        []byte
	cipher     Cipher
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
