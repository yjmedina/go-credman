package vault

type CredentialRepository interface {
	save(creds EncryptedCredential) error
	get(id CredentialID) (*EncryptedCredential, error)
	delete(id CredentialID) error
	update(creds EncryptedCredential) error
}

type VaultRepository interface {
	save(vault LockedVault) error
	get(id VaultID) (*LockedVault, error)
	delete(id VaultID) error
}
