package vault

type CredentialRepository interface {
	SaveCredential(creds EncryptedCredential) error
	GetCredential(id CredentialID) (*EncryptedCredential, error)
	UpdateCredential(creds EncryptedCredential) error
	DeleteCredential(id CredentialID) error
}

type VaultRepository interface {
	SaveVault(vault LockedVault) error
	Exists() (bool, error)
	GetVault() (*LockedVault, error)
	DeleteVault() error
}
