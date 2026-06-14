package vault

type CredentialRepository interface {
	SaveCredential(creds EncryptedCredential) error
	GetCredential(id CredentialID) (*EncryptedCredential, error)
	GetCredentialByName(name string) (*EncryptedCredential, error)
	SearchCredentials(pattern string) ([]string, error)
	UpdateCredential(creds EncryptedCredential) error
	DeleteCredential(id CredentialID) error
}

type VaultRepository interface {
	SaveVault(vault LockedVault) error
	Exists() (bool, error)
	GetVault() (*LockedVault, error)
	DeleteVault() error
}
