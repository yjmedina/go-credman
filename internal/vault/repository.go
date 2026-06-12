package vault

type CredentialRepository interface {
	SaveCredential(creds EncryptedCredential) error
	GetCredential(id CredentialID) (*EncryptedCredential, error)
	UpdateCredential(creds EncryptedCredential) error
	DeleteCredential(id CredentialID) error
}

type VaultRepository interface {
	SaveVault(vault LockedVault) error
	GetVault(id VaultID) (*LockedVault, error)
	GetDefaultVault() (VaultID, error)
	SetDefaultVault(id VaultID) error
	DeleteVault(id VaultID) error
}
