package vault

// LockedCredentialRepository exposes only the credential operations that are
// safe to perform while the vault is locked: metadata lookups that do not
// require the DEK and reveal no plaintext.
type LockedCredentialRepository interface {
	ExistsByName(name string) (bool, error)
	ListCredentialNames(pattern string) ([]string, error)
}

// CredentialRepository is the full credential persistence surface, available
// only once the vault has been unlocked.
type CredentialRepository interface {
	LockedCredentialRepository
	SaveCredential(creds EncryptedCredential) error
	GetCredential(id CredentialID) (*EncryptedCredential, error)
	GetCredentialByName(name string) (*EncryptedCredential, error)
	UpdateCredential(creds EncryptedCredential) error
	DeleteCredential(id CredentialID) error
	DeleteCredentialByName(name string) error
}

type VaultRepository interface {
	SaveVault(vault vaultRecord) error
	Exists() (bool, error)
	GetVault() (*vaultRecord, error)
	DeleteVault() error
}
