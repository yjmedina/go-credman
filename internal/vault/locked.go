package vault

// LockedVault: Operations that can be performed without unlocking the vault
type LockedVault struct {
	ID         VaultID
	repository LockedCredentialRepository
}

func (v *LockedVault) ListNames(pattern string) ([]string, error) {
	return v.repository.ListCredentialNames(pattern)
}
