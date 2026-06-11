package vault

import (
	"credman/internal/crypto"
)

type VaultIdGenerator func() VaultID

type VaultManager struct {
	vaultRepo         VaultRepository
	credRepo          CredentialRepository
	keyDeriver        crypto.KeyDeriverFunction
	cipher            crypto.Cipher
	idGenerator       VaultIdGenerator
	kdfParamGenerator crypto.KDFParamGenerator
}

func (m *VaultManager) CreateVault(password []byte) (*LockedVault, error) {
	kdfParams := m.kdfParamGenerator()
	wrappedDEK, err := crypto.GenerateNewKDF(password, kdfParams, m.keyDeriver, m.cipher)
	if err != nil {
		return nil, err
	}
	vaultID := m.idGenerator()

	vault := LockedVault{
		ID:         vaultID,
		KDFParams:  kdfParams,
		WrappedDEK: wrappedDEK,
	}

	err = m.vaultRepo.save(vault)
	if err != nil {
		return nil, err
	}

	return &vault, nil

}
func (m *VaultManager) UnlockVault(id VaultID, password []byte) (*UnlockedVault, error) {
	lockedVault, err := m.vaultRepo.get(id)
	if err != nil {
		return nil, err
	}

	masterKey, err := m.keyDeriver(password, lockedVault.KDFParams)
	if err != nil {
		return nil, err
	}

	dek, err := m.cipher.Open(masterKey, lockedVault.WrappedDEK, nil)
	if err != nil {
		return nil, err
	}

	return &UnlockedVault{
		ID:         lockedVault.ID,
		dek:        dek,
		cipher:     m.cipher,
		repository: m.credRepo,
	}, nil
}

func (m *VaultManager) DeleteVault(id VaultID) error {
	return m.vaultRepo.delete(id)

}

func (m *VaultManager) GetDefaultVault() (*LockedVault, error) {
	defaultID := m.vaultRepo.getDefault()
	return m.vaultRepo.get(defaultID)
}

func (m *VaultManager) Init(password []byte) error {
	// Check if default vault already exists
	defaultID := m.vaultRepo.getDefault()
	// already exists
	if defaultID != "" {
		return nil
	}
	// create Default vault
	defaultVault, err := m.CreateVault(password)
	if err != nil {
		return err
	}
	// set default vault
	m.vaultRepo.setDefault(defaultVault.ID)
	return nil
}
