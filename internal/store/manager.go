package store

import "crypto/rand"

type KDFParams struct {
	Salt        []byte
	Time        uint32
	Parallelism uint32
	Memory      uint32
}

type LockedVault struct {
	ID         VaultID
	KDFParams  KDFParams
	WrappedDEK []byte
}

type VaultRepository interface {
	save(vault LockedVault) error
	get(id VaultID) (*LockedVault, error)
	delete(id VaultID) error
}

type KeyDeriverFunction func(password []byte, params KDFParams) ([]byte, error)
type VaultIdGenerator func() VaultID
type KDFParamGenerator func() KDFParams

type VaultManager struct {
	vaultRepo         VaultRepository
	credRepo          CredentialRepository
	keyDeriver        KeyDeriverFunction
	cipher            Cipher
	idGenerator       VaultIdGenerator
	kdfParamGenerator KDFParamGenerator
}

func (m *VaultManager) CreateVault(password []byte) (*LockedVault, error) {
	kdfParams := m.kdfParamGenerator()
	master_key, err := m.keyDeriver(password, kdfParams)
	if err != nil {
		return nil, err
	}

	// generate random DEK (Data Encryption Key)
	dek := make([]byte, 32) // Generate a random DEK (Data Encryption Key)
	_, err = rand.Read(dek)
	if err != nil {
		return nil, err
	}

	// encrypt DEK with master key
	wrappedDEK, err := m.cipher.Seal(master_key, dek, nil)
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

	master_key, err := m.keyDeriver(password, lockedVault.KDFParams)
	if err != nil {
		return nil, err
	}

	dek, err := m.cipher.Open(master_key, lockedVault.WrappedDEK, nil)
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
