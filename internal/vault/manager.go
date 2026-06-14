package vault

import (
	"credman/internal/crypto"
	"fmt"

	"github.com/google/uuid"
)

type VaultIdGenerator func() VaultID

func UUIDGenerator() VaultID {
	return VaultID(uuid.New().String())
}

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

	err = m.vaultRepo.SaveVault(vault)
	if err != nil {
		return nil, err
	}

	return &vault, nil

}
func (m *VaultManager) UnlockVault(password []byte) (*UnlockedVault, error) {
	lockedVault, err := m.vaultRepo.GetVault()
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

func (m *VaultManager) DeleteVault() error {
	return m.vaultRepo.DeleteVault()

}
func (m *VaultManager) Init(password []byte) error {
	// Check if default vault already exists
	exists, err := m.vaultRepo.Exists()
	if err != nil {
		return err
	}

	if exists {
		return nil
	}

	_, err = m.CreateVault(password)
	if err != nil {
		return err
	}

	return nil
}

func NewVaultManager() (*VaultManager, error) {
	repo, err := NewSqlLiteRepository()
	if err != nil {
		return nil, fmt.Errorf("Failed to init sql repository %e", err)
	}

	cipher := crypto.AESCipher{}

	manager := VaultManager{
		vaultRepo:         repo,
		credRepo:          repo,
		cipher:            &cipher,
		keyDeriver:        crypto.Argon2KeyDeriver,
		idGenerator:       UUIDGenerator,
		kdfParamGenerator: crypto.DefaultKDFParamGenerator,
	}

	return &manager, nil

}
