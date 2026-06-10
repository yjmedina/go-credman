package crypto

import "crypto/rand"

type KeyDeriverFunction func(password []byte, params KDFParams) ([]byte, error)

type KDFParams struct {
	Salt        []byte
	Time        uint32
	Parallelism uint32
	Memory      uint32
}

type KDFParamGenerator func() KDFParams

func GenerateNewKDF(
	password []byte,
	kdfParams KDFParams,
	keyDeriver KeyDeriverFunction,
	cipher Cipher,
) ([]byte, error) {
	masterKey, err := keyDeriver(password, kdfParams)
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
	wrappedDEK, err := cipher.Seal(masterKey, dek, nil)
	if err != nil {
		return nil, err
	}

	return wrappedDEK, nil
}
