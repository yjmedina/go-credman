package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

func Argon2KeyDeriver(password []byte, params KDFParams) ([]byte, error) {
	return argon2.IDKey(password, params.Salt, params.Time, params.Memory, uint8(params.Parallelism), 32), nil
}

func DefaultKDFParamGenerator() KDFParams {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		panic("failed to generate random salt: " + err.Error())
	}

	return KDFParams{
		Salt:        salt,
		Time:        3,         // Number of iterations
		Memory:      32 * 1024, // Memory usage in KiB (32 MiB)
		Parallelism: 4,         // Number of parallel threads
	}
}
