package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params configurable for hashing.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params returns OWASP-recommended defaults for Argon2id.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024, // 64 MiB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Argon2Hasher implements ports.PasswordHasher using Argon2id.
type Argon2Hasher struct {
	params Argon2Params
}

func NewArgon2Hasher(params Argon2Params) *Argon2Hasher {
	return &Argon2Hasher{params: params}
}

func (h *Argon2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.params.Iterations,
		h.params.Memory,
		h.params.Parallelism,
		h.params.KeyLength,
	)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.Memory, h.params.Iterations, h.params.Parallelism, b64Salt, b64Hash), nil
}

func (h *Argon2Hasher) Verify(password, encoded string) bool {
	params, salt, hash, err := decodeHash(encoded)
	if err != nil {
		return false
	}
	decodedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)
	return subtle.ConstantTimeCompare(hash, decodedHash) == 1
}

func decodeHash(encoded string) (params *Argon2Params, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid argon2 hash format")
	}
	var version int
	_, _ = fmt.Sscanf(parts[2], "v=%d", &version)
	if version != argon2.Version {
		return nil, nil, nil, errors.New("unsupported argon2 version")
	}
	params = &Argon2Params{}
	_, _ = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism)
	params.SaltLength = 16
	params.KeyLength = 32
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, err
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, err
	}
	return params, salt, hash, nil
}
