package argon2hash_wrapper

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

type Argon2Hash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

func New() *Argon2Hash {
	return &Argon2Hash{
		memory:      64 * 1024,
		iterations:  2,
		parallelism: 4,
		saltLength:  16,
		keyLength:   32,
	}
}

func (p *Argon2Hash) GenerateFromPassword(password string) (hashWithSalt string, err error) {
	//Generate a cryptographically secure random salt.
	salt, err := generateRandomBytes(p.saltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	saltStr := base64.StdEncoding.EncodeToString(salt)
	hashStr := base64.StdEncoding.EncodeToString(hash)

	hashWithSalt = fmt.Sprintf("argon2$%d$%s$%s", p.iterations, saltStr, hashStr)
	return hashWithSalt, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (p *Argon2Hash) CompareHashAndPassword(hashWithSalt string, password string) (err error) {
	parts := strings.Split(hashWithSalt, "$")

	if len(parts) != 4 {
		return errors.New("incorrect hash format")
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	hash, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return err
	}

	computedHash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	if !bytes.Equal(hash, computedHash) {
		return errors.New("incorrect password")
	}
	return nil
}
