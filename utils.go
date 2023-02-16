package fileencryptor

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

func GetSymmetricKey() ([chacha20poly1305.KeySize]byte, error) {
	var key [chacha20poly1305.KeySize]byte

	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return key, err
	}

	return key, err
}
