package fileencryptor

import (
	"crypto/rand"
	"io"
)

func GetSymmetricKey() ([32]byte, error) {
	var key [32]byte

	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return key, err
	}

	return key, err
}
