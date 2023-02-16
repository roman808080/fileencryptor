package fileencryptor

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
)

const defaultPermissions = 0644

type RSAEncryptor struct {
	key *rsa.PublicKey
}

func NewRSAEncryptor(key *rsa.PublicKey) *RSAEncryptor {
	return &RSAEncryptor{key: key}
}

func (e *RSAEncryptor) Encrypt(input io.Reader, output io.Writer) error {
	inputData, err := io.ReadAll(input)
	if err != nil {
		return err
	}

	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, e.key, inputData)
	if err != nil {
		return err
	}

	if _, err := output.Write(cipherText); err != nil {
		return err
	}

	return nil
}

type RSADecryptor struct {
	key *rsa.PrivateKey
}

func NewRSADecryptor(key *rsa.PrivateKey) *RSADecryptor {
	return &RSADecryptor{key: key}
}

func (d *RSADecryptor) Decrypt(input io.Reader, output io.Writer) error {
	inputData, err := io.ReadAll(input)
	if err != nil {
		return err
	}

	plainText, err := rsa.DecryptPKCS1v15(rand.Reader, d.key, inputData)
	if err != nil {
		return err
	}

	if _, err := output.Write(plainText); err != nil {
		return err
	}

	return nil
}
