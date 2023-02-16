package fileencryptor

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
)

const defaultPermissions = 0644

type AsymmetricEncryptor struct {
	key *rsa.PublicKey
}

func NewAsymmetricEncryptor(key *rsa.PublicKey) *AsymmetricEncryptor {
	return &AsymmetricEncryptor{key: key}
}

func (e *AsymmetricEncryptor) Encrypt(input io.Reader, output io.Writer) error {
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

type AsymmetricDecryptor struct {
	key *rsa.PrivateKey
}

func NewAsymmetricDecryptor(key *rsa.PrivateKey) *AsymmetricDecryptor {
	return &AsymmetricDecryptor{key: key}
}

func (d *AsymmetricDecryptor) Decrypt(input io.Reader, output io.Writer) error {
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
