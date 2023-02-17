package fileencryptor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/gob"
	"hash"
	"io"
)

const defaultPermissions = 0644

type RSAEncryptor struct {
	key  *rsa.PublicKey
	hash hash.Hash
}

func NewRSAEncryptor(key *rsa.PublicKey) *RSAEncryptor {
	return &RSAEncryptor{
		key:  key,
		hash: sha256.New()}
}

func (e *RSAEncryptor) Encrypt(input io.Reader, output io.Writer) error {
	// TODO: Read all content from io.Reader, not nice
	inputData, err := io.ReadAll(input)
	if err != nil {
		return err
	}

	cipherText, err := rsa.EncryptOAEP(e.hash, rand.Reader, e.key, inputData, nil)
	if err != nil {
		return err
	}

	enc := gob.NewEncoder(output)
	err = enc.Encode(cipherText)
	if err != nil {
		return err
	}

	return nil
}

type RSADecryptor struct {
	key  *rsa.PrivateKey
	hash hash.Hash
}

func NewRSADecryptor(key *rsa.PrivateKey) *RSADecryptor {
	return &RSADecryptor{
		key:  key,
		hash: sha256.New()}
}

func (d *RSADecryptor) Decrypt(input io.Reader, output io.Writer) error {
	var encryptedMessage []byte
	dec := gob.NewDecoder(input)

	err := dec.Decode(&encryptedMessage)
	if err != nil {
		return err
	}

	plainText, err := rsa.DecryptOAEP(d.hash, rand.Reader, d.key, encryptedMessage, nil)
	if err != nil {
		return err
	}

	if _, err := output.Write(plainText); err != nil {
		return err
	}

	return nil
}
