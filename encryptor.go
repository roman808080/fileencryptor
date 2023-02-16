package fileencryptor

import (
	"bytes"
	"crypto/rsa"
	"io"
)

type Encryptor struct {
	input     io.Reader
	output    io.Writer
	publicKey *rsa.PublicKey
	blockSize int
}

func NewEncryptor(input io.Reader, output io.Writer, publicKey *rsa.PublicKey, blockSize int) *Encryptor {
	return &Encryptor{
		input:     input,
		output:    output,
		publicKey: publicKey,
		blockSize: blockSize,
	}
}

func (e *Encryptor) Encrypt() error {
	// Generate a symmetric key
	key, err := GetSymmetricKey()
	if err != nil {
		return err
	}

	rsaEncryptor := NewRSAEncryptor(e.publicKey)

	// Encrypting a symmetric key
	reader := bytes.NewReader(key[:])
	err = rsaEncryptor.Encrypt(reader, e.output)
	if err != nil {
		return err
	}

	// TODO: Add a custom block size

	// Encrypt a file with the generated symmetric key
	symEnc, err := NewSymmetricEncryptor(e.input, e.output, e.blockSize, key)
	if err != nil {
		return err
	}

	return symEnc.Encrypt()
}

type Decryptor struct {
	input      io.Reader
	output     io.Writer
	privateKey *rsa.PrivateKey
	blockSize  int
}

func NewDecryptor(input io.Reader, output io.Writer, privateKey *rsa.PrivateKey, blockSize int) *Decryptor {
	return &Decryptor{
		input:      input,
		output:     output,
		privateKey: privateKey,
		blockSize:  blockSize,
	}
}

func (d *Decryptor) Decrypt() error {
	// Generate a symmetric key
	key, err := GetSymmetricKey()
	if err != nil {
		return err
	}

	rsaEncryptor := NewRSAEncryptor(e.publicKey)

	// Encrypting a symmetric key
	reader := bytes.NewReader(key[:])
	err = rsaEncryptor.Encrypt(reader, e.output)
	if err != nil {
		return err
	}

	// TODO: Add a custom block size

	// Encrypt a file with the generated symmetric key
	symEnc, err := NewSymmetricEncryptor(e.input, e.output, e.blockSize, key)
	if err != nil {
		return err
	}

	return symEnc.Encrypt()
}
