package fileencryptor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

func LoadPrivateRSAKey(keyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func LoadPublicKeyFromRSACert(certData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate does not contain an RSA public key")
	}

	return publicKey, nil
}
