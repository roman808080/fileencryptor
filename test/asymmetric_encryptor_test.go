package fileencryptor_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/roman808080/fileencryptor"
)

func TestAsymmetricEncryptionAndDecryption(t *testing.T) {
	// Generate a new RSA key pair for testing
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a new AsymmetricEncryptor and AsymmetricDecryptor
	encryptor := fileencryptor.NewAsymmetricEncryptor(&key.PublicKey)
	decryptor := fileencryptor.NewAsymmetricDecryptor(key)

	// Test data to encrypt and decrypt
	data := []byte("Hello, world!")

	// Create a buffer for the input and output data
	input := bytes.NewBuffer(data)
	output := new(bytes.Buffer)

	// Encrypt the data using the encryptor
	err = encryptor.Encrypt(input, output)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Decrypt the data using the decryptor
	input.Reset()
	input.Write(output.Bytes()) // Set the encrypted data as the new input
	output.Reset()              // Reset the output buffer
	err = decryptor.Decrypt(input, output)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Check that the decrypted data is the same as the original data
	if !bytes.Equal(output.Bytes(), data) {
		t.Fatalf("Decrypted data does not match original data")
	}
}
