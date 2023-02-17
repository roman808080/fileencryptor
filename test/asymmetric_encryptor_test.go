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
	encryptor := fileencryptor.NewRSAEncryptor(&key.PublicKey)
	decryptor := fileencryptor.NewRSADecryptor(key)

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

func TestAsymmetricEncryptionAndDecryptionAdditionalBytes(t *testing.T) {
	// Generate a new RSA key pair for testing
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a new AsymmetricEncryptor and AsymmetricDecryptor
	encryptor := fileencryptor.NewRSAEncryptor(&key.PublicKey)
	decryptor := fileencryptor.NewRSADecryptor(key)

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

	// Writing unencrypted data to read them after decrypting the first part.
	_, err = output.Write(data)
	if err != nil {
		t.Fatalf("Failed to write data at the end: %v", err)
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

	var additionalOutput []byte
	additionalOutput = make([]byte, len(data))
	_, err = input.Read(additionalOutput)
	if err != nil {
		t.Fatalf("Failed to read data from the end: %v", err)
	}

	if !bytes.Equal(additionalOutput, data) {
		t.Fatalf("Appended bytes at the end were not read properly")
	}
}
