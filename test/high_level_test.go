package fileencryptor_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/roman808080/fileencryptor"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDecryptHighLevel(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	publicKey := &privateKey.PublicKey

	// Create a random file for testing
	content := make([]byte, 100000)
	_, err = rand.Read(content)
	assert.NoError(t, err)

	origFile := bytes.NewReader(content)

	encFile := new(bytes.Buffer)
	enc := fileencryptor.NewEncryptor(origFile, encFile, publicKey, 1024)
	err = enc.Encrypt()
	assert.NoError(t, err)

	decFile := new(bytes.Buffer)
	dec := fileencryptor.NewDecryptor(encFile, decFile, privateKey, 1024)
	err = dec.Decrypt()
	assert.NoError(t, err)

	// Compare the original file with the decrypted file
	assert.Equal(t, content, decFile.Bytes())
}
