package fileencryptor

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"os"
	"testing"

	"github.com/roman808080/fileencryptor"
	"github.com/stretchr/testify/assert"
)

func TestEncryptDecryptHighLevel(t *testing.T) {
	t.Skip("Skipping the test")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	publicKey := &privateKey.PublicKey

	// Create a random file for testing
	content := make([]byte, 100000)
	_, err = rand.Read(content)
	assert.NoError(t, err)

	f, err := ioutil.TempFile("", "encrypt_test")
	assert.NoError(t, err)

	_, err = f.Write(content)
	assert.NoError(t, err)

	err = f.Close()
	assert.NoError(t, err)

	defer os.Remove(f.Name())

	// Open the test file and encrypt it
	origFile, err := os.Open(f.Name())
	assert.NoError(t, err)

	encFile, err := ioutil.TempFile("", "enc_test")
	assert.NoError(t, err)

	enc := fileencryptor.NewEncryptor(origFile, encFile, publicKey, 1024)
	err = enc.Encrypt()
	assert.NoError(t, err)

	err = encFile.Close()
	assert.NoError(t, err)

	// Open the encrypted file and decrypt it
	encFile, err = os.Open(encFile.Name())
	assert.NoError(t, err)

	decFile, err := ioutil.TempFile("", "dec_test")
	assert.NoError(t, err)

	dec := fileencryptor.NewDecryptor(encFile, decFile, privateKey, 1024)
	err = dec.Decrypt()
	assert.NoError(t, err)

	err = decFile.Close()
	assert.NoError(t, err)

	// Compare the original file with the decrypted file
	origData, err := ioutil.ReadFile(f.Name())
	assert.NoError(t, err)

	decData, err := ioutil.ReadFile(decFile.Name())
	assert.NoError(t, err)

	assert.Equal(t, origData, decData)
}
