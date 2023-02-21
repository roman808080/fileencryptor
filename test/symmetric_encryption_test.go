package fileencryptor_test

import (
	"bytes"
	"testing"

	"github.com/roman808080/fileencryptor"
)

func TestSymmetricEncryption(t *testing.T) {
	// Create some input data
	inputData := []byte("hello world")

	// Create input and output buffers
	forEncryption := bytes.NewBuffer(inputData)
	forDecryption := &bytes.Buffer{}
	gobWriter := fileencryptor.NewGobWriter(forDecryption)

	key, err := fileencryptor.GetSymmetricKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Create a new FileEncryptor instance
	blockSize := 5
	encryptor, err := fileencryptor.NewSymmetricEncryptor(forEncryption, gobWriter, blockSize, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Call the Encrypt method to encrypt the data
	if err := encryptor.Encrypt(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that the encrypted data has been written to the output buffer
	if forDecryption.Len() == 0 {
		t.Errorf("output buffer is empty")
	}
	gobReader := fileencryptor.NewGobReader(forDecryption)

	out := &bytes.Buffer{}

	// Create a new FileDecryptor instance
	decryptor, err := fileencryptor.NewSymmetricDecryptor(gobReader, out, blockSize, key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Call the Decrypt method to decrypt the data
	if err := decryptor.Decrypt(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that the decrypted data has been written to the output buffer
	if out.Len() == 0 {
		t.Errorf("output buffer is empty")
	}

	// Verify that the decrypted data is the same as the original input data
	if !bytes.Equal(out.Bytes(), inputData) {
		t.Errorf("unexpected output: %v", out.Bytes())
	}
}
