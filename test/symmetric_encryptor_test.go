package fileencryptor_test

import (
	"bytes"
	"testing"

	"github.com/roman808080/fileencryptor"
)

func TestFileEncryptor_Encrypt(t *testing.T) {
	// Create some input data
	inputData := []byte("hello world")

	// Create input and output buffers
	in := bytes.NewBuffer(inputData)
	out := &bytes.Buffer{}

	// Create a new FileEncryptor instance
	blockSize := 5
	encryptor, err := fileencryptor.NewSymmetricEncryptor(in, out, blockSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Call the Encrypt method to encrypt the data
	if err := encryptor.Encrypt(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify that the encrypted data has been written to the output buffer
	if out.Len() == 0 {
		t.Errorf("output buffer is empty")
	}

	// Verify that the encrypted data has the correct length
	if out.Len() != len(inputData)+12+(len(inputData)+blockSize-1)/blockSize*16 {
		t.Errorf("unexpected output length: %d", out.Len())
	}
}
