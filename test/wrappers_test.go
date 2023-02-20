package fileencryptor_test

import (
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/roman808080/fileencryptor"
)

func TestWrapper(t *testing.T) {
	// Create some sample data
	input := [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("foo"),
		[]byte("bar"),
		[]byte("baz"),
	}

	// Encode data using EncoderWrapper
	buf := bytes.NewBuffer(nil)
	enc := fileencryptor.NewGobWriter(buf)
	for _, m := range input {
		err := enc.Write(m)
		if err != nil {
			t.Errorf("error encoding value: %v", err)
		}
	}

	// Decode data using DecoderWrapper
	dec := fileencryptor.NewGobReader(buf)
	var output [][]byte
	for {
		var m []byte
		err := dec.Read(&m)

		if err == io.EOF {
			break
		}

		if err != nil {
			t.Errorf("error decoding value: %v", err)
		}

		output = append(output, m)
	}

	// Verify that input and output match
	if !reflect.DeepEqual(input, output) {
		t.Errorf("expected %v, got %v", input, output)
	}
}

func TestWrapperWithFiles(t *testing.T) {
	// Create some sample data
	input := [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("foo"),
		[]byte("bar"),
		[]byte("baz"),
	}

	// Create temporary file for input
	inFile, err := ioutil.TempFile("", "input")
	if err != nil {
		t.Errorf("error creating input file: %v", err)
	}
	defer os.Remove(inFile.Name())
	defer inFile.Close()

	// Write input data to temporary file
	enc := fileencryptor.NewGobWriter(inFile)
	for _, m := range input {
		err := enc.Write(m)
		if err != nil {
			t.Errorf("error encoding value: %v", err)
		}
	}

	// Reopen input file for reading
	inFile, err = os.Open(inFile.Name())
	if err != nil {
		t.Errorf("error opening input file: %v", err)
	}

	// Create temporary file for output
	outFile, err := ioutil.TempFile("", "output")
	if err != nil {
		t.Errorf("error creating output file: %v", err)
	}
	defer os.Remove(outFile.Name())
	defer outFile.Close()

	// Read from input file and write to output file using wrappers
	dec := fileencryptor.NewGobReader(inFile)
	enc = fileencryptor.NewGobWriter(outFile)
	for {
		var m []byte
		err := dec.Read(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("error decoding value: %v", err)
		}
		err = enc.Write(m)
		if err != nil {
			t.Errorf("error encoding value: %v", err)
		}
	}

	// Reopen output file for reading
	outFile, err = os.Open(outFile.Name())
	if err != nil {
		t.Errorf("error opening output file: %v", err)
	}

	// Read output data from file
	var output [][]byte
	dec = fileencryptor.NewGobReader(outFile)
	for {
		var m []byte
		err := dec.Read(&m)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Errorf("error decoding value: %v", err)
		}
		output = append(output, m)
	}

	// Verify that input and output match
	if !reflect.DeepEqual(input, output) {
		t.Errorf("expected %v, got %v", input, output)
	}
}

func TestBinWrapper(t *testing.T) {
	// Create some sample data
	input := [][]byte{
		[]byte("hello"),
		[]byte("world"),
		[]byte("foo"),
		[]byte("bar"),
		[]byte("baz"),
	}

	// Encode data using EncoderWrapper
	buf := bytes.NewBuffer(nil)
	enc := fileencryptor.NewBinWriter(buf)
	for _, m := range input {
		err := enc.Write(m)
		if err != nil {
			t.Errorf("error encoding value: %v", err)
		}
	}

	// Decode data using DecoderWrapper
	dec := fileencryptor.NewBinReader(buf)
	var output [][]byte
	for {
		var m []byte
		err := dec.Read(&m)

		if err == io.EOF {
			break
		}

		if err != nil {
			t.Errorf("error decoding value: %v", err)
		}

		output = append(output, m)
	}

	// Verify that input and output match
	if !reflect.DeepEqual(input, output) {
		t.Errorf("expected %v, got %v", input, output)
	}
}
