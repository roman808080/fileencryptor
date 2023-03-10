package fileencryptor

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type SymmetricDecryptor struct {
	in        BinaryReader
	out       io.Writer
	blockSize int
	key       [chacha20poly1305.KeySize]byte
}

func NewSymmetricDecryptor(in BinaryReader, out io.Writer, blockSize int, key [chacha20poly1305.KeySize]byte) (*SymmetricDecryptor, error) {
	return &SymmetricDecryptor{
		in:        in,
		out:       out,
		blockSize: blockSize,
		key:       key,
	}, nil
}

func (f *SymmetricDecryptor) Decrypt() error {
	aead, err := chacha20poly1305.New(f.key[:])
	if err != nil {
		return err
	}

	var nonce [chacha20poly1305.NonceSize]byte
	if err := f.in.Read(&nonce); err != nil {
		return err
	}

	for {
		var buf []byte
		err := f.in.Read(&buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		plaintext, err := aead.Open(nil, nonce[:], buf, nil)
		if err != nil {
			return err
		}

		// add gob here
		if _, err := f.out.Write(plaintext); err != nil {
			return err
		}

		// TODO: Fix this one
		binary.LittleEndian.PutUint64(nonce[4:], binary.LittleEndian.Uint64(nonce[4:])+1)
	}

	return nil
}
