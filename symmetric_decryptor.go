package fileencryptor

import (
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type SymmetricDecryptor struct {
	in        io.Reader
	out       io.Writer
	blockSize int
	key       [chacha20poly1305.KeySize]byte
}

func NewSymmetricDecryptor(in io.Reader, out io.Writer, blockSize int, key [chacha20poly1305.KeySize]byte) (*SymmetricDecryptor, error) {
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
	if err := binary.Read(f.in, binary.LittleEndian, &nonce); err != nil {
		return err
	}

	buf := make([]byte, f.blockSize+aead.Overhead())
	for {
		n, err := f.in.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		plaintext, err := aead.Open(nil, nonce[:], buf[:n], nil)
		if err != nil {
			return err
		}

		if _, err := f.out.Write(plaintext); err != nil {
			return err
		}

		binary.LittleEndian.PutUint64(nonce[4:], binary.LittleEndian.Uint64(nonce[4:])+1)
	}

	return nil
}
