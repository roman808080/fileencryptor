package fileencryptor

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type SymmetricEncryptor struct {
	in        io.Reader
	out       io.Writer
	blockSize int
	key       [32]byte
}

func NewSymmetricEncryptor(in io.Reader, out io.Writer, blockSize int) (*SymmetricEncryptor, error) {
	var key [32]byte
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, err
	}

	return &SymmetricEncryptor{
		in:        in,
		out:       out,
		blockSize: blockSize,
		key:       key,
	}, nil
}

func (f *SymmetricEncryptor) Encrypt() error {
	aead, err := chacha20poly1305.New(f.key[:])
	if err != nil {
		return err
	}

	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}

	if err := binary.Write(f.out, binary.LittleEndian, nonce); err != nil {
		return err
	}

	buf := make([]byte, f.blockSize)
	for {
		n, err := f.in.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		encrypted := aead.Seal(nil, nonce[:], buf[:n], nil)

		if _, err := f.out.Write(encrypted); err != nil {
			return err
		}

		binary.LittleEndian.PutUint64(nonce[4:], binary.LittleEndian.Uint64(nonce[4:])+1)
	}

	return nil
}

func (f *SymmetricEncryptor) GetKey() [32]byte {
	return f.key
}
