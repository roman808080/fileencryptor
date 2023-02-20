package fileencryptor

import (
	"encoding/binary"
	"encoding/gob"
	"io"
)

// BinaryReader interface
type BinaryReader interface {
	Read(destination any) error
}

// GobReader
type GobReader struct {
	dec *gob.Decoder
}

func NewGobReader(r io.Reader) *GobReader {
	return &GobReader{dec: gob.NewDecoder(r)}
}

func (reader *GobReader) Read(destination any) error {
	return reader.dec.Decode(destination)
}

// BinaryReader
type BinReader struct {
	reader io.Reader
}

func NewBinReader(r io.Reader) *BinReader {
	return &BinReader{reader: r}
}

func (bin *BinReader) Read(destination any) error {
	bytes, ok := destination.(*[]byte)

	if ok {
		var size uint32
		err := binary.Read(bin.reader, binary.LittleEndian, &size)
		if err != nil {
			return err
		}

		*bytes = make([]byte, size)
		err = binary.Read(bin.reader, binary.LittleEndian, bytes)
		if err != nil {
			return err
		}

		return nil
	}

	return binary.Read(bin.reader, binary.LittleEndian, destination)
}

// BinaryWriter interface
type BinaryWriter interface {
	Write(source any) error
}

// GobWriter
type GobWriter struct {
	enc *gob.Encoder
}

func NewGobWriter(w io.Writer) *GobWriter {
	return &GobWriter{enc: gob.NewEncoder(w)}
}

func (e *GobWriter) Write(source any) error {
	return e.enc.Encode(source)
}

// BinWriter
type BinWriter struct {
	writer io.Writer
}

func NewBinWriter(w io.Writer) *BinWriter {
	return &BinWriter{writer: w}
}

func (e *BinWriter) Write(source any) error {
	bytes, ok := source.([]byte)
	if ok {

		size := len(bytes)
		err := binary.Write(e.writer, binary.LittleEndian, uint32(size))
		if err != nil {
			return err
		}
	}

	return binary.Write(e.writer, binary.LittleEndian, source)
}
