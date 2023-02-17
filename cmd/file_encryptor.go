package main

import (
	"flag"
	"io/ioutil"
	"os"

	"github.com/roman808080/fileencryptor"
)

func main() {
	keyPath := flag.String("key", "", "A path to a a private key. If specified the utility works in the decryption mode.")
	peerCertPath := flag.String("peer-cert", "", "A path to a peer certificate. If specified the utility works in the encryption mode.")
	input := flag.String("input", "", "An input path from where a file will be read")
	output := flag.String("output", "", "An output path where a file will be saved.")

	flag.Parse()

	inputStream, err := os.Open(*input)
	if err != nil {
		panic(err)
	}

	outputStream, err := os.Create(*output)
	if err != nil {
		panic(err)
	}

	if *keyPath != "" {
		keyBytes, err := ioutil.ReadFile(*keyPath)
		if err != nil {
			panic(err)
		}

		rsaKey, err := fileencryptor.LoadPrivateRSAKey(keyBytes)
		if err != nil {
			panic(err)
		}

		fileDecryptror := fileencryptor.NewDecryptor(inputStream, outputStream, rsaKey, 1024)
		err = fileDecryptror.Decrypt()
		if err != nil {
			panic(err)
		}
	}

	if *peerCertPath != "" {
		certBytes, err := ioutil.ReadFile(*peerCertPath)
		if err != nil {
			panic(err)
		}

		rsaPublicKey, err := fileencryptor.LoadPublicKeyFromRSACert(certBytes)
		if err != nil {
			panic(err)
		}

		enc := fileencryptor.NewEncryptor(inputStream, outputStream, rsaPublicKey, 1024)
		err = enc.Encrypt()
		if err != nil {
			panic(err)
		}
	}
}
