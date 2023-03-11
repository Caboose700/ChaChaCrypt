package main

import (
	header "ChaChaCrypt/src/shared"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
	"io"
	"os"
	"runtime"
	"syscall"
)

func wipe(b []byte) {
	l := len(b)
	for i := 0; i < l; i++ {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func main() {
	aLen := len(os.Args[1:])

	if aLen == 0 {
		fmt.Println("no arguments provided")
		return
	}

	fmt.Println("Decrypting the following files:\n")
	for _, file := range os.Args[1:] {
		fmt.Println(file)
	}

	// Prompt for Passphrase
	fmt.Println("\nPlease enter the decryption passphrase:")
	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	defer wipe(passphrase)
	if err != nil {
		panic(err)
	}

	for _, file := range os.Args[1:] {
		err = decrypt(file, passphrase)
		if err != nil {
			fmt.Printf("Error decrypting %s\n", file)
			fmt.Println(err)
			continue
		}

		fmt.Printf("Finished decrypting %s\n", file)
	}

	fmt.Printf("\nDone")
}

func decrypt(inputPath string, passphrase []byte) error {
	// Open Files
	input, err := os.Open(inputPath)
	if err != nil {
		return errors.New(fmt.Sprintf("unable to open %s", inputPath))
	}

	outputPath := inputPath[:len(inputPath)-4]
	output, err := os.OpenFile(outputPath, os.O_CREATE, 0644)
	if err != nil {
		return errors.New(fmt.Sprintf("unable to open %s", outputPath))
	}

	// We're only calling close once, so no error handling required.
	defer func(input *os.File) {
		_ = input.Close()
	}(input)
	defer func(output *os.File) {
		_ = output.Close()
	}(output)

	// Read Header from File
	headerBuf := make([]byte, header.FV1HeaderLen)
	read, err := input.Read(headerBuf)
	if err != nil {
		panic(err)
	}
	if read != header.FV1HeaderLen {
		return errors.New(fmt.Sprintf("%s was not created by this program", inputPath))
	}

	// Parse Header
	cccHeader := header.ParseFV1Header(headerBuf)
	if cccHeader.MagicNumber != header.FV1Magic {
		return errors.New(fmt.Sprintf("%s was not created by this program", inputPath))
	}

	// Create XChaCha20-Poly1305 AEAD Construction
	key := argon2.IDKey(
		passphrase,
		cccHeader.KDFSalt,
		uint32(cccHeader.KDFIterCount),
		uint32(cccHeader.KDFMemUsage*1024),
		cccHeader.KDFThreadCount,
		chacha20poly1305.KeySize)
	defer wipe(key)

	// Error check not required, we use the actual KeySize.
	chacha, _ := chacha20poly1305.NewX(key)

	// Create Buffers
	backingBuf := make([]byte, 1+chacha20poly1305.NonceSizeX+cccHeader.ChunkSize+chacha20poly1305.Overhead)
	statusBuf := backingBuf[0:1]
	nonceBuf := backingBuf[1 : chacha20poly1305.NonceSizeX+1]
	dataBuf := backingBuf[chacha20poly1305.NonceSizeX+1:]

	// Seek past the cccHeader
	_, err = input.Seek(header.FV1HeaderLen, 0)
	if err != nil {
		return errors.New(fmt.Sprintf("unable to seek %s", inputPath))
	}

	for {
		// Read data from input file into buffer
		read, err = input.Read(backingBuf)
		if err != nil && err != io.EOF {
			return errors.New(fmt.Sprintf("unable to read from %s", inputPath))
		}
		if err == io.EOF {
			break
		}

		// Adjust data slice if this is the last chunk
		ciphertext := dataBuf
		if statusBuf[0] == 1 {
			ciphertext = backingBuf[chacha20poly1305.NonceSizeX+1 : read]
		}

		// Decrypt
		plaintext, err := chacha.Open(dataBuf[:0], nonceBuf, ciphertext, nil)
		if err != nil {
			return errors.New(fmt.Sprintf("unable to decrypt %s, wrong passphrase and/or file has been tampered with", inputPath))
		}

		// Write plaintext to file
		_, err = output.Write(plaintext)
		if err != nil {
			return errors.New(fmt.Sprintf("unable to write data to %s", outputPath))
		}
	}

	return nil
}
