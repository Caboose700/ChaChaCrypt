package main

import (
	header "ChaChaCrypt/src/shared"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
	"io"
	"os"
	"runtime"
	"strconv"
	"syscall"
)

func wipe(b []byte) {
	l := len(b)
	for i := 0; i < l; i++ {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

type Params struct {
	memory     uint16
	iterations byte
	threads    byte
	files      []string
}

func newParams() Params {
	return Params{
		memory:     header.Memory,
		iterations: header.Iterations,
		threads:    header.Threads,
		files:      make([]string, 0, 1),
	}
}

func parseArgs(args []string) (Params, error) {
	params := newParams()

	aLen := len(args)
	if aLen == 0 {
		return params, errors.New("no arguments provided")
	}

	for i := 0; i < aLen; i++ {
		if args[i] == "-m" {
			memory64, err := strconv.ParseUint(args[i+1], 10, 16)
			i++ // Skip next iteration

			if err != nil && errors.Is(err, strconv.ErrRange) {
				fmt.Printf("Notice: -m out of range, set to %d\n", memory64)
			} else if err != nil {
				fmt.Printf("Error: -m invalid syntax, using defaults\n")
				continue
			}

			params.memory = uint16(memory64)
			continue
		}
		if args[i] == "-i" {
			iterations64, err := strconv.ParseUint(args[i+1], 10, 8)
			i++ // Skip next iteration
			if err != nil && errors.Is(err, strconv.ErrRange) {
				fmt.Printf("Notice: -i out of range, set to %d\n", iterations64)
			} else if err != nil {
				fmt.Printf("Error: -i invalid syntax, using defaults\n")
				continue
			}

			params.iterations = byte(iterations64)
			continue
		}
		if args[i] == "-t" {
			threads64, err := strconv.ParseUint(args[i+1], 10, 8)
			i++ // Skip next iteration
			if err != nil && errors.Is(err, strconv.ErrRange) {
				fmt.Printf("Notice: -t out of range, set to %d\n", threads64)
			} else if err != nil {
				fmt.Printf("Error: -t invalid syntax, using defaults\n")
				continue
			}

			params.threads = byte(threads64)
			continue
		}

		params.files = append(params.files, args[i])
	}

	if len(params.files) == 0 {
		return params, errors.New("No files selected")
	}

	return params, nil
}

func getPassphrase() ([]byte, error) {
	fmt.Println("\nPlease enter a encryption passphrase:")
	passphrase, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		wipe(passphrase)
		return nil, err
	}

	fmt.Println("Please verify the encryption passphrase:")
	passphrase2, err := term.ReadPassword(int(syscall.Stdin))
	defer wipe(passphrase2)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(passphrase, passphrase2) {
		wipe(passphrase)
		return nil, errors.New("The provided passphrases do not match")
	}

	return passphrase, nil
}

func main() {
	// Parse Arguments
	params, err := parseArgs(os.Args[1:])
	if err != nil {
		panic(err)
	}

	// Print Information
	fmt.Println("Using XChaCha20-Poly1305 with Argon2id for key derivation.")
	fmt.Printf("Argon2id Memory Usage: %d MiB\n", params.memory)
	fmt.Printf("Argon2id Iterations: %d\n", params.iterations)
	fmt.Printf("Argon2id Threads: %d\n", params.threads)
	fmt.Printf("\nEncrypting the following files:\n\n")
	for _, file := range params.files {
		fmt.Println(file)
	}

	// Prompt for Passphrase
	passphrase, err := getPassphrase()
	defer wipe(passphrase)
	if err != nil {
		panic(err)
	}

	// Create Data Buffer
	buffer := make([]byte, 1+chacha20poly1305.NonceSizeX+(uint64(params.memory)*1024*1024)+chacha20poly1305.Overhead)

	fmt.Printf("\n")
	for _, file := range params.files {
		err = encrypt(file, passphrase, params.memory, params.iterations, params.threads, buffer)
		if err != nil {
			fmt.Printf("Error encrypting %s\n", file)
			fmt.Println(err)
			continue
		}

		fmt.Printf("Finished encrypting %s\n", file)
	}
	fmt.Println("\nDone")
}

func encrypt(inputPath string, passphrase []byte, memory uint16, iterations byte, threads byte, buffer []byte) error {
	// Open Files
	input, err := os.Open(inputPath)
	if err != nil {
		return errors.New(fmt.Sprintf("unable to open %s", inputPath))
	}

	outputPath := inputPath + header.FV1Ext
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

	// Create Header
	cccHeader := header.NewFV1Header(memory, iterations, threads)

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

	// Create Buffer Slices
	statusBuf := buffer[0:1]
	nonceBuf := buffer[1 : chacha20poly1305.NonceSizeX+1]
	dataBuf := buffer[chacha20poly1305.NonceSizeX+1:]

	// Write Header
	_, err = output.Write(header.FV1HeaderToBytes(cccHeader))
	if err != nil {
		return errors.New(fmt.Sprintf("unable to write header to %s", outputPath))
	}

	for {
		// Read data from input file into buffer
		read, err := input.Read(dataBuf[:cccHeader.ChunkSize])
		if err != nil && err != io.EOF {
			return errors.New(fmt.Sprintf("unable to read from %s", inputPath))
		}
		if err == io.EOF {
			break
		}

		_, err = rand.Read(nonceBuf)
		if err != nil {
			return errors.New("unable to retrieve random bytes for nonce")
		}

		ciphertext := chacha.Seal(dataBuf[:0], nonceBuf, dataBuf[:read], nil)

		// If this is the last chunk, this byte is 1, otherwise 0.
		if uint64(read) != cccHeader.ChunkSize {
			statusBuf[0] = 1
		}

		// Write chunk status byte to file
		_, err = output.Write(statusBuf)
		if err != nil {
			return errors.New(fmt.Sprintf("unable to write data to %s", outputPath))
		}

		// Write the chunk nonce key to file
		_, err = output.Write(nonceBuf)
		if err != nil {
			return errors.New(fmt.Sprintf("unable to write data to %s", outputPath))
		}

		// Write ciphertext to file
		_, err = output.Write(ciphertext)
		if err != nil {
			return errors.New(fmt.Sprintf("unable to write data to %s", outputPath))
		}
	}

	return nil
}
