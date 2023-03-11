package main

import (
	header "ChaChaCrypt/src/shared"
	"bytes"
	"crypto/rand"
	"testing"
)

func TestWipe(t *testing.T) {
	randomBytes := make([]byte, 32)
	zeroedBytes := make([]byte, 32)

	_, _ = rand.Read(randomBytes)

	if bytes.Equal(randomBytes, zeroedBytes) {
		t.Errorf("randomBytes and zeroedBytes are the same")
	}

	wipe(randomBytes)
	if !bytes.Equal(randomBytes, zeroedBytes) {
		t.Errorf("randomBytes and zeroedBytes should both be 32 byte arrays of zero")
	}
}

func TestParseArgs(t *testing.T) {
	argsEmpty := make([]string, 0)
	args1 := []string{"-t", "8"}
	args2 := []string{"-t", "8", "-m", "128"}
	args3 := []string{"C:\\Users\\Chase\\GolandProjects\\ChaChaCrypt\\bin\\ccc_encrypt.exe"}
	args4 := []string{"-m", "128", "-t", "6", "-i", "1", "C:\\Users\\Chase\\GolandProjects\\ChaChaCrypt\\bin\\ccc_encrypt.exe"}
	args5 := []string{"-m", "128128"}

	params, err := parseArgs(argsEmpty)
	if err == nil {
		t.Errorf("error should have been thrown, no arguments specified at all")
	}

	params, err = parseArgs(args1)
	if err == nil {
		t.Errorf("error should have been thrown, no file specified")
	}
	if params.threads != 8 {
		t.Errorf("params.threads (%d) does not match the input value (%d)", params.threads, 8)
	}

	params, err = parseArgs(args2)
	if err == nil {
		t.Errorf("error should have been thrown, no file specified")
	}

	params, err = parseArgs(args3)
	if err != nil {
		t.Errorf("%s", err)
	}

	if params.threads != header.Threads {
		t.Errorf("default value mismatch")
	}
	if params.iterations != header.Iterations {
		t.Errorf("default value mismatch")
	}
	if params.memory != header.Memory {
		t.Errorf("default value mismatch")
	}
	if len(params.files) != 1 {
		t.Errorf("failed recording files")
	}
	if params.files[0] != "C:\\Users\\Chase\\GolandProjects\\ChaChaCrypt\\bin\\ccc_encrypt.exe" {
		t.Errorf("wrong file")
	}

	params, err = parseArgs(args4)
	if err != nil {
		t.Errorf("%s", err)
	}

	if params.threads != 6 {
		t.Errorf("got %d threads, expected %d", params.threads, 6)
	}
	if params.memory != 128 {
		t.Errorf("got %d memory, expected %d", params.memory, 128)
	}
	if params.iterations != 1 {
		t.Errorf("got %d iterations, expected %d", params.iterations, 1)
	}
	if params.files[0] != "C:\\Users\\Chase\\GolandProjects\\ChaChaCrypt\\bin\\ccc_encrypt.exe" {
		t.Errorf("wrong file")
	}

	params, err = parseArgs(args5)
	if err == nil {
		t.Errorf("error should have been thrown, no file specified")
	}
	if params.memory != 65535 {
		t.Errorf("got %d memory, expected %d", params.memory, 65535)
	}
}
