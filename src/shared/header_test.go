package header

import (
	"bytes"
	"fmt"
	"testing"
)

func getRawFV1TestHeader() []byte {
	return []byte{
		204, 207, 17, 225, // CCCF11E
		64, 0, // 64MB Argon2
		4,                                                    // 4 Argon2 Iterations
		8,                                                    // 8 Argon2 Threads
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // 16 Byte Argon2 Header
	}
}

func TestNewFV1Header(t *testing.T) {
	header := NewFV1Header(64, 4, 8)

	if header.MagicNumber != 3776040908 {
		t.Errorf("Magic Number Failed: got %d, wanted %d", header.MagicNumber, 3776040908)
	}

	if header.ChunkSize != 64*1024*1024 {
		t.Errorf("Chunk Size Failed: got %d, wanted %d", header.ChunkSize, 64*1024*1024)
	}

	if header.KDFIterCount != 4 {
		t.Errorf("KDFIterCount Failed: got %d, wanted %d", header.KDFIterCount, 4)
	}

	if header.KDFThreadCount != 8 {
		t.Errorf("KDFThreadCount Failed: got %d, wanted %d", header.KDFThreadCount, 8)
	}

}

func TestParseFV1Header(t *testing.T) {
	testSalt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	rawHeaderTest := getRawFV1TestHeader()
	parsedHeader := ParseFV1Header(rawHeaderTest)

	if parsedHeader.MagicNumber != 3776040908 {
		t.Errorf("Magic Number Failed: got %d, wanted %d", parsedHeader.MagicNumber, 3776040908)
	}

	if parsedHeader.ChunkSize != 64*1024*1024 {
		t.Errorf("Chunk Size Failed: got %d, wanted %d", parsedHeader.ChunkSize, 64)
	}

	if parsedHeader.KDFIterCount != 4 {
		t.Errorf("KDFIterCount Failed: got %d, wanted %d", parsedHeader.KDFIterCount, 4)
	}

	if parsedHeader.KDFThreadCount != 8 {
		t.Errorf("KDFThreadCount Failed: got %d, wanted %d", parsedHeader.KDFThreadCount, 8)
	}

	if !bytes.Equal(parsedHeader.KDFSalt, testSalt) {
		t.Errorf("KDFSalt failed: salts are not equal")
		fmt.Printf("parsed   salt: %x\n", testSalt)
		fmt.Printf("expected salt: %x\n", parsedHeader.KDFSalt)
	}
}

func TestFV1HeaderToBytes(t *testing.T) {
	testSalt := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	header := NewFV1Header(64, 4, 8)
	header.KDFSalt = testSalt
	testBytes := getRawFV1TestHeader()
	headerBytes := FV1HeaderToBytes(header)

	if !bytes.Equal(headerBytes[0:4], testBytes[0:4]) {
		t.Errorf("Magic Number Failed: Mismatch")
		fmt.Printf("parsed   bytes: %x\n", headerBytes[0:4])
		fmt.Printf("expected bytes: %x\n", testBytes[0:4])
	}

	if !bytes.Equal(headerBytes[4:6], testBytes[4:6]) {
		t.Errorf("KDFMemUsage Failed: Mismatch")
		fmt.Printf("parsed   bytes: %x\n", headerBytes[4:6])
		fmt.Printf("expected bytes: %x\n", testBytes[4:6])
	}

	if headerBytes[6] != testBytes[6] {
		t.Errorf("KDFIterCount Failed: Mismatch")
		fmt.Printf("parsed   bytes: %x\n", headerBytes[6])
		fmt.Printf("expected bytes: %x\n", testBytes[6])
	}

	if headerBytes[7] != testBytes[7] {
		t.Errorf("KDFThreadCount Failed: Mismatch")
		fmt.Printf("parsed   bytes: %x\n", headerBytes[7])
		fmt.Printf("expected bytes: %x\n", testBytes[7])
	}

	if !bytes.Equal(headerBytes[8:24], testBytes[8:24]) {
		t.Errorf("KDFSalt Failed: Mismatch")
		fmt.Printf("parsed   bytes: %x\n", headerBytes[8:24])
		fmt.Printf("expected bytes: %x\n", testBytes[8:24])
	}
}
