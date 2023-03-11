package header

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	FV1Ext       = ".ccc" // File Version 1 Extension
	FV1HeaderLen = 24
	FV1Magic     = 3776040908 // Hex: CCCF11E1
	FV2Magic     = 3792818124 // HEX: CCCF11E2

	Memory     = 64
	Iterations = 4
	Threads    = 4
)

type FV1Header struct {
	MagicNumber    uint32
	KDFMemUsage    uint16
	KDFIterCount   byte
	KDFThreadCount byte
	KDFSalt        []byte
	ChunkSize      uint64
}

func NewFV1Header(memory uint16, iterations byte, threads byte) FV1Header {
	if memory == 0 {
		memory = Memory
	}
	if iterations == 0 {
		iterations = Iterations
	}
	if threads == 0 {
		threads = Threads
	}

	header := FV1Header{
		MagicNumber:    FV1Magic,
		KDFSalt:        make([]byte, 16),
		KDFMemUsage:    memory,
		KDFIterCount:   iterations,
		KDFThreadCount: threads,
	}

	header.ChunkSize = uint64(header.KDFMemUsage) * 1024 * 1024

	_, err := rand.Read(header.KDFSalt)
	if err != nil {
		panic(err)
	}

	return header
}

func ParseFV1Header(data []byte) FV1Header {
	header := NewFV1Header(0, 0, 0)
	header.MagicNumber = binary.LittleEndian.Uint32(data[0:4])
	header.KDFMemUsage = binary.LittleEndian.Uint16(data[4:6])
	header.ChunkSize = uint64(binary.LittleEndian.Uint16(data[4:6])) * 1024 * 1024
	header.KDFIterCount = data[6]
	header.KDFThreadCount = data[7]
	copy(header.KDFSalt, data[8:24])
	return header
}

func FV1HeaderToBytes(header FV1Header) []byte {
	data := make([]byte, FV1HeaderLen)
	binary.LittleEndian.PutUint32(data[0:4], header.MagicNumber)
	binary.LittleEndian.PutUint16(data[4:6], header.KDFMemUsage)
	data[6] = header.KDFIterCount
	data[7] = header.KDFThreadCount
	copy(data[8:24], header.KDFSalt)
	return data
}
