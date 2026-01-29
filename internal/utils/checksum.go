package utils

import (
	"hash"

	"github.com/zeebo/blake3"
	"github.com/zeebo/xxh3"
)

func XXHash64(data []byte) uint64 {
	return xxh3.Hash(data)
}

func NewXXHash64() hash.Hash64 {
	return xxh3.New()
}

func Blake3(data []byte) []byte {
	h := blake3.New()
	h.Write(data)
	return h.Sum(nil)
}

func NewBlake3() hash.Hash {
	return blake3.New()
}
