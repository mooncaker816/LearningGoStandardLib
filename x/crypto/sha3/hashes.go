// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file provides functions for creating instances of the SHA-3
// and SHAKE hash functions, as well as utility functions for hashing
// bytes.

import (
	"hash"
)

// New224 creates a new SHA3-224 hash.
// Its generic security strength is 224 bits against preimage attacks,
// and 112 bits against collision attacks.
// [Min] SHA3-224 分组大小 144 字节，输出大小 28 字节
func New224() hash.Hash {
	if h := new224Asm(); h != nil {
		return h
	}
	return &state{rate: 144, outputLen: 28, dsbyte: 0x06}
}

// New256 creates a new SHA3-256 hash.
// Its generic security strength is 256 bits against preimage attacks,
// and 128 bits against collision attacks.
// [Min] SHA3-256 分组大小 136 字节，输出大小 32 字节
func New256() hash.Hash {
	if h := new256Asm(); h != nil {
		return h
	}
	return &state{rate: 136, outputLen: 32, dsbyte: 0x06}
}

// New384 creates a new SHA3-384 hash.
// Its generic security strength is 384 bits against preimage attacks,
// and 192 bits against collision attacks.
// [Min] SHA3-384 分组大小 104 字节，输出大小 48 字节
func New384() hash.Hash {
	if h := new384Asm(); h != nil {
		return h
	}
	return &state{rate: 104, outputLen: 48, dsbyte: 0x06}
}

// New512 creates a new SHA3-512 hash.
// Its generic security strength is 512 bits against preimage attacks,
// and 256 bits against collision attacks.
// [Min] SHA3-512 分组大小 72 字节，输出大小 64 字节
func New512() hash.Hash {
	if h := new512Asm(); h != nil {
		return h
	}
	return &state{rate: 72, outputLen: 64, dsbyte: 0x06}
}

// NewLegacyKeccak256 creates a new Keccak-256 hash.
//
// Only use this function if you require compatibility with an existing cryptosystem
// that uses non-standard padding. All other users should use New256 instead.
func NewLegacyKeccak256() hash.Hash { return &state{rate: 136, outputLen: 32, dsbyte: 0x01} }

// Sum224 returns the SHA3-224 digest of the data.
// [Min] 计算SHA3-224
func Sum224(data []byte) (digest [28]byte) {
	h := New224()
	h.Write(data)
	h.Sum(digest[:0])
	return
}

// Sum256 returns the SHA3-256 digest of the data.
// [Min] 计算SHA3-256
func Sum256(data []byte) (digest [32]byte) {
	h := New256()
	h.Write(data)
	h.Sum(digest[:0])
	return
}

// Sum384 returns the SHA3-384 digest of the data.
// [Min] 计算SHA3-384
func Sum384(data []byte) (digest [48]byte) {
	h := New384()
	h.Write(data)
	h.Sum(digest[:0])
	return
}

// Sum512 returns the SHA3-512 digest of the data.
// [Min] 计算SHA3-512
func Sum512(data []byte) (digest [64]byte) {
	h := New512()
	h.Write(data)
	h.Sum(digest[:0])
	return
}
