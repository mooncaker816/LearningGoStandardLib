// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file defines the ShakeHash interface, and provides
// functions for creating SHAKE instances, as well as utility
// functions for hashing bytes to arbitrary-length output.

import (
	"io"
)

// ShakeHash defines the interface to hash functions that
// support arbitrary-length output.
type ShakeHash interface {
	// Write absorbs more data into the hash's state. It panics if input is
	// written to it after output has been read from it.
	// [Min] 用来吸收输入
	io.Writer

	// Read reads more output from the hash; reading affects the hash's
	// state. (ShakeHash.Read is thus very different from Hash.Sum)
	// It never returns an error.
	// [Min] 用来挤压输出
	io.Reader

	// Clone returns a copy of the ShakeHash in its current state.
	Clone() ShakeHash

	// Reset resets the ShakeHash to its initial state.
	Reset()
}

func (d *state) Clone() ShakeHash {
	return d.clone()
}

// NewShake128 creates a new SHAKE128 variable-output-length ShakeHash.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
// [Min] Shake-128 rate 168 字节
func NewShake128() ShakeHash {
	if h := newShake128Asm(); h != nil {
		return h
	}
	return &state{rate: 168, dsbyte: 0x1f}
}

// NewShake256 creates a new SHAKE256 variable-output-length ShakeHash.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
// [Min] Shake-256 rate 136 字节
func NewShake256() ShakeHash {
	if h := newShake256Asm(); h != nil {
		return h
	}
	return &state{rate: 136, dsbyte: 0x1f}
}

// ShakeSum128 writes an arbitrary-length digest of data into hash.
// [Min] 根据给定hash的长度，返回对应长度的Shake128
func ShakeSum128(hash, data []byte) {
	h := NewShake128()
	h.Write(data)
	h.Read(hash)
}

// ShakeSum256 writes an arbitrary-length digest of data into hash.
// [Min] 根据给定hash的长度，返回对应长度的Shake256
// [Min] 需注意的是，相同数据同等长度的Shake256和SHA3-256不同，因为他们的填充首字节不同
func ShakeSum256(hash, data []byte) {
	h := NewShake256()
	h.Write(data)
	h.Read(hash)
}
