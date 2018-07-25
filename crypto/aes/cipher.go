// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/cipher"
	"strconv"
)

/* [Min]
AES key 长度有三种规格，128-bit，192-bit，256-bit
AES block 大小为 128-bit
引入word的概念，一个word为4个字节，
Nk表示key以word为单位的大小，Nb表示block以word为单位的大小，Nr表示轮次数
		key length(Nk words) block size(Nb words) number of rounds
AES-128			4					4					10
AES-192			6					4					12
AES-256			8					4					14
*/

// The AES block size in bytes.
// [Min] AES block 大小16字节，128-bit
const BlockSize = 16

// A cipher is an instance of AES encryption using a particular key.
type aesCipher struct {
	enc []uint32
	dec []uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new cipher.Block.
// The key argument should be the AES key,
// either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256.
// [Min] 新建aesCipher实例，key可以是16，24，32字节三种规格
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	switch k {
	default:
		return nil, KeySizeError(k)
	case 16, 24, 32:
		break
	}
	// [Min] newCipher 会调用newCipherGeneric，来生成key
	return newCipher(key)
}

// newCipherGeneric creates and returns a new cipher.Block
// implemented in pure Go.
// [Min] 调用expandKeyGo生成子秘钥，将nk个word扩至nk*（nr+1）个word
func newCipherGeneric(key []byte) (cipher.Block, error) {
	// [Min] 扩充后的key的word个数
	n := len(key) + 28
	// [Min] uint32存一个word
	c := aesCipher{make([]uint32, n), make([]uint32, n)}
	expandKeyGo(key, c.enc, c.dec)
	return &c, nil
}

func (c *aesCipher) BlockSize() int { return BlockSize }

// [Min] AES 加密
func (c *aesCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	encryptBlockGo(c.enc, dst, src)
}

// [Min] AES 解密
func (c *aesCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("crypto/aes: input not full block")
	}
	if len(dst) < BlockSize {
		panic("crypto/aes: output not full block")
	}
	decryptBlockGo(c.dec, dst, src)
}
