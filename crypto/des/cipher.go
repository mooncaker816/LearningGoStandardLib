// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

import (
	"crypto/cipher"
	"encoding/binary"
	"strconv"
)

/* [Min]
DES 的加解密流程完全一致，都需要进行16轮次，唯一的不同是子秘钥的选取，
加密时，子秘钥索引与轮次一致，解密时，子秘钥索引=15-轮次
*/

// The DES block size in bytes.
// [Min] DES 分块大小 8 字节 64 bits
const BlockSize = 8

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/des: invalid key size " + strconv.Itoa(int(k))
}

// desCipher is an instance of DES encryption.
// [Min] DES 加密实例，内含16轮加密用的子秘钥，
// [Min] 子秘钥包含48位有效位，分成8组，每组6-bit，
// [Min] 分配到uint64的8个字节的低6位中，分配顺序参见unpack函数
type desCipher struct {
	subkeys [16]uint64
}

// NewCipher creates and returns a new cipher.Block.
// [Min] 新建desCipher，并根据key准备好16轮子key
func NewCipher(key []byte) (cipher.Block, error) {
	// [Min] key的大小必须为8字节，64 bits，其中每个字节的最后一位是奇校验位，所以实际上是56bits的秘钥
	if len(key) != 8 {
		return nil, KeySizeError(len(key))
	}

	c := new(desCipher)
	// [Min] 生成16个子秘钥
	c.generateSubkeys(key)
	return c, nil
}

// [Min] DES加密block大小64位，8字节
func (c *desCipher) BlockSize() int { return BlockSize }

// [Min] DES加密
func (c *desCipher) Encrypt(dst, src []byte) { encryptBlock(c.subkeys[:], dst, src) }

// [Min] DES解密
func (c *desCipher) Decrypt(dst, src []byte) { decryptBlock(c.subkeys[:], dst, src) }

// A tripleDESCipher is an instance of TripleDES encryption.
// [Min] 3DES实例，包含三个desCipher
type tripleDESCipher struct {
	cipher1, cipher2, cipher3 desCipher
}

// NewTripleDESCipher creates and returns a new cipher.Block.
// [Min] 新建3DES实例，key必须是8*3=24字节
func NewTripleDESCipher(key []byte) (cipher.Block, error) {
	if len(key) != 24 {
		return nil, KeySizeError(len(key))
	}

	c := new(tripleDESCipher)
	// [Min] 分配三层DES子秘钥
	c.cipher1.generateSubkeys(key[:8])
	c.cipher2.generateSubkeys(key[8:16])
	c.cipher3.generateSubkeys(key[16:])
	return c, nil
}

func (c *tripleDESCipher) BlockSize() int { return BlockSize }

// [Min] 3DES加密，单独cipher的加解密与普通DES一致
func (c *tripleDESCipher) Encrypt(dst, src []byte) {
	b := binary.BigEndian.Uint64(src)
	b = permuteInitialBlock(b)
	left, right := uint32(b>>32), uint32(b)

	left = (left << 1) | (left >> 31)
	right = (right << 1) | (right >> 31)

	// [Min] cipher1 先16轮加密
	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher1.subkeys[2*i], c.cipher1.subkeys[2*i+1])
	}
	// [Min] cipher2 进行16轮解密，注意首轮要交换左右
	for i := 0; i < 8; i++ {
		right, left = feistel(right, left, c.cipher2.subkeys[15-2*i], c.cipher2.subkeys[15-(2*i+1)])
	}
	// [Min] cipher3 再进行16轮加密，注意首轮要交换左右
	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher3.subkeys[2*i], c.cipher3.subkeys[2*i+1])
	}

	left = (left << 31) | (left >> 1)
	right = (right << 31) | (right >> 1)

	preOutput := (uint64(right) << 32) | uint64(left)
	binary.BigEndian.PutUint64(dst, permuteFinalBlock(preOutput))
}

// [Min] 3DES解密，单独cipher的加解密与普通DES一致
func (c *tripleDESCipher) Decrypt(dst, src []byte) {
	b := binary.BigEndian.Uint64(src)
	b = permuteInitialBlock(b)
	left, right := uint32(b>>32), uint32(b)

	left = (left << 1) | (left >> 31)
	right = (right << 1) | (right >> 31)

	// [Min] cipher3先进行16轮解密
	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher3.subkeys[15-2*i], c.cipher3.subkeys[15-(2*i+1)])
	}
	// [Min] cipher2进行16轮加密，注意首轮交换左右
	for i := 0; i < 8; i++ {
		right, left = feistel(right, left, c.cipher2.subkeys[2*i], c.cipher2.subkeys[2*i+1])
	}
	// [Min] cipher1进行16轮解密，注意首轮交换左右
	for i := 0; i < 8; i++ {
		left, right = feistel(left, right, c.cipher1.subkeys[15-2*i], c.cipher1.subkeys[15-(2*i+1)])
	}

	left = (left << 31) | (left >> 1)
	right = (right << 31) | (right >> 1)

	preOutput := (uint64(right) << 32) | uint64(left)
	binary.BigEndian.PutUint64(dst, permuteFinalBlock(preOutput))
}
