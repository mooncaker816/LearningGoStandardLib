// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Cipher block chaining (CBC) mode.

// CBC provides confidentiality by xoring (chaining) each plaintext block
// with the previous ciphertext block before applying the block cipher.

// See NIST SP 800-38A, pp 10-11

package cipher

// [Min] 分组密码之CBC模式，模式用来明确各个分组的迭代方式
// [Min] 更像是在Block外部套一层迭代方式，以及用于驱动这个迭代方式的初始向量
type cbc struct {
	b         Block  // [Min] 承载了具体的对单一分组的加解密函数，以及秘钥
	blockSize int    // [Min] 分组大小
	iv        []byte // [Min] 初始向量
	tmp       []byte // [Min] 临时存储空间，长度为blockSize
}

// [Min] 根据初始向量和确定的算法实例，新建cbc实例
func newCBC(b Block, iv []byte) *cbc {
	return &cbc{
		b:         b,
		blockSize: b.BlockSize(),
		iv:        dup(iv),                     // [Min] 初始化向量的副本
		tmp:       make([]byte, b.BlockSize()), // [Min] 与分组大小相同
	}
}

// [Min] 分组密码加密
type cbcEncrypter cbc

// cbcEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of CBC encryption, like crypto/aes.
// NewCBCEncrypter will check for this interface and return the specific
// BlockMode if found.
type cbcEncAble interface {
	NewCBCEncrypter(iv []byte) BlockMode
}

// NewCBCEncrypter returns a BlockMode which encrypts in cipher block chaining
// mode, using the given Block. The length of iv must be the same as the
// Block's block size.
// [Min] 构造一个CBC分组加密模式，
// [Min] 如果 block 本身实现了NewCBCEncrypter接口，直接调用即可，否则调用newCBC
func NewCBCEncrypter(b Block, iv []byte) BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewCBCEncrypter: IV length must equal block size")
	}
	if cbc, ok := b.(cbcEncAble); ok {
		return cbc.NewCBCEncrypter(iv)
	}
	return (*cbcEncrypter)(newCBC(b, iv))
}

func (x *cbcEncrypter) BlockSize() int { return x.blockSize }

// [Min] 迭代分组，此处明文数据已经经过填充，大小恰好为分组大小的整数倍
func (x *cbcEncrypter) CryptBlocks(dst, src []byte) {
	// [Min] 明文数据的大小必须是分组大小的整数倍
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	// [Min] 输出容量必须比明文长
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}

	iv := x.iv

	// [Min] 循环处理每一组明文
	for len(src) > 0 {
		// Write the xor to dst, then encrypt in place.
		// [Min] 首先异或前一组密文（初始向量）和分组明文
		xorBytes(dst[:x.blockSize], src[:x.blockSize], iv)
		// [Min] 调用Block的Encrypt方法对该组明文进行加密
		x.b.Encrypt(dst[:x.blockSize], dst[:x.blockSize])

		// Move to the next block with this block as the next iv.
		// [Min] 将该组密文作为下一组明文的异或对象
		iv = dst[:x.blockSize]
		// [Min] 调整下一组明文，密文位置
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}

	// Save the iv for the next CryptBlocks call.
	// [Min] 保存当前最后一组密文作为下一次调用的初始向量
	copy(x.iv, iv)
}

// [Min] 设置初始向量
func (x *cbcEncrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}

// [Min] 分组密码解密
type cbcDecrypter cbc

// cbcDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of CBC decryption, like crypto/aes.
// NewCBCDecrypter will check for this interface and return the specific
// BlockMode if found.
type cbcDecAble interface {
	NewCBCDecrypter(iv []byte) BlockMode
}

// NewCBCDecrypter returns a BlockMode which decrypts in cipher block chaining
// mode, using the given Block. The length of iv must be the same as the
// Block's block size and must match the iv used to encrypt the data.
func NewCBCDecrypter(b Block, iv []byte) BlockMode {
	if len(iv) != b.BlockSize() {
		panic("cipher.NewCBCDecrypter: IV length must equal block size")
	}
	if cbc, ok := b.(cbcDecAble); ok {
		return cbc.NewCBCDecrypter(iv)
	}
	return (*cbcDecrypter)(newCBC(b, iv))
}

func (x *cbcDecrypter) BlockSize() int { return x.blockSize }

func (x *cbcDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if len(src) == 0 {
		return
	}

	// [Min] 从最后一个分组开始处理，先解密，再异或前一组密文，得到该组的明文
	// For each block, we need to xor the decrypted data with the previous block's ciphertext (the iv).
	// To avoid making a copy each time, we loop over the blocks BACKWARDS.
	end := len(src)
	start := end - x.blockSize
	prev := start - x.blockSize

	// Copy the last block of ciphertext in preparation as the new iv.
	// [Min] 保持最后一组密文作为最后返回时的初始向量
	copy(x.tmp, src[start:end])

	// Loop over all but the first block.
	// [Min] 从后往前循环处理每一个分组
	for start > 0 {
		// [Min] 先解密当前分组的密文
		x.b.Decrypt(dst[start:end], src[start:end])
		// [Min] 再与前一分组的密文异或得到明文
		xorBytes(dst[start:end], dst[start:end], src[prev:start])

		// [Min] 调整前一个分组的位置
		end = start
		start = prev
		prev -= x.blockSize
	}

	// The first block is special because it uses the saved iv.
	// [Min] 解密第一分组
	x.b.Decrypt(dst[start:end], src[start:end])
	// [Min] 对于第一个分组，没有了前一个分组的密文，其异或的向量为初始向量
	xorBytes(dst[start:end], dst[start:end], x.iv)

	// Set the new iv to the first block we copied earlier.
	// [Min] 设置初始向量为最后一个分组的密文
	x.iv, x.tmp = x.tmp, x.iv
}

// [Min] 设置初始向量
func (x *cbcDecrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}
