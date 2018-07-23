// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"crypto/subtle"
	"errors"
)

// AEAD is a cipher mode providing authenticated encryption with associated
// data. For a description of the methodology, see
//	https://en.wikipedia.org/wiki/Authenticated_encryption
type AEAD interface {
	// NonceSize returns the size of the nonce that must be passed to Seal
	// and Open.
	NonceSize() int

	// Overhead returns the maximum difference between the lengths of a
	// plaintext and its ciphertext.
	Overhead() int

	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	//
	// The plaintext and dst must overlap exactly or not at all. To reuse
	// plaintext's storage for the encrypted output, use plaintext[:0] as dst.
	Seal(dst, nonce, plaintext, additionalData []byte) []byte

	// Open decrypts and authenticates ciphertext, authenticates the
	// additional data and, if successful, appends the resulting plaintext
	// to dst, returning the updated slice. The nonce must be NonceSize()
	// bytes long and both it and the additional data must match the
	// value passed to Seal.
	//
	// The ciphertext and dst must overlap exactly or not at all. To reuse
	// ciphertext's storage for the decrypted output, use ciphertext[:0] as dst.
	//
	// Even if the function fails, the contents of dst, up to its capacity,
	// may be overwritten.
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// gcmAble is an interface implemented by ciphers that have a specific optimized
// implementation of GCM, like crypto/aes. NewGCM will check for this interface
// and return the specific AEAD if found.
type gcmAble interface {
	NewGCM(int) (AEAD, error)
}

// gcmFieldElement represents a value in GF(2¹²⁸). In order to reflect the GCM
// standard and make getUint64 suitable for marshaling these values, the bits
// are stored backwards. For example:
//   the coefficient of x⁰ can be obtained by v.low >> 63.
//   the coefficient of x⁶³ can be obtained by v.low & 1.
//   the coefficient of x⁶⁴ can be obtained by v.high >> 63.
//   the coefficient of x¹²⁷ can be obtained by v.high & 1.
// [Min] 一个128比特位的值，以倒序的方式存储，分成low和high两部分，左边为low，右边为high
type gcmFieldElement struct {
	low, high uint64
}

// gcm represents a Galois Counter Mode with a specific key. See
// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
type gcm struct {
	cipher    Block
	nonceSize int // [Min] 随机数字节长度，12位标准长度
	// productTable contains the first sixteen powers of the key, H.
	// However, they are in bit reversed order. See NewGCMWithNonceSize.
	productTable [16]gcmFieldElement
}

// NewGCM returns the given 128-bit, block cipher wrapped in Galois Counter Mode
// with the standard nonce length.
//
// In general, the GHASH operation performed by this implementation of GCM is not constant-time.
// An exception is when the underlying Block was created by aes.NewCipher
// on systems with hardware support for AES. See the crypto/aes package documentation for details.
func NewGCM(cipher Block) (AEAD, error) {
	return NewGCMWithNonceSize(cipher, gcmStandardNonceSize)
}

// NewGCMWithNonceSize returns the given 128-bit, block cipher wrapped in Galois
// Counter Mode, which accepts nonces of the given length.
//
// Only use this function if you require compatibility with an existing
// cryptosystem that uses non-standard nonce lengths. All other users should use
// NewGCM, which is faster and more resistant to misuse.
func NewGCMWithNonceSize(cipher Block, size int) (AEAD, error) {
	if cipher, ok := cipher.(gcmAble); ok {
		return cipher.NewGCM(size)
	}

	if cipher.BlockSize() != gcmBlockSize {
		return nil, errors.New("cipher: NewGCM requires 128-bit block cipher")
	}

	var key [gcmBlockSize]byte
	// [Min] 计算H，对128位0加密即为H，此处为标记为key
	cipher.Encrypt(key[:], key[:])

	g := &gcm{cipher: cipher, nonceSize: size}

	// We precompute 16 multiples of |key|. However, when we do lookups
	// into this table we'll be using bits from a field element and
	// therefore the bits will be in the reverse order. So normally one
	// would expect, say, 4*key to be in index 4 of the table but due to
	// this bit ordering it will actually be in index 0010 (base 2) = 2.
	// [Min] 将key对应的值存入gcmFieldElement中，构造productTable，一共16个元素
	// [Min] 索引以后4位比特倒序对应的值存储，值是该索引正序值 * key
	// [Min] 相当于 0 -> 0000 -> 0000 -> 0   0 * key
	// [Min] 1 -> 0001 -> 1000 -> 8  * key
	// [Min] 2 -> 0010 -> 0100 -> 4  * key
	// [Min] 3 -> 0011 -> 1100 -> 12 * key
	// [Min] 4 -> 0100 -> 0010 -> 2  * key
	// [Min] 5 -> 0101 -> 1010 -> 10 * key
	// [Min] 6 -> 0110 -> 0110 -> 6  * key
	// [Min] 7 -> 0111 -> 1110 -> 14 * key
	// [Min] 8 -> 1000 -> 0001 -> 1  * key
	// [Min] 9 -> 1001 -> 1001 -> 9  * key
	// [Min] 10 -> 1010 -> 0101 -> 5 * key
	// [Min] 11 -> 1011 -> 1101 -> 13 * key
	// [Min] 12 -> 1100 -> 0011 -> 3  * key
	// [Min] 13 -> 1101 -> 1011 -> 11 * key
	// [Min] 14 -> 1110 -> 0111 -> 7  * key
	// [Min] 15 -> 1111 -> 1111 -> 15 * key

	x := gcmFieldElement{
		getUint64(key[:8]),
		getUint64(key[8:]),
	}
	g.productTable[reverseBits(1)] = x

	for i := 2; i < 16; i += 2 {
		g.productTable[reverseBits(i)] = gcmDouble(&g.productTable[reverseBits(i/2)])
		g.productTable[reverseBits(i+1)] = gcmAdd(&g.productTable[reverseBits(i)], &x)
	}

	return g, nil
}

const (
	gcmBlockSize         = 16
	gcmTagSize           = 16
	gcmStandardNonceSize = 12
)

func (g *gcm) NonceSize() int {
	return g.nonceSize
}

func (*gcm) Overhead() int {
	return gcmTagSize
}

// [Min] 加密，data为额外信息
func (g *gcm) Seal(dst, nonce, plaintext, data []byte) []byte {
	if len(nonce) != g.nonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}
	if uint64(len(plaintext)) > ((1<<32)-2)*uint64(g.cipher.BlockSize()) {
		panic("cipher: message too large for GCM")
	}

	// [Min] ret要足够大，首先要存放dst本身的内容，还有再容纳len(plaintext)+gcmTagSize长度的内容
	// [Min] out就是除去dst本身内容后的部分
	ret, out := sliceForAppend(dst, len(plaintext)+gcmTagSize)

	var counter, tagMask [gcmBlockSize]byte
	// [Min] 先计算初始counter
	g.deriveCounter(&counter, nonce)

	// [Min] 对初始counter加密，得到最后用来异或生成tag的tagMask
	g.cipher.Encrypt(tagMask[:], counter[:])
	// [Min] counter + 1
	gcmInc32(&counter)

	// [Min] 对明文采用CTR模式加密
	g.counterCrypt(out, plaintext, &counter)
	// [Min] 额外信息+填充 +  ---- 整数倍的block
	// [Min] 上述密文+填充 +  ---- 整数倍的block
	// [Min] 额外信息长度(uint64) + 上述密文长度(uint64) --- 正好是一个block
	// [Min] 对上述三大部分连接起来的数据进行GHASH，实际是是对每一个block进行GHASH
	// [Min] 然后再和tagMask（初始counter加密而来）异或，得到MAC
	g.auth(out[len(plaintext):], out[:len(plaintext)], data, &tagMask)

	// [Min] 最终out中的信息为 ciphertext+tag
	return ret
}

var errOpen = errors.New("cipher: message authentication failed")

// [Min] 解密
func (g *gcm) Open(dst, nonce, ciphertext, data []byte) ([]byte, error) {
	if len(nonce) != g.nonceSize {
		panic("cipher: incorrect nonce length given to GCM")
	}

	if len(ciphertext) < gcmTagSize {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > ((1<<32)-2)*uint64(g.cipher.BlockSize())+gcmTagSize {
		return nil, errOpen
	}

	// [Min] 首先根据tag的大小（128bits）区分出ciphertext和tag，前面是ciphertext，后面是tag
	tag := ciphertext[len(ciphertext)-gcmTagSize:]
	ciphertext = ciphertext[:len(ciphertext)-gcmTagSize]

	// [Min] 和加密一样，先根据随机数生成初始counter，再对此counter加密得到tagMask
	var counter, tagMask [gcmBlockSize]byte
	g.deriveCounter(&counter, nonce)

	g.cipher.Encrypt(tagMask[:], counter[:])
	gcmInc32(&counter)

	// [Min] 此时我们已经有ciphertext，需要验证摘要的数据data，和最后生成tag的tagMask，
	// [Min] 和加密时一样，我们可以由此生成data + ciphertext + 长度信息的tag
	var expectedTag [gcmTagSize]byte
	g.auth(expectedTag[:], ciphertext, data, &tagMask)

	ret, out := sliceForAppend(dst, len(ciphertext))

	// [Min] 如果两个tag不一样，那么说明数据一致性被破坏了，可能已被篡改
	if subtle.ConstantTimeCompare(expectedTag[:], tag) != 1 {
		// The AESNI code decrypts and authenticates concurrently, and
		// so overwrites dst in the event of a tag mismatch. That
		// behavior is mimicked here in order to be consistent across
		// platforms.
		for i := range out {
			out[i] = 0
		}
		return nil, errOpen
	}

	// [Min] 如果tag一样，那就尝试对ciphertext进行CTR解密，解密成功，说明这个数据确实是目标对象发送的
	g.counterCrypt(out, ciphertext, &counter)

	return ret, nil
}

// reverseBits reverses the order of the bits of 4-bit number in i.
// [Min] 将i中的低四位反转
func reverseBits(i int) int {
	// [Min] abcd
	// [Min] cd00 | ab00 => cdab
	i = ((i << 2) & 0xc) | ((i >> 2) & 0x3)
	// [Min] d0b0 | 0c0a => dcba
	i = ((i << 1) & 0xa) | ((i >> 1) & 0x5)
	return i
}

// gcmAdd adds two elements of GF(2¹²⁸) and returns the sum.
// [Min] 加法就是异或
func gcmAdd(x, y *gcmFieldElement) gcmFieldElement {
	// Addition in a characteristic 2 field is just XOR.
	return gcmFieldElement{x.low ^ y.low, x.high ^ y.high}
}

// gcmDouble returns the result of doubling an element of GF(2¹²⁸).
// [Min] 在伽罗华域内作右移1位
// Vi+1 = Vi >>1 if LSB1(Vi) = 0;
// Vi+1 = Vi >>1 ⊕ R if LSB1(Vi) =1.
// R = 11100001 || 0^120
func gcmDouble(x *gcmFieldElement) (double gcmFieldElement) {
	msbSet := x.high&1 == 1

	// Because of the bit-ordering, doubling is actually a right shift.
	// [Min] 因为是倒序的，所以high右移1位，并且要将low中最高次数项移到high中的最低次项
	// [Min] low右移一位
	double.high = x.high >> 1
	double.high |= x.low << 63
	double.low = x.low >> 1

	// If the most-significant bit was set before shifting then it,
	// conceptually, becomes a term of x^128. This is greater than the
	// irreducible polynomial so the result has to be reduced. The
	// irreducible polynomial is 1+x+x^2+x^7+x^128. We can subtract that to
	// eliminate the term at x^128 which also means subtracting the other
	// four terms. In characteristic 2 fields, subtraction == addition ==
	// XOR.
	// [Min] 如果high中最高次项的系数为1，那么此时要扣除不可约多项式对应的那几项，作异或
	if msbSet {
		double.low ^= 0xe100000000000000
	}

	return
}

// [Min] 不可约多项式的系数，用来做完右移后，对low做异或，索引为反序
// [Min] 右移4位，对应的16种不可约多项式
var gcmReductionTable = []uint16{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

// mul sets y to y*H, where H is the GCM key, fixed during NewGCMWithNonceSize.
// [Min] GHASH 中的加密函数，伽罗华域乘法，即乘以H，H是对128位0的加密后的值
// [Min] mul之前，已经把block的数据异或进y
func (g *gcm) mul(y *gcmFieldElement) {
	var z gcmFieldElement

	for i := 0; i < 2; i++ {
		word := y.high
		if i == 1 {
			word = y.low
		}

		// Multiplication works by multiplying z by 16 and adding in
		// one of the precomputed multiples of H.
		for j := 0; j < 64; j += 4 {
			msw := z.high & 0xf
			z.high >>= 4
			z.high |= z.low << 60
			z.low >>= 4
			z.low ^= uint64(gcmReductionTable[msw]) << 48

			// the values in |table| are ordered for
			// little-endian bit positions. See the comment
			// in NewGCMWithNonceSize.
			t := &g.productTable[word&0xf]

			z.low ^= t.low
			z.high ^= t.high
			word >>= 4
		}
	}

	*y = z
}

// updateBlocks extends y with more polynomial terms from blocks, based on
// Horner's rule. There must be a multiple of gcmBlockSize bytes in blocks.
// [Min] 循环处理每一个block，先xor新的block数据，然后 * H（GHASH），得到的数据用来和下一组block异或
// [Min] 类似于CBC模式
func (g *gcm) updateBlocks(y *gcmFieldElement, blocks []byte) {
	for len(blocks) > 0 {
		y.low ^= getUint64(blocks)
		y.high ^= getUint64(blocks[8:])
		g.mul(y)
		blocks = blocks[gcmBlockSize:]
	}
}

// update extends y with more polynomial terms from data. If data is not a
// multiple of gcmBlockSize bytes long then the remainder is zero padded.
// [Min] 对每一个block（128bits）调用updateBlocks
func (g *gcm) update(y *gcmFieldElement, data []byte) {
	// [Min] 对data中整数倍的block调用updateBlocks
	fullBlocks := (len(data) >> 4) << 4
	g.updateBlocks(y, data[:fullBlocks])

	// [Min] 不能整除16个字节，最后一组末尾填0，再调用updateBlocks
	if len(data) != fullBlocks {
		var partialBlock [gcmBlockSize]byte
		copy(partialBlock[:], data[fullBlocks:])
		g.updateBlocks(y, partialBlock[:])
	}
}

// gcmInc32 treats the final four bytes of counterBlock as a big-endian value
// and increments it.
// [Min] 把16个字节长的一段数据的最后4个字节当成一个大字节序的uint32，然后对其加1
func gcmInc32(counterBlock *[16]byte) {
	for i := gcmBlockSize - 1; i >= gcmBlockSize-4; i-- {
		counterBlock[i]++
		if counterBlock[i] != 0 {
			break
		}
	}
}

// sliceForAppend takes a slice and a requested number of bytes. It returns a
// slice with the contents of the given slice followed by that many bytes and a
// second slice that aliases into it and contains only the extra bytes. If the
// original slice has sufficient capacity then no allocation is performed.
// [Min] in是原数据，n是打算在in后面append的长度，head是一个以in开头的足够再容纳n个字节的切片，tail是head中去掉in后的部分
// [Min] 如果in的容量足够再容纳n个字节，则head就是in + n个新字节的部分，tail就是扣除in这一部分还剩的容量对应的部分
// [Min] 如果in的容量不足以再容纳n个字节，则以 len(in)+n 为长度新建slice，拷贝in到head的头部，剩下的为tail
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

// counterCrypt crypts in to out using g.cipher in counter mode.
// [Min] CTR模式，注意最后一组并没有补齐后再异或
func (g *gcm) counterCrypt(out, in []byte, counter *[gcmBlockSize]byte) {
	var mask [gcmBlockSize]byte

	for len(in) >= gcmBlockSize {
		g.cipher.Encrypt(mask[:], counter[:])
		gcmInc32(counter)

		xorWords(out, in, mask[:])
		out = out[gcmBlockSize:]
		in = in[gcmBlockSize:]
	}

	if len(in) > 0 {
		g.cipher.Encrypt(mask[:], counter[:])
		gcmInc32(counter)
		xorBytes(out, in, mask[:])
	}
}

// deriveCounter computes the initial GCM counter state from the given nonce.
// See NIST SP 800-38D, section 7.1. This assumes that counter is filled with
// zeros on entry.
// [Min] 根据随机数计算初始counter
func (g *gcm) deriveCounter(counter *[gcmBlockSize]byte, nonce []byte) {
	// GCM has two modes of operation with respect to the initial counter
	// state: a "fast path" for 96-bit (12-byte) nonces, and a "slow path"
	// for nonces of other lengths. For a 96-bit nonce, the nonce, along
	// with a four-byte big-endian counter starting at one, is used
	// directly as the starting counter. For other nonce sizes, the counter
	// is computed by passing it through the GHASH function.
	// [Min] 如果随机数的长度是标准的12个字节，将其直接拷贝至counter的头12个字节中，
	// [Min] 后4个字节用来当成局部递增的数值，并将最后一个字节置为1
	// [Min] 如果随机数不是12个字节，
	if len(nonce) == gcmStandardNonceSize {
		copy(counter[:], nonce)
		counter[gcmBlockSize-1] = 1
	} else {
		var y gcmFieldElement
		// [Min] 将nonce分组，不够的补0，然后对每一个分组以CBC模式进行加密，加密函数为GHASH，即 * H
		g.update(&y, nonce)
		// [Min] 再把nonce的长度以uint64形式写入y的最右端
		y.high ^= uint64(len(nonce)) * 8
		// [Min] 再次GHASH，得到初始counter
		g.mul(&y)
		putUint64(counter[:8], y.low)
		putUint64(counter[8:], y.high)
	}
}

// auth calculates GHASH(ciphertext, additionalData), masks the result with
// tagMask and writes the result to out.
// [Min] 计算最终的mac，对数据进行GHASH，数据分为以下三大部分，每一部分都要按block来处理
// [Min] 额外信息+填充 +  ---- 整数倍的block
// [Min] 上述密文+填充 +  ---- 整数倍的block
// [Min] 额外信息长度(uint64) + 上述密文长度(uint64) --- 正好是一个block
func (g *gcm) auth(out, ciphertext, additionalData []byte, tagMask *[gcmTagSize]byte) {
	var y gcmFieldElement
	// [Min] 首先处理额外信息
	g.update(&y, additionalData)
	// [Min] 处理密文
	g.update(&y, ciphertext)

	// [Min] 处理两个长度信息组成的一个block，先异或，再*H
	y.low ^= uint64(len(additionalData)) * 8
	y.high ^= uint64(len(ciphertext)) * 8

	g.mul(&y)

	// [Min] 输出到out
	putUint64(out, y.low)
	putUint64(out[8:], y.high)

	// [Min] 最后再次异或tagMask得到tag，即MAC
	xorWords(out, out, tagMask[:])
}

// [Min] 大字节序从data中读取一个uint64的数值
func getUint64(data []byte) uint64 {
	r := uint64(data[0])<<56 |
		uint64(data[1])<<48 |
		uint64(data[2])<<40 |
		uint64(data[3])<<32 |
		uint64(data[4])<<24 |
		uint64(data[5])<<16 |
		uint64(data[6])<<8 |
		uint64(data[7])
	return r
}

// [Min] 大字节序存储v到out中
func putUint64(out []byte, v uint64) {
	out[0] = byte(v >> 56)
	out[1] = byte(v >> 48)
	out[2] = byte(v >> 40)
	out[3] = byte(v >> 32)
	out[4] = byte(v >> 24)
	out[5] = byte(v >> 16)
	out[6] = byte(v >> 8)
	out[7] = byte(v)
}
