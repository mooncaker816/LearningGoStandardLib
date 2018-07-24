// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// CFB (Cipher Feedback) Mode.

package cipher

/* [Min]
1. 对CFB来说，我们要做的核心工作是为每个分组生成密钥流，再使用这个密钥流来加解密该分组
2. 对于加，解密，生成密钥流的方法都是一样的，可以看成是对某一数据的加密，
而这个某一数据就是前一分组的密文（初始向量）
3. 加密时，先利用加密算法对前一分组的密文进行加密，得到秘钥流，再和该分组明文异或得到该组的密文
4. 解密时，先利用加密算法对前一分组的密文进行加密，得到秘钥流，再和该分组密文异或得到该组的明文
*/
// [Min] 分组密码之CFB模式
type cfb struct {
	b       Block  // [Min] 用来对密文（初始向量）加密生成下一分组的秘钥流
	next    []byte // [Min] 存储当前分组的密文（初始向量）
	out     []byte // [Min] 存储对当前分组密文加密后的密钥流
	outUsed int

	decrypt bool
}

// [Min] 循环处理每一个分组，加解密都是从第一个分组开始
func (x *cfb) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		// [Min] 处理第一个分组的时候，next中为初始向量，
		// [Min] 后续分组 next 中为前一分组的密文，用于生成密钥流到out中
		// [Min] x.outUsed == len(x.out)，说明上轮循环成功加密或解密了一个分组的数据，
		// [Min] 需要为后续分组创建密钥流
		if x.outUsed == len(x.out) {
			// [Min] 加解密调用的都是Encrypt，用来生成密钥流
			x.b.Encrypt(x.out, x.next)
			x.outUsed = 0
		}

		// [Min] 如果是解密，则从src中取出该分组密文存入next中
		// [Min] 理论上，如果是解密的话，可以像OFB模式一样一次计算出多个密钥流，
		// [Min] 但是这里并没有实现，next的长度还是blockSize
		if x.decrypt {
			// We can precompute a larger segment of the
			// keystream on decryption. This will allow
			// larger batches for xor, and we should be
			// able to match CTR/OFB performance.
			copy(x.next[x.outUsed:], src)
		}
		// [Min] 将当前分组和密钥流异或，得到当前分组的密文
		n := xorBytes(dst, src, x.out[x.outUsed:])
		// [Min] 如果是加密，则从dst中将该分组密文存入next中
		if !x.decrypt {
			copy(x.next[x.outUsed:], dst)
		}
		// [Min] 设置下一分组位置
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}

// NewCFBEncrypter returns a Stream which encrypts with cipher feedback mode,
// using the given Block. The iv must be the same length as the Block's block
// size.
func NewCFBEncrypter(block Block, iv []byte) Stream {
	return newCFB(block, iv, false)
}

// NewCFBDecrypter returns a Stream which decrypts with cipher feedback mode,
// using the given Block. The iv must be the same length as the Block's block
// size.
func NewCFBDecrypter(block Block, iv []byte) Stream {
	return newCFB(block, iv, true)
}

// [Min] 新建CFB秘钥流模式
func newCFB(block Block, iv []byte, decrypt bool) Stream {
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		// stack trace will indicate whether it was de or encryption
		panic("cipher.newCFB: IV length must equal block size")
	}
	x := &cfb{
		b:       block,
		out:     make([]byte, blockSize),
		next:    make([]byte, blockSize),
		outUsed: blockSize,
		decrypt: decrypt,
	}
	copy(x.next, iv)

	return x
}
