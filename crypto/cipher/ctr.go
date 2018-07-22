// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Counter (CTR) mode.

// CTR converts a block cipher into a stream cipher by
// repeatedly encrypting an incrementing counter and
// xoring the resulting stream of data with the input.

// See NIST SP 800-38A, pp 13-15

package cipher

/* [Min]
1. 对CTR来说，与OFB极其类似，我们要做的核心工作也是为每个分组生成密钥流，再使用这个密钥流来加解密该分组
2. 对于加，解密，生成密钥流的方法都是一样的，可以看成是对某一数据的加密，
而这个某一数据就是当前分组的计数值，
如果加密函数为f的话，初始计数为A，那么第i组的密钥流就是f(A+i-1),i=1,2,3...
3. 同样，密钥流也可以提前计算好，因为每一组对应的秘钥流只与组的索引有关，（初始计数已确定）
所以我们可以提前按顺序计算好若干个组的密钥流，然后一次性对这若干个组进行加解密，提高效率
4. 如果在完成这若干个秘钥流的加解密后，还有数据，继续3中的操作，直到完成所有数据的加解密
*/
// [Min] 分组密码之CTR模式
type ctr struct {
	b       Block  // [Min] 用来对本组计数加密生成下一分组的秘钥流
	ctr     []byte // [Min] 分组计数器，长度与blockSize相同，可以把byte切片看成一个连起来的大数
	out     []byte // [Min] 一系列密钥流
	outUsed int    // [Min] out中已使用的密钥流
}

const streamBufferSize = 512

// ctrAble is an interface implemented by ciphers that have a specific optimized
// implementation of CTR, like crypto/aes. NewCTR will check for this interface
// and return the specific Stream if found.
type ctrAble interface {
	NewCTR(iv []byte) Stream
}

// NewCTR returns a Stream which encrypts/decrypts using the given Block in
// counter mode. The length of iv must be the same as the Block's block size.
func NewCTR(block Block, iv []byte) Stream {
	if ctr, ok := block.(ctrAble); ok {
		return ctr.NewCTR(iv)
	}
	if len(iv) != block.BlockSize() {
		panic("cipher.NewCTR: IV length must equal block size")
	}
	bufSize := streamBufferSize
	if bufSize < block.BlockSize() {
		bufSize = block.BlockSize()
	}
	return &ctr{
		b:       block,
		ctr:     dup(iv),
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
	}
}

// [Min] 尽可能多地在out中计算密钥流
func (x *ctr) refill() {
	remain := len(x.out) - x.outUsed
	copy(x.out, x.out[x.outUsed:])
	x.out = x.out[:cap(x.out)]
	bs := x.b.BlockSize()
	for remain <= len(x.out)-bs {
		x.b.Encrypt(x.out[remain:], x.ctr)
		remain += bs

		// Increment counter
		// [Min] 从最后一个字节开始尝试加1，如果没有溢出，跳出循环
		// [Min] 否则高一个字节进一位
		for i := len(x.ctr) - 1; i >= 0; i-- {
			x.ctr[i]++
			if x.ctr[i] != 0 {
				break
			}
		}
	}
	x.out = x.out[:remain]
	x.outUsed = 0
}

// [Min] 与OFB类似
func (x *ctr) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		if x.outUsed >= len(x.out)-x.b.BlockSize() {
			x.refill()
		}
		n := xorBytes(dst, src, x.out[x.outUsed:])
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}
