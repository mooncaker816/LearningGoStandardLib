// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// OFB (Output Feedback) Mode.

package cipher

/* [Min]
1. 对OFB来说，与CFB类似，我们要做的核心工作是为每个分组生成密钥流，再使用这个密钥流来加解密该分组
2. 对于加，解密，生成密钥流的方法都是一样的，可以看成是对某一数据的加密，
而这个某一数据就是前一分组的密钥流（初始向量），
即对初始向量不断加密，如果加密函数为f的话，那么第i组的密钥流就是f...(f(f(iv))),i=1,2,3...
3. 与CFB略有不同的是，密钥流可以提前计算好，因为每一组对应的秘钥流只与组的索引有关，
所以我们可以提前按顺序计算好若干个组的密钥流，然后一次性对这若干个组进行加解密，提高效率
4. 如果在完成这若干个秘钥流的加解密后，还有数据，继续3中的操作，直到完成所有数据的加解密
*/
// [Min] 分组密码之OFB模式
type ofb struct {
	b       Block  // [Min] 用来对本组密钥流（初始向量）加密生成下一分组的秘钥流
	cipher  []byte // [Min] 前一组密钥流(初始向量)
	out     []byte // [Min] 一系列按顺序通过refill计算好的密钥流
	outUsed int    // [Min] out中已经使用过的密钥流的总长度
}

// NewOFB returns a Stream that encrypts or decrypts using the block cipher b
// in output feedback mode. The initialization vector iv's length must be equal
// to b's block size.
// [Min] 新建OFB密钥流模式
func NewOFB(b Block, iv []byte) Stream {
	blockSize := b.BlockSize()
	if len(iv) != blockSize {
		panic("cipher.NewOFB: IV length must equal block size")
	}
	// [Min] out的容量最低取512字节，如果blockSize超过512，按blockSize计算
	bufSize := streamBufferSize
	if bufSize < blockSize {
		bufSize = blockSize
	}
	x := &ofb{
		b:       b,
		cipher:  make([]byte, blockSize),
		out:     make([]byte, 0, bufSize),
		outUsed: 0,
	}

	copy(x.cipher, iv)
	return x
}

// [Min] 根据outUsed，移去out中已使用过的密钥流，并计算后续密钥流
func (x *ofb) refill() {
	bs := x.b.BlockSize()
	remain := len(x.out) - x.outUsed
	// [Min] 如果剩余的大于已使用的，说明剩余的至少还有一个完整的密钥流未使用，直接返回
	if remain > x.outUsed {
		return
	}
	// [Min] 从out中移去已使用的密钥流
	copy(x.out, x.out[x.outUsed:])
	// [Min] 保留remain的部分，并初始化后续数据
	x.out = x.out[:cap(x.out)]
	// [Min] 累计计算密钥流，并添加到remain中，直到无法再次添加一个完整的密钥流为止
	for remain < len(x.out)-bs {
		x.b.Encrypt(x.cipher, x.cipher)
		copy(x.out[remain:], x.cipher)
		remain += bs
	}
	// [Min] 保留当前所有未使用的秘钥流，置outUsed为0
	x.out = x.out[:remain]
	x.outUsed = 0
}

// [Min] 通过out中的密钥流，对明文，密文加解密
func (x *ofb) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		// [Min] 如果out中剩余未使用的部分不够一个密钥流的长度，
		// [Min] 则需要从out中移去已使用过的密钥流，并且计算后续的密钥流
		if x.outUsed >= len(x.out)-x.b.BlockSize() {
			x.refill()
		}
		// [Min] 一次性从src中加解密与out中未使用的秘钥流对应的相同数量的明文或密文
		n := xorBytes(dst, src, x.out[x.outUsed:])
		// [Min] 设置下一次加解密的起点位置
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}
