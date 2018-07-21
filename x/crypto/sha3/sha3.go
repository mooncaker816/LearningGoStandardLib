// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// spongeDirection indicates the direction bytes are flowing through the sponge.
// [Min] 海绵方向，指字节流动的方向，吸入，挤出
type spongeDirection int

const (
	// spongeAbsorbing indicates that the sponge is absorbing input.
	// [Min] 吸入
	spongeAbsorbing spongeDirection = iota
	// spongeSqueezing indicates that the sponge is being squeezed.
	// [Min] 挤出
	spongeSqueezing
)

const (
	// maxRate is the maximum size of the internal buffer. SHAKE-256
	// currently needs the largest buffer.
	maxRate = 168
)

// [Min] Keccak 内部状态结构，其规格由参数 b 决定
// [Min] b = 25,50,100,200,400,800,1600
// [Min] 这几种规格都是25的整数倍，
// [Min] 即25的1(2^0)倍，2(2^1)倍，4(2^2)倍，8(2^3)倍，16(2^4)倍，32(2^5)倍，64(2^6)倍
// [Min] SHA3 采用 1600
type state struct {
	// Generic sponge components.
	// [Min] 最主要的内部状态三维比特数组，5*5*64 位
	// [Min] 其中a的一个元素可以看成是一个Lane
	// [Min] 这25个元素依次首尾相连，构成内部状态的比特表达形式
	a [25]uint64 // main state of the hash
	// [Min] 一段临时存储空间，指向storage数组，用于填充不满组大小的数据，也用于最后挤压时当作临时输出
	buf []byte // points into storage
	// [Min] 参与和输入分组数据运算的位数，即输入分组的大小
	rate int // the number of bytes of state to use

	// dsbyte contains the "domain separation" bits and the first bit of
	// the padding. Sections 6.1 and 6.2 of [1] separate the outputs of the
	// SHA-3 and SHAKE functions by appending bitstrings to the message.
	// Using a little-endian bit-ordering convention, these are "01" for SHA-3
	// and "1111" for SHAKE, or 00000010b and 00001111b, respectively. Then the
	// padding rule from section 5.1 is applied to pad the message to a multiple
	// of the rate, which involves adding a "1" bit, zero or more "0" bits, and
	// a final "1" bit. We merge the first "1" bit from the padding into dsbyte,
	// giving 00000110b (0x06) and 00011111b (0x1f).
	// [1] http://csrc.nist.gov/publications/drafts/fips-202/fips_202_draft.pdf
	//     "Draft FIPS 202: SHA-3 Standard: Permutation-Based Hash and
	//      Extendable-Output Functions (May 2014)"
	// [Min] 填充首字节，和具体SHA3类型有关
	dsbyte  byte
	storage [maxRate]byte

	// Specific to SHA-3 and SHAKE.
	// [Min] 输出SHA3摘要字节长度
	outputLen int // the default output size in bytes
	// [Min] 表明当前状态是吸收还是挤压
	state spongeDirection // whether the sponge is absorbing or squeezing
}

// BlockSize returns the rate of sponge underlying this hash function.
// [Min] 分组大小，即状态数组中参与运算的位数
func (d *state) BlockSize() int { return d.rate }

// Size returns the output size of the hash function in bytes.
// [Min] 输出摘要的字节长度
func (d *state) Size() int { return d.outputLen }

// Reset clears the internal state by zeroing the sponge state and
// the byte buffer, and setting Sponge.state to absorbing.
// [Min] 重置state,状态设为吸收状态，设buf的底层数组位storage
func (d *state) Reset() {
	// Zero the permutation's state.
	for i := range d.a {
		d.a[i] = 0
	}
	d.state = spongeAbsorbing
	d.buf = d.storage[:0]
}

func (d *state) clone() *state {
	ret := *d
	if ret.state == spongeAbsorbing {
		ret.buf = ret.storage[:len(ret.buf)]
	} else {
		ret.buf = ret.storage[d.rate-cap(d.buf) : d.rate]
	}

	return &ret
}

// permute applies the KeccakF-1600 permutation. It handles
// any input-output buffering.
// [Min] 如果是吸收状态，从buf中吸收数据后处理
// [Min] 如果是挤压状态，从state中输出一组数据到buf中
func (d *state) permute() {
	switch d.state {
	case spongeAbsorbing:
		// [Min] 如果是吸收状态，从buf中吸收并清空buf，此时的buf已经填充完毕，然后处理这一组数据
		// If we're absorbing, we need to xor the input into the state
		// before applying the permutation.
		xorIn(d, d.buf)
		d.buf = d.storage[:0]
		keccakF1600(&d.a)
	case spongeSqueezing:
		// [Min] 如果是挤压状态，调用 keccakF1600，然后输出一组数据到buf
		// If we're squeezing, we need to apply the permutatin before
		// copying more output.
		keccakF1600(&d.a)
		d.buf = d.storage[:d.rate]
		copyOut(d, d.buf)
	}
}

// pads appends the domain separation bits in dsbyte, applies
// the multi-bitrate 10..1 padding rule, and permutes the state.
// [Min] 填充数据，此时buf肯定不满一组
func (d *state) padAndPermute(dsbyte byte) {
	if d.buf == nil {
		d.buf = d.storage[:0]
	}
	// Pad with this instance's domain-separator bits. We know that there's
	// at least one byte of space in d.buf because, if it were full,
	// permute would have been called to empty it. dsbyte also contains the
	// first one bit for the padding. See the comment in the state struct.
	// [Min] 先填充一个字节的domain-separator，再以0补足一组大小
	d.buf = append(d.buf, dsbyte)
	zerosStart := len(d.buf)
	d.buf = d.storage[:d.rate]
	for i := zerosStart; i < d.rate; i++ {
		d.buf[i] = 0
	}
	// This adds the final one bit for the padding. Because of the way that
	// bits are numbered from the LSB upwards, the final bit is the MSB of
	// the last byte.
	// [Min] 翻转最后一个字节的最高位
	d.buf[d.rate-1] ^= 0x80
	// Apply the permutation
	// [Min] 调用permute，处理buf中的数据
	d.permute()
	// [Min] 此时已完成吸收阶段，修改状态为挤压
	d.state = spongeSqueezing
	// [Min] buf在permute中已经清零，这里将它扩容到可以容纳一组输出，
	// [Min] 然后从state中将最后一组的处理结果输出到buf
	d.buf = d.storage[:d.rate]
	copyOut(d, d.buf)
}

// Write absorbs more data into the hash's state. It produces an error
// if more data is written to the ShakeHash after writing
// [Min] 从外部输入吸收数据到state中
func (d *state) Write(p []byte) (written int, err error) {
	// [Min] 必须处于吸收阶段
	if d.state != spongeAbsorbing {
		panic("sha3: write to sponge after read")
	}
	if d.buf == nil {
		d.buf = d.storage[:0]
	}
	written = len(p)

	for len(p) > 0 {
		// [Min] 如果 p 的长度超过了分组大小，从 p 的头部取出分组大小的部分，吸收入state中
		if len(d.buf) == 0 && len(p) >= d.rate {
			// The fast path; absorb a full "rate" bytes of input and apply the permutation.
			// [Min] 吸收一个分组到 state 中
			xorIn(d, p[:d.rate])
			// [Min] 从 p 中移除已吸收的部分，待后续处理
			p = p[d.rate:]
			// [Min] 对已吸收的分组作用keccakF1600函数
			keccakF1600(&d.a)
		} else {
			// The slow path; buffer the input until we can fill the sponge, and then xor it in.
			// [Min] 不够一组或者buf中有数据，先将数据存入buf中，
			// [Min] 如果buf + p剩余的能够满一组，调用permute从buf中吸收数据并处理
			todo := d.rate - len(d.buf)
			if todo > len(p) {
				todo = len(p)
			}
			d.buf = append(d.buf, p[:todo]...)
			p = p[todo:]

			// If the sponge is full, apply the permutation.
			if len(d.buf) == d.rate {
				d.permute()
			}
		}
	}

	return
}

// Read squeezes an arbitrary number of bytes from the sponge.
// [Min] 如果是吸收状态，会先进行最后一个填充分块的处理，再从state中把数据挤出
// [Min] 永远返回0，nil
func (d *state) Read(out []byte) (n int, err error) {
	// If we're still absorbing, pad and apply the permutation.
	// [Min] 如果还是吸收状态，先处理最后一组待填充数据
	if d.state == spongeAbsorbing {
		d.padAndPermute(d.dsbyte)
	}

	// [Min] 此时buf中包含了第一组待输出分组数据
	n = len(out)

	// Now, do the squeezing.
	// [Min] 从buf中拷贝数据到最终输出，直到满足该SHA3类型的输出长度为止
	// [Min] 这也就实现了Shake的变长输出，由out的长度决定
	for len(out) > 0 {
		n := copy(out, d.buf)
		d.buf = d.buf[n:]
		out = out[n:]

		// Apply the permutation if we've squeezed the sponge dry.
		// [Min] 如果buf内的数据已经全部拷贝至out，则说明还没达到输出长度要求（或者恰好刚达到，等待跳出循环）
		// [Min] 此时继续执行挤压数据的操作，对当前的d再作用keccakF1600，并将输出数据拷贝至buf等待下次循环拷贝至最终输出
		if len(d.buf) == 0 {
			d.permute()
		}
	}

	return
}

// Sum applies padding to the hash state and then squeezes out the desired
// number of output bytes.
// [Min] 在当前state的状态下，填充后计算SHA3，in 一般填 nil 即可
// [Min] 主要用于分批次调用 d.Write 的情况，可以计算即时（当前write后）SHA3
// [Min] 因为采用了clone state的模式，相当于是一个分支对应于当前已写入的数据，不会影响到最终计算完整输入的结果
func (d *state) Sum(in []byte) []byte {
	// Make a copy of the original hash so that caller can keep writing
	// and summing.
	dup := d.clone()
	hash := make([]byte, dup.outputLen)
	dup.Read(hash)
	return append(in, hash...)
}
