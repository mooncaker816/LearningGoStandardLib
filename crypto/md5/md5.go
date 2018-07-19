// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run gen.go -full -output md5block.go

// Package md5 implements the MD5 hash algorithm as defined in RFC 1321.
//
// MD5 is cryptographically broken and should not be used for secure
// applications.
package md5

import (
	"crypto"
	"errors"
	"hash"
)

func init() {
	crypto.RegisterHash(crypto.MD5, New)
}

// The size of an MD5 checksum in bytes.
// [Min] MD5 消息摘要的字节数，16 字节，128 bits
const Size = 16

// The blocksize of MD5 in bytes.
// [Min] 分块的大小 64 字节
const BlockSize = 64

const (
	chunk = 64         // [Min] 一个分块的字节长度，64 字节，512 位
	init0 = 0x67452301 // [Min] 初始摘要中0-3字节的值
	init1 = 0xEFCDAB89 // [Min] 初始摘要中4-7字节的值
	init2 = 0x98BADCFE // [Min] 初始摘要中8-11字节的值
	init3 = 0x10325476 // [Min] 初始摘要中12-15字节的值
)

/* [Min]
1. 先将源数据以64字节为单位分块，留出不够一个分块的部分 B ，其余部分 A 为64字节的整数倍
2. 将 A 中的数据依次按分块处理
3. 对 B 进行以下填充，使得 B % 64 = 56， 单位为字节
如果 B 不满 56 字节（448位），第一位填充1，后续填充 0 至448位即可，等待最终长度的填充
如果 B >= 56 字节，则需填充 (64 - B)*8 + 448 位，第一位为1，后续为0，
并且此时会形成一个满的分块，对此分块处理，剩余 448 位等待最终长度填充后达到512位后一起处理
4. 最后将源数据和所有填充数据的长度以 uint64 的类型填充到上述 448 位后，形成最后一个分块
对此分块进行处理
*/
// digest represents the partial evaluation of a checksum.
// [Min] 消息摘要
type digest struct {
	s   [4]uint32   // [Min] 存储摘要的实际载体
	x   [chunk]byte // [Min] 填充分块
	nx  int         // [Min] 当前填充分块中未处理数据的字节长度
	len uint64      // [Min] 源消息的长度
}

// [Min] 重置摘要，将载体中的值按初始值初始化
func (d *digest) Reset() {
	d.s[0] = init0
	d.s[1] = init1
	d.s[2] = init2
	d.s[3] = init3
	d.nx = 0
	d.len = 0
}

const (
	magic = "md5\x01"
	// [Min] MarshalBinary 返回的字节长度 ：
	// [Min] magic 头长度 + 16 字节消息摘要长度 + 64 字节最后一个分块长度 + 8 字节源消息大小的长度
	marshaledSize = len(magic) + 4*4 + chunk + 8
)

// [Min] 调用 Write 方法后，将当前 d 中数据格式化，用于反应 hash 过程中的状态
func (d *digest) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, marshaledSize)
	// [Min] 头
	b = append(b, magic...)
	// [Min] 当前已处理分块的消息摘要
	b = appendUint32(b, d.s[0])
	b = appendUint32(b, d.s[1])
	b = appendUint32(b, d.s[2])
	b = appendUint32(b, d.s[3])
	// [Min] 将填充分块中的还在等待填充的数据写入 b
	b = append(b, d.x[:d.nx]...)
	// [Min] 撑满一个分块的大小
	b = b[:len(b)+len(d.x)-int(d.nx)] // already zero
	// [Min] 当前已处理的数据的长度（可能包括填充数据）写入 b
	b = appendUint64(b, d.len)
	return b, nil
}

// [Min] 根据 digest 的状态（marshal 后的字节流），还原 digest
func (d *digest) UnmarshalBinary(b []byte) error {
	// [Min] 必须有 magic 头
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return errors.New("crypto/md5: invalid hash state identifier")
	}
	// [Min] b 的长度是固定的 marshaledSize
	if len(b) != marshaledSize {
		return errors.New("crypto/md5: invalid hash state size")
	}
	b = b[len(magic):]
	// [Min] 还原当前的消息摘要
	b, d.s[0] = consumeUint32(b)
	b, d.s[1] = consumeUint32(b)
	b, d.s[2] = consumeUint32(b)
	b, d.s[3] = consumeUint32(b)
	// [Min] 还原填充分块数据
	b = b[copy(d.x[:], b):]
	// [Min] 还原已处理数据（可能包括填充数据）长度
	b, d.len = consumeUint64(b)
	// [Min] 还原填充分块中待填充的数据的长度
	d.nx = int(d.len) % chunk
	return nil
}

// [Min] 将 x 对应的8个字节由高到低依次存入 b 中
func appendUint64(b []byte, x uint64) []byte {
	a := [8]byte{
		byte(x >> 56),
		byte(x >> 48),
		byte(x >> 40),
		byte(x >> 32),
		byte(x >> 24),
		byte(x >> 16),
		byte(x >> 8),
		byte(x),
	}
	return append(b, a[:]...)
}

// [Min] 将 x 对应的4个字节由高到低依次存入 b 中
func appendUint32(b []byte, x uint32) []byte {
	a := [4]byte{
		byte(x >> 24),
		byte(x >> 16),
		byte(x >> 8),
		byte(x),
	}
	return append(b, a[:]...)
}

// [Min] 将 b 中前8个字节当成一个 uint64 数值，返回剩余部分和该数值
func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

// [Min] 将 b 中前4个字节当成一个 uint32 数值，返回剩余部分和该数值
func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}

// New returns a new hash.Hash computing the MD5 checksum. The Hash also
// implements encoding.BinaryMarshaler and encoding.BinaryUnmarshaler to
// marshal and unmarshal the internal state of the hash.
// [Min] 构造一个 MD5 类型的 hash 载体
func New() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// [Min] 返回 MD5 摘要的字节长度16
func (d *digest) Size() int { return Size }

// [Min] 返回 MD5 的 BlockSize 64
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	// [Min] 如果 d.nx >0, 说明 d.x 中含有遗留的未处理的尾部源数据（不够一个分块的部分）
	// [Min] 此时 p 中的数据为填充数据，
	// [Min] 如果填满了一个分块，就进行处理
	// [Min] 如果没满，说明还在等待最后的长度填充（届时一定能恰好填满一个分块）
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == chunk {
			block(d, d.x[:])
			d.nx = 0
		}
		p = p[n:]
	}
	// [Min] 源数据超过一个分块的大小，此处的 p 为源数据
	if len(p) >= chunk {
		// [Min] 计算出 p 中最大整数倍分块大小的字节长度 n，
		// [Min] 对这 n 个字节先处理，剩余部分比分块大小小，存入 p 中
		n := len(p) &^ (chunk - 1)
		block(d, p[:n])
		p = p[n:]
	}
	// [Min] p 中数据不够一个分块，存入 d.x 中，待后续调用 Write 时再处理
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *digest) Sum(in []byte) []byte {
	// Make a copy of d0 so that caller can keep writing and summing.
	d := *d0
	hash := d.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() [Size]byte {
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	// [Min] 获得填充前的源消息字节长度
	len := d.len
	var tmp [64]byte
	// [Min] 填充信息，最高位为1，后续全为0
	tmp[0] = 0x80
	// [Min] 如果不满56字节（448位），填充至56字节即可
	// [Min] 如果超过或等于56字节，需填满一个分块64字节，再填56字节
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	// [Min] 将字节长度转为 bit 位长，再将其存入8个字节中，代表一个 uint64 值
	// [Min] 再将这8个字节填入剩余部分，构成最后一个分块（小字节序）
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	d.Write(tmp[0:8])

	// [Min] 此时 d.nx 必须为0， 代表 d.x 中的分块已处理
	if d.nx != 0 {
		panic("d.nx != 0")
	}

	// [Min] 所有分块都处理完后，将最终128位摘要信息按小字节序写入对应的16个字节的变量返回
	var digest [Size]byte
	for i, s := range d.s {
		digest[i*4] = byte(s)
		digest[i*4+1] = byte(s >> 8)
		digest[i*4+2] = byte(s >> 16)
		digest[i*4+3] = byte(s >> 24)
	}

	return digest
}

// Sum returns the MD5 checksum of the data.
// [Min] 计算 data 的 MD5 摘要信息
func Sum(data []byte) [Size]byte {
	var d digest
	d.Reset()
	// [Min] 先把能构成分块的数据处理，留下剩余不够分块的数据待处理
	d.Write(data)
	// [Min] 填充分块，处理数据，最后返回消息摘要
	return d.checkSum()
}
