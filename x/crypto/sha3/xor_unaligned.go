// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64 386 ppc64le
// +build !appengine

package sha3

import "unsafe"

// [Min] 将输入分组数据吸收入state中，并作异或处理
// [Min] 此时 buf 的大小已经调整为相关类型对应得 rate
func xorInUnaligned(d *state, buf []byte) {
	// [Min] 按 Lane 结构依次吸入，最多可以吸入21条Lane，一共25条Lane，要留填充部分
	// [Min] 每条 Lane 对应一个 uint64 的整数
	bw := (*[maxRate / 8]uint64)(unsafe.Pointer(&buf[0]))
	n := len(buf) // [Min] 根据 buf 的长度获得 rate
	// [Min] SHA3-512 rate 72 字节 = 9 组 uint64
	if n >= 72 {
		d.a[0] ^= bw[0]
		d.a[1] ^= bw[1]
		d.a[2] ^= bw[2]
		d.a[3] ^= bw[3]
		d.a[4] ^= bw[4]
		d.a[5] ^= bw[5]
		d.a[6] ^= bw[6]
		d.a[7] ^= bw[7]
		d.a[8] ^= bw[8]
	}
	// [Min] SHA3-384 rate 104 字节 = 13 组 uint64
	if n >= 104 {
		d.a[9] ^= bw[9]
		d.a[10] ^= bw[10]
		d.a[11] ^= bw[11]
		d.a[12] ^= bw[12]
	}
	// [Min] SHA3-256，Shake256 rate 136 字节 = 17 组 uint64
	if n >= 136 {
		d.a[13] ^= bw[13]
		d.a[14] ^= bw[14]
		d.a[15] ^= bw[15]
		d.a[16] ^= bw[16]
	}
	// [Min] SHA3-224 rate 144 字节 = 18 组 uint64
	if n >= 144 {
		d.a[17] ^= bw[17]
	}
	// [Min] Shake128 rate 168 字节 = 21 组 uint64
	if n >= 168 {
		d.a[18] ^= bw[18]
		d.a[19] ^= bw[19]
		d.a[20] ^= bw[20]
	}
}

// [Min] 将state中的数据返回
func copyOutUnaligned(d *state, buf []byte) {
	ab := (*[maxRate]uint8)(unsafe.Pointer(&d.a[0]))
	copy(buf, ab[:])
}

var (
	xorIn   = xorInUnaligned
	copyOut = copyOutUnaligned
)

const xorImplementationUnaligned = "unaligned"
