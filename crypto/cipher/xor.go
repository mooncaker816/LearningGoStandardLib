// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"runtime"
	"unsafe"
)

// [Min] uint 占的字节数
const wordSize = int(unsafe.Sizeof(uintptr(0)))
const supportsUnaligned = runtime.GOARCH == "386" || runtime.GOARCH == "amd64" || runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le" || runtime.GOARCH == "s390x"

// fastXORBytes xors in bulk. It only works on architectures that
// support unaligned read/writes.
// [Min] 优先以wordSize为单位，a,b按短的长度作异或，存入dst
func fastXORBytes(dst, a, b []byte) int {
	// [Min] n取a,b长度的最小值
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	if n == 0 {
		return 0
	}
	// Assert dst has enough space
	_ = dst[n-1]

	// [Min] w 表示有几个完整的uint
	w := n / wordSize
	// [Min] 以uint为一个单位，将a^b存入dst中
	if w > 0 {
		dw := *(*[]uintptr)(unsafe.Pointer(&dst))
		aw := *(*[]uintptr)(unsafe.Pointer(&a))
		bw := *(*[]uintptr)(unsafe.Pointer(&b))
		for i := 0; i < w; i++ {
			dw[i] = aw[i] ^ bw[i]
		}
	}

	// [Min] 对于不足一个uint的部分，按顺序一个字节一个字节异或
	for i := (n - n%wordSize); i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	// [Min] 返回n
	return n
}

// [Min] 以字节为单位，a,b按短的长度作异或，存入dst
func safeXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

// xorBytes xors the bytes in a and b. The destination should have enough
// space, otherwise xorBytes will panic. Returns the number of bytes xor'd.
// [Min] a,b异或存入dst
func xorBytes(dst, a, b []byte) int {
	if supportsUnaligned {
		return fastXORBytes(dst, a, b)
	} else {
		// TODO(hanwen): if (dst, a, b) have common alignment
		// we could still try fastXORBytes. It is not clear
		// how often this happens, and it's only worth it if
		// the block encryption itself is hardware
		// accelerated.
		return safeXORBytes(dst, a, b)
	}
}

// fastXORWords XORs multiples of 4 or 8 bytes (depending on architecture.)
// The arguments are assumed to be of equal length.
// [Min] 以wordSize为单位，且a，b长度相同，异或a,b存入dst，不足wordSize的部分被舍弃
func fastXORWords(dst, a, b []byte) {
	dw := *(*[]uintptr)(unsafe.Pointer(&dst))
	aw := *(*[]uintptr)(unsafe.Pointer(&a))
	bw := *(*[]uintptr)(unsafe.Pointer(&b))
	n := len(b) / wordSize
	for i := 0; i < n; i++ {
		dw[i] = aw[i] ^ bw[i]
	}
}

// [Min] 按wordSize为单位，异或
func xorWords(dst, a, b []byte) {
	if supportsUnaligned {
		fastXORWords(dst, a, b)
	} else {
		safeXORBytes(dst, a, b)
	}
}
