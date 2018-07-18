// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package utf16 implements encoding and decoding of UTF-16 sequences.
package utf16

// The conditions replacementChar==unicode.ReplacementChar and
// maxRune==unicode.MaxRune are verified in the tests.
// Defining them locally avoids this package depending on package unicode.

const (
	replacementChar = '\uFFFD'     // Unicode replacement character
	maxRune         = '\U0010FFFF' // Maximum valid Unicode code point.
)

const (
	// 0xd800-0xdc00 encodes the high 10 bits of a pair.
	// 0xdc00-0xe000 encodes the low 10 bits of a pair.
	// the value is those 20 bits plus 0x10000.
	surr1 = 0xd800
	surr2 = 0xdc00
	surr3 = 0xe000

	surrSelf = 0x10000
)

/* [Min]
UTF-16 编码的字符由2个或4个字节构成，
U+0000至U+D7FF的 unicode 的码点值和 UTF-16 的码点值相同，只需将 unicode 的码值等效转为2个字节的码值即可
U+E000至U+FFFF的 unicode 的码点值和 UTF-16 的码点值相同，只需将 unicode 的码值等效转为2个字节的码值即可
U+10000到U+10FFFF的 unicode 字符对应的 UTF-16 编码由一对代理码点构成，
其中高代理码点取值范围是0xD800-0xDBFF，低代理码点取值范围是0xDC00-0xDFFF，
将这一对码点（共32位4个字节）作为一个整体当成 UTF-16 对该字符的编码

Unicode 0x10437 对应的代理码点的计算：
1. 0x10437减去0x10000,结果为0x00437,二进制为 0000 0000 0100 0011 0111。
2. 分区它的上10位值和下10位值（使用二进制）:0000000001 and 0000110111。
3. 添加0xD800到上值，以形成高位：0xD800 + 0x0001 = 0xD801。
4. 添加0xDC00到下值，以形成低位：0xDC00 + 0x0037 = 0xDC37。
*/

// IsSurrogate reports whether the specified Unicode code point
// can appear in a surrogate pair.
// [Min] 判断 unicode 码点是否为代理码点
func IsSurrogate(r rune) bool {
	return surr1 <= r && r < surr3
}

// DecodeRune returns the UTF-16 decoding of a surrogate pair.
// If the pair is not a valid UTF-16 surrogate pair, DecodeRune returns
// the Unicode replacement code point U+FFFD.
// [Min] 根据高代理码点 r1 和低代理码点 r2，返回对应的 unicode 码点
func DecodeRune(r1, r2 rune) rune {
	if surr1 <= r1 && r1 < surr2 && surr2 <= r2 && r2 < surr3 {
		return (r1-surr1)<<10 | (r2 - surr2) + surrSelf
	}
	return replacementChar
}

// EncodeRune returns the UTF-16 surrogate pair r1, r2 for the given rune.
// If the rune is not a valid Unicode code point or does not need encoding,
// EncodeRune returns U+FFFD, U+FFFD.
// [Min] 对 unicode 进行 UTF-16 编码，返回对应的代理码点，
// [Min] 如果 unicode 本身不需要代理码点来表示，返回replacementChar
func EncodeRune(r rune) (r1, r2 rune) {
	if r < surrSelf || r > maxRune {
		return replacementChar, replacementChar
	}
	r -= surrSelf
	return surr1 + (r>>10)&0x3ff, surr2 + r&0x3ff
}

// Encode returns the UTF-16 encoding of the Unicode code point sequence s.
// [Min] 将 unicode 编码为 UTF-16
func Encode(s []rune) []uint16 {
	n := len(s)
	// [Min] 先根据需要代理的 unicode 码点的个数计算出返回切片的长度
	for _, v := range s {
		if v >= surrSelf {
			n++
		}
	}

	a := make([]uint16, n)
	n = 0
	for _, v := range s {
		switch {
		case 0 <= v && v < surr1, surr3 <= v && v < surrSelf:
			// normal rune
			// [Min] 正常的直接按照 uint16 双字节转换即可
			a[n] = uint16(v)
			n++
		case surrSelf <= v && v <= maxRune:
			// needs surrogate sequence
			// [Min] 需要代理的码点，写入 uint16 类型的高低两个代理码点值
			r1, r2 := EncodeRune(v)
			a[n] = uint16(r1)
			a[n+1] = uint16(r2)
			n += 2
		default:
			// [Min] 其他写入 replacementChar
			a[n] = uint16(replacementChar)
			n++
		}
	}
	return a[:n]
}

// Decode returns the Unicode code point sequence represented
// by the UTF-16 encoding s.
// [Min] 将 UTF-16 解码为 unicode
func Decode(s []uint16) []rune {
	a := make([]rune, len(s))
	n := 0
	for i := 0; i < len(s); i++ {
		switch r := s[i]; {
		case r < surr1, surr3 <= r:
			// normal rune
			a[n] = rune(r)
		case surr1 <= r && r < surr2 && i+1 < len(s) &&
			surr2 <= s[i+1] && s[i+1] < surr3:
			// valid surrogate sequence
			a[n] = DecodeRune(rune(r), rune(s[i+1]))
			i++
		default:
			// invalid surrogate sequence
			a[n] = replacementChar
		}
		n++
	}
	return a[:n]
}
