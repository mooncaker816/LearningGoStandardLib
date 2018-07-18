// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package utf8 implements functions and constants to support text encoded in
// UTF-8. It includes functions to translate between runes and UTF-8 byte sequences.
package utf8

// The conditions RuneError==unicode.ReplacementChar and
// MaxRune==unicode.MaxRune are verified in the tests.
// Defining them locally avoids this package depending on package unicode.

// Numbers fundamental to the encoding.
const (
	RuneError = '\uFFFD'     // the "error" Rune or "Unicode replacement character"
	RuneSelf  = 0x80         // characters below Runeself are represented as themselves in a single byte.
	MaxRune   = '\U0010FFFF' // Maximum valid Unicode code point.
	UTFMax    = 4            // maximum number of bytes of a UTF-8 encoded Unicode character.
)

// Code points in the surrogate range are not valid for UTF-8.
const (
	surrogateMin = 0xD800
	surrogateMax = 0xDFFF
)

const (
	t1 = 0x00 // 0000 0000
	tx = 0x80 // 1000 0000
	t2 = 0xC0 // 1100 0000
	t3 = 0xE0 // 1110 0000
	t4 = 0xF0 // 1111 0000
	t5 = 0xF8 // 1111 1000

	maskx = 0x3F // 0011 1111
	mask2 = 0x1F // 0001 1111
	mask3 = 0x0F // 0000 1111
	mask4 = 0x07 // 0000 0111

	rune1Max = 1<<7 - 1
	rune2Max = 1<<11 - 1
	rune3Max = 1<<16 - 1

	// The default lowest and highest continuation byte.
	locb = 0x80 // 1000 0000
	hicb = 0xBF // 1011 1111

	// These names of these constants are chosen to give nice alignment in the
	// table below. The first nibble is an index into acceptRanges or F for
	// special one-byte cases. The second nibble is the Rune length or the
	// Status for the special one-byte case.
	xx = 0xF1 // invalid: size 1
	as = 0xF0 // ASCII: size 1
	s1 = 0x02 // accept 0, size 2
	s2 = 0x13 // accept 1, size 3
	s3 = 0x03 // accept 0, size 3
	s4 = 0x23 // accept 2, size 3
	s5 = 0x34 // accept 3, size 4
	s6 = 0x04 // accept 0, size 4
	s7 = 0x44 // accept 4, size 4
)

// [Min] Unicode 与 UTF-8 码点的对应关系，目前 UTF-8 码最长为4个字节（足够满足最大有效 unicode U+10FFFF），5，6两个字节已经弃用
// 码点的位数	码点起值	码点终值	字节序列	Byte 1				Byte 2		Byte 3		Byte 4		Byte 5		Byte 6
// 		7		 U+0000		 U+007F		    1		0xxxxxxx(0x00-0x7F)
// 		11		 U+0080		 U+07FF			2		110xxxxx(0xC2-0xDF)	10xxxxxx
// 		16		 U+0800		 U+FFFF			3		1110xxxx(0xE0-0xEF)	10xxxxxx	10xxxxxx
// 		21		 U+10000	 U+1FFFFF		4		11110xxx(0xF0-0xF7)	10xxxxxx	10xxxxxx	10xxxxxx
// 		26		 U+200000	 U+3FFFFFF		5		111110xx(0xF8-0xFB)	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx
// 		31		 U+4000000	 U+7FFFFFFF		6		1111110x(0xFC-0xFD)	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx	10xxxxxx
/* [Min]
1.	Unicode 码点值范围为0000 0000-0111 1111(0x00-0x7F)，
	UTF-8 对应单字节字符（128个ASCII码字符），首字节范围为0000 0000-0111 1111(0x00-0x7F)，与 Unicode 码点一致
2.	Unicode 码点值范围为0000 0000 1000 0000 - 0000 0111 1111 1111(0x80-0x07FF)，
	UTF-8 对应双字节字符，首字节范围为1100 0010-1101 1111(0xC2-0xDF)，第二字节范围为1000 0000-1011 1111(0x80-0xBF)
3.	Unicode 码点值范围为0000 1000 0000 0000 - 1111 1111 1111 1111(0x800-0xFFFF)，
	其中1101 1000 0000 0000 - 1101 1111 1111 1111(0xD800-0xDFFF) 为代理码点，不能单独作为一个有效的 unicode，需要排除
	Unicode 有效范围为 0000 1000 0000 0000 - 1101 0111 1111 1111(0x800-0xD7FF)
					   1110 0000 0000 0000 - 1111 1111 1111 1111(0xE000-0xFFFF)
	UTF-8 对应三字节字符，首字节范围为1110 0000-1110 1101(0xE0-0xED)，
									  1110 1110-1110 1111(0xEE-0xEF)
	当首字节为1110 0000(0xE0)时，第二字节范围为1010 0000-1011 1111(0xA0-0xBF)
	当首字节为1110 0001-1110 1100(0xE1-0xEC)时，第二字节范围为1000 0000-1011 1111(0x80-0xBF)
	当首字节为1110 1101(0xED)时，第二字节范围为1000 0000-1001 1111(0x80-0x9F)
	当首字节为1110 1110-1110 1111(0xEE-0xEF)时，第二字节范围为1000 0000-1011 1111(0x80-0xBF)
	第三字节总是1000 0000-1011 1111(0x80-0xBF)
4.	Unicode 码点值范围为0001 0000 0000 0000 0000 - 0001 1111 1111 1111 1111 1111(0x10000 - 0x1FFFFF)
	其中0x110000-0x1FFFF为无效字符，需排除
	Unicode 有效范围为0001 0000 0000 0000 0000 - 0001 0000 1111 1111 1111 1111(0x10000 - 0x10FFFF)
	UTF-8 对应四字节字符，首字节范围为1111 0000 - 1111 0100(0xF0-0xF4)，
	当首字节为1111 0000(0xF0)时，第二字节范围为1001 0000 - 1011 1111(0x90-0xBF)
	当首字节为1111 0001-1111 0011(0xF1-0xF3)时，第二字节范围为1000 0000-1011 1111(0x80-0xBF)
	当首字节为1111 0100(0xF4)时，第二字节范围为1000 0000-1000 1111(0x80-0x8F)
	第三，四字节范围均为1000 0000-1011 1111(0x80-0xBF)
*/

// [Min] UTF-8 中首字节信息，
// [Min] 如果是 as，代表该字节为单字节 UTF-8 码（ASCII 码）
// [Min] 如果是 xx，代表该字节为无效 UTF-8 首字节
// [Min] 如果是 s1-7，其低四位代表该 UTF-8 码的字节数，高四位代表第二字节的有效取值范围在 acceptRange 中的索引
// first is information about the first byte in a UTF-8 sequence.
var first = [256]uint8{
	//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x00-0x0F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x10-0x1F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x20-0x2F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x30-0x3F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x40-0x4F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x50-0x5F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x60-0x6F
	as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, as, // 0x70-0x7F
	//   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x80-0x8F
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0x90-0x9F
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xA0-0xAF
	xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xB0-0xBF
	xx, xx, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, // 0xC0-0xCF
	s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, s1, // 0xD0-0xDF
	s2, s3, s3, s3, s3, s3, s3, s3, s3, s3, s3, s3, s3, s4, s3, s3, // 0xE0-0xEF
	s5, s6, s6, s6, s7, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, xx, // 0xF0-0xFF
}

// acceptRange gives the range of valid values for the second byte in a UTF-8
// sequence.
type acceptRange struct {
	lo uint8 // lowest value for second byte.
	hi uint8 // highest value for second byte.
}

var acceptRanges = [...]acceptRange{
	0: {locb, hicb},
	1: {0xA0, hicb},
	2: {locb, 0x9F},
	3: {0x90, hicb},
	4: {locb, 0x8F},
}

// FullRune reports whether the bytes in p begin with a full UTF-8 encoding of a rune.
// An invalid encoding is considered a full Rune since it will convert as a width-1 error rune.
// [Min] 检查 p 是否是以一个完整长度的 UTF-8 码开头，如果无效字节开头，也认为是真
func FullRune(p []byte) bool {
	n := len(p)
	if n == 0 {
		return false
	}
	x := first[p[0]]
	// [Min] x&7 以 x 开头的 utf-8 码可能的字节长度
	// [Min] 其中0代表 ascii，1为无效，2，3，4为多字节 utf-8码
	// [Min] 因为 n 至少为1，所以当 x 为 ascii 码时，总是返回 true
	// [Min] 当 x 为无效字节时，也默认返回 true，因为该字节会转为对应的 RuneError（三字节）
	// [Min]
	if n >= int(x&7) {
		return true // ASCII, invalid or valid.
	}
	// [Min] 此时 n 的范围为 1<n<4，且 n 小于首字节中标明的 utf-8 字节数
	// [Min] 这种情况只有当第二或第三字节无效才返回真
	// Must be short or invalid.
	accept := acceptRanges[x>>4]
	if n > 1 && (p[1] < accept.lo || accept.hi < p[1]) {
		return true
	} else if n > 2 && (p[2] < locb || hicb < p[2]) {
		return true
	}
	return false
}

// FullRuneInString is like FullRune but its input is a string.
// [Min] 和 FullRune 类似
func FullRuneInString(s string) bool {
	n := len(s)
	if n == 0 {
		return false
	}
	x := first[s[0]]
	if n >= int(x&7) {
		return true // ASCII, invalid, or valid.
	}
	// Must be short or invalid.
	accept := acceptRanges[x>>4]
	if n > 1 && (s[1] < accept.lo || accept.hi < s[1]) {
		return true
	} else if n > 2 && (s[2] < locb || hicb < s[2]) {
		return true
	}
	return false
}

// DecodeRune unpacks the first UTF-8 encoding in p and returns the rune and
// its width in bytes. If p is empty it returns (RuneError, 0). Otherwise, if
// the encoding is invalid, it returns (RuneError, 1). Both are impossible
// results for correct, non-empty UTF-8.
//
// An encoding is invalid if it is incorrect UTF-8, encodes a rune that is
// out of range, or is not the shortest possible UTF-8 encoding for the
// value. No other validation is performed.
// [Min] 从 p 中解码第一个 UTF-8 字符，
// [Min] 如果 p 为空，返回 RuneError，0
// [Min] 如果 p 开头无法解码出一个有效的 UTF-8 字符，返回 RuneError，1
// [Min] 如果 p 开头能够解码出一个有效的 UTF-8 字符，返回 UTF-8 对应的 rune，并且返回原 UTF-8 的字节长度
func DecodeRune(p []byte) (r rune, size int) {
	n := len(p)
	if n < 1 {
		return RuneError, 0
	}
	p0 := p[0]
	x := first[p0]
	// [Min] x > as，说明 p0 为 ascii 码或无效首字节
	// [Min] 如果为 ascii 码，x = 0xF0，mask = 0x0000，
	// [Min] rune(p[0])&^mask 仍为 rune(p[0])，RuneError&mask 为 0，
	// [Min] 最终或运算仍为 rune(p[0])，满足期望返回
	// [Min] 如果为无效首字节，x = 0xF1，mask = 0xFFFF，
	// [Min] rune(p[0])&^mask 为 0，RuneError&mask 仍为 RuneError，
	// [Min] 最终或运算仍为 RuneError，满足期望返回
	if x >= as {
		// The following code simulates an additional check for x == xx and
		// handling the ASCII and invalid cases accordingly. This mask-and-or
		// approach prevents an additional branch.
		mask := rune(x) << 31 >> 31 // Create 0x0000 or 0xFFFF.
		return rune(p[0])&^mask | RuneError&mask, 1
	}
	// [Min] 多字节 UTF-8 码处理，先获取字节数 sz，以及第二字节有效范围 accept
	sz := x & 7
	accept := acceptRanges[x>>4]
	// [Min] 如果 p 的长度不够 sz，则无法解码，返回 RuneError，1
	if n < int(sz) {
		return RuneError, 1
	}
	// [Min] 获取第二字节，比较是否在有效范围 accept 内，否返回 RuneError，1
	b1 := p[1]
	if b1 < accept.lo || accept.hi < b1 {
		return RuneError, 1
	}
	// [Min] 如果是双字节，且第二字节有效，则依次拼接以下两组六位二进制即所求 unicode
	// [Min] 取第一个字节的后5位（p0&mask2）构成 unicode 中的第一组六位二进制
	// [Min] 取第二个字节的后6位（b1&maskx）构成 unicode 中的第二组六位二进制
	if sz == 2 {
		return rune(p0&mask2)<<6 | rune(b1&maskx), 2
	}
	// [Min] 取第三个字节，比较是否在有效范围 locb - hicb 中，否返回 RuneError，1
	b2 := p[2]
	if b2 < locb || hicb < b2 {
		return RuneError, 1
	}
	// [Min] 如果是三字节，且前两个字节都有效，则依次拼接以下三组六位二进制即所求 unicode
	// [Min] 取第一字节的后4位（p0&mask3）构成 unicode 中的第一组六位二进制
	// [Min] 取第二字节的后6位（b1&maskx）构成 unicode 中的第二组六位二进制
	// [Min] 取第三字节的后6位（b2&maskx）构成 unicode 中的第三组六位二进制
	if sz == 3 {
		return rune(p0&mask3)<<12 | rune(b1&maskx)<<6 | rune(b2&maskx), 3
	}
	// [Min] 取第四个字节，比较是否在有效范围 locb - hicb 中，否返回 RuneError，1
	b3 := p[3]
	if b3 < locb || hicb < b3 {
		return RuneError, 1
	}
	// [Min] 依次拼接以下四组六位二进制即所求 unicode
	// [Min] 取第一字节的后3位（p0&mask4）构成 unicode 中的第一组六位二进制
	// [Min] 取第二字节的后6位（b1&maskx）构成 unicode 中的第二组六位二进制
	// [Min] 取第三字节的后6位（b2&maskx）构成 unicode 中的第三组六位二进制
	// [Min] 取第四字节的后6位（b3&maskx）构成 unicode 中的第四组六位二进制
	return rune(p0&mask4)<<18 | rune(b1&maskx)<<12 | rune(b2&maskx)<<6 | rune(b3&maskx), 4
}

// DecodeRuneInString is like DecodeRune but its input is a string. If s is
// empty it returns (RuneError, 0). Otherwise, if the encoding is invalid, it
// returns (RuneError, 1). Both are impossible results for correct, non-empty
// UTF-8.
//
// An encoding is invalid if it is incorrect UTF-8, encodes a rune that is
// out of range, or is not the shortest possible UTF-8 encoding for the
// value. No other validation is performed.
// [Min] 与 DecodeRune 类似
func DecodeRuneInString(s string) (r rune, size int) {
	n := len(s)
	if n < 1 {
		return RuneError, 0
	}
	s0 := s[0]
	x := first[s0]
	if x >= as {
		// The following code simulates an additional check for x == xx and
		// handling the ASCII and invalid cases accordingly. This mask-and-or
		// approach prevents an additional branch.
		mask := rune(x) << 31 >> 31 // Create 0x0000 or 0xFFFF.
		return rune(s[0])&^mask | RuneError&mask, 1
	}
	sz := x & 7
	accept := acceptRanges[x>>4]
	if n < int(sz) {
		return RuneError, 1
	}
	s1 := s[1]
	if s1 < accept.lo || accept.hi < s1 {
		return RuneError, 1
	}
	if sz == 2 {
		return rune(s0&mask2)<<6 | rune(s1&maskx), 2
	}
	s2 := s[2]
	if s2 < locb || hicb < s2 {
		return RuneError, 1
	}
	if sz == 3 {
		return rune(s0&mask3)<<12 | rune(s1&maskx)<<6 | rune(s2&maskx), 3
	}
	s3 := s[3]
	if s3 < locb || hicb < s3 {
		return RuneError, 1
	}
	return rune(s0&mask4)<<18 | rune(s1&maskx)<<12 | rune(s2&maskx)<<6 | rune(s3&maskx), 4
}

// DecodeLastRune unpacks the last UTF-8 encoding in p and returns the rune and
// its width in bytes. If p is empty it returns (RuneError, 0). Otherwise, if
// the encoding is invalid, it returns (RuneError, 1). Both are impossible
// results for correct, non-empty UTF-8.
//
// An encoding is invalid if it is incorrect UTF-8, encodes a rune that is
// out of range, or is not the shortest possible UTF-8 encoding for the
// value. No other validation is performed.
// [Min] 尝试从 p 的末尾解码一个 UTF-8 码
func DecodeLastRune(p []byte) (r rune, size int) {
	end := len(p)
	if end == 0 {
		return RuneError, 0
	}
	start := end - 1
	// [Min] 如果最后一个字节是 ASCII 码，直接返回 r
	r = rune(p[start])
	if r < RuneSelf {
		return r, 1
	}
	// guard against O(n^2) behavior when traversing
	// backwards through strings with long sequences of
	// invalid UTF-8.
	// [Min] 获取向上查找最后一个 UTF-8 码的起始字节的最小起始位置
	lim := end - UTFMax
	if lim < 0 {
		lim = 0
	}
	for start--; start >= lim; start-- {
		// [Min] 从形式上看，该字节是否可能是 UTF-8 的首字节（不是10xxxxxx的形式）
		if RuneStart(p[start]) {
			break
		}
	}
	if start < 0 {
		start = 0
	}
	// [Min] 调用 DecodeRune 进行解码
	r, size = DecodeRune(p[start:end])
	if start+size != end {
		return RuneError, 1
	}
	return r, size
}

// DecodeLastRuneInString is like DecodeLastRune but its input is a string. If
// s is empty it returns (RuneError, 0). Otherwise, if the encoding is invalid,
// it returns (RuneError, 1). Both are impossible results for correct,
// non-empty UTF-8.
//
// An encoding is invalid if it is incorrect UTF-8, encodes a rune that is
// out of range, or is not the shortest possible UTF-8 encoding for the
// value. No other validation is performed.
// [Min] 与 DecodeLastRune 类似
func DecodeLastRuneInString(s string) (r rune, size int) {
	end := len(s)
	if end == 0 {
		return RuneError, 0
	}
	start := end - 1
	r = rune(s[start])
	if r < RuneSelf {
		return r, 1
	}
	// guard against O(n^2) behavior when traversing
	// backwards through strings with long sequences of
	// invalid UTF-8.
	lim := end - UTFMax
	if lim < 0 {
		lim = 0
	}
	for start--; start >= lim; start-- {
		if RuneStart(s[start]) {
			break
		}
	}
	if start < 0 {
		start = 0
	}
	r, size = DecodeRuneInString(s[start:end])
	if start+size != end {
		return RuneError, 1
	}
	return r, size
}

// RuneLen returns the number of bytes required to encode the rune.
// It returns -1 if the rune is not a valid value to encode in UTF-8.
// [Min] 返回 rune 对应的 UTF-8 码的字节数，如果 rune 无效，返回-1
func RuneLen(r rune) int {
	switch {
	case r < 0:
		return -1
	case r <= rune1Max:
		// [Min] 00000000 00000000 0zzzzzzz => 0zzzzzzz 单字节 UTF-8（ASCII 码）
		return 1
	case r <= rune2Max:
		// [Min] 00000000 00000yyy yyzzzzzz => 110yyyyy 10zzzzzz 双字节 UTF-8
		return 2
	case surrogateMin <= r && r <= surrogateMax:
		// [Min] 代理码点，无效 unicode
		return -1
	case r <= rune3Max:
		// [Min] 00000000 xxxxyyyy yyzzzzzz => 1110xxxx 10yyyyyy 10zzzzzz 三字节 UTF-8
		return 3
	case r <= MaxRune:
		// [Min] 000wwwxx xxxxyyyy yyzzzzzz => 11110www 10xxxxxx 10yyyyyy 10zzzzzz 四字节 UTF-8
		return 4
	}
	return -1
}

// EncodeRune writes into p (which must be large enough) the UTF-8 encoding of the rune.
// It returns the number of bytes written.
// [Min] 将 unicode 编码为 UTF-8 码，返回 UTF-8 的长度，
// [Min] 如果 unicdoe 无效，写入 \uFFFD 对应的 UTF-8 码，代表 unicode 错误
func EncodeRune(p []byte, r rune) int {
	// Negative values are erroneous. Making it unsigned addresses the problem.
	switch i := uint32(r); {
	case i <= rune1Max:
		// [Min] 单字节 UTF-8，直接转为 byte 写入，返回1
		p[0] = byte(r)
		return 1
	case i <= rune2Max:
		// [Min] 双字节 UTF-8
		_ = p[1] // eliminate bounds checks
		p[0] = t2 | byte(r>>6)
		p[1] = tx | byte(r)&maskx
		return 2
	case i > MaxRune, surrogateMin <= i && i <= surrogateMax:
		r = RuneError
		fallthrough
	case i <= rune3Max:
		_ = p[2] // eliminate bounds checks
		p[0] = t3 | byte(r>>12)
		p[1] = tx | byte(r>>6)&maskx
		p[2] = tx | byte(r)&maskx
		return 3
	default:
		_ = p[3] // eliminate bounds checks
		p[0] = t4 | byte(r>>18)
		p[1] = tx | byte(r>>12)&maskx
		p[2] = tx | byte(r>>6)&maskx
		p[3] = tx | byte(r)&maskx
		return 4
	}
}

// RuneCount returns the number of runes in p. Erroneous and short
// encodings are treated as single runes of width 1 byte.
// [Min] 返回以 UTF-8 编码的 p 中有多少个 unicode，无效的或者长度不够的均当成1个 unicode
func RuneCount(p []byte) int {
	np := len(p)
	var n int
	for i := 0; i < np; {
		n++
		c := p[i]
		if c < RuneSelf {
			// ASCII fast path
			i++
			continue
		}
		x := first[c]
		if x == xx {
			i++ // invalid.
			continue
		}
		size := int(x & 7)
		if i+size > np {
			i++ // Short or invalid.
			continue
		}
		accept := acceptRanges[x>>4]
		if c := p[i+1]; c < accept.lo || accept.hi < c {
			size = 1
		} else if size == 2 {
		} else if c := p[i+2]; c < locb || hicb < c {
			size = 1
		} else if size == 3 {
		} else if c := p[i+3]; c < locb || hicb < c {
			size = 1
		}
		i += size
	}
	return n
}

// RuneCountInString is like RuneCount but its input is a string.
// [Min] 与 RuneCount 类似
func RuneCountInString(s string) (n int) {
	ns := len(s)
	for i := 0; i < ns; n++ {
		c := s[i]
		if c < RuneSelf {
			// ASCII fast path
			i++
			continue
		}
		x := first[c]
		if x == xx {
			i++ // invalid.
			continue
		}
		size := int(x & 7)
		if i+size > ns {
			i++ // Short or invalid.
			continue
		}
		accept := acceptRanges[x>>4]
		if c := s[i+1]; c < accept.lo || accept.hi < c {
			size = 1
		} else if size == 2 {
		} else if c := s[i+2]; c < locb || hicb < c {
			size = 1
		} else if size == 3 {
		} else if c := s[i+3]; c < locb || hicb < c {
			size = 1
		}
		i += size
	}
	return n
}

// RuneStart reports whether the byte could be the first byte of an encoded,
// possibly invalid rune. Second and subsequent bytes always have the top two
// bits set to 10.
// [Min] 仅从形式上看，不以10为高两位的字节，可以作为 UTF-8 的首字节（不是10xxxxxx的形式）
// [Min] 但究竟有效与否，还要进一步对照 first 表分析，这个工作在 DecodeRune 中会进行
func RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// Valid reports whether p consists entirely of valid UTF-8-encoded runes.
// [Min] 判断 p 中是否都是有效的 UTF-8 码
func Valid(p []byte) bool {
	n := len(p)
	for i := 0; i < n; {
		pi := p[i]
		if pi < RuneSelf {
			i++
			continue
		}
		x := first[pi]
		if x == xx {
			return false // Illegal starter byte.
		}
		size := int(x & 7)
		if i+size > n {
			return false // Short or invalid.
		}
		accept := acceptRanges[x>>4]
		if c := p[i+1]; c < accept.lo || accept.hi < c {
			return false
		} else if size == 2 {
		} else if c := p[i+2]; c < locb || hicb < c {
			return false
		} else if size == 3 {
		} else if c := p[i+3]; c < locb || hicb < c {
			return false
		}
		i += size
	}
	return true
}

// ValidString reports whether s consists entirely of valid UTF-8-encoded runes.
// [Min] 与 Valid 类似
func ValidString(s string) bool {
	n := len(s)
	for i := 0; i < n; {
		si := s[i]
		if si < RuneSelf {
			i++
			continue
		}
		x := first[si]
		if x == xx {
			return false // Illegal starter byte.
		}
		size := int(x & 7)
		if i+size > n {
			return false // Short or invalid.
		}
		accept := acceptRanges[x>>4]
		if c := s[i+1]; c < accept.lo || accept.hi < c {
			return false
		} else if size == 2 {
		} else if c := s[i+2]; c < locb || hicb < c {
			return false
		} else if size == 3 {
		} else if c := s[i+3]; c < locb || hicb < c {
			return false
		}
		i += size
	}
	return true
}

// ValidRune reports whether r can be legally encoded as UTF-8.
// Code points that are out of range or a surrogate half are illegal.
// [Min] 判断 r 是否有有效的 UTF-8 码与之对应，
// [Min] 代理码点不能单独作为有效的 unicode 码点
func ValidRune(r rune) bool {
	switch {
	case 0 <= r && r < surrogateMin:
		return true
	case surrogateMax < r && r <= MaxRune:
		return true
	}
	return false
}
