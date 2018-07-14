// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import (
	"bytes"
	"unicode/utf8"
)

const (
	caseMask     = ^byte(0x20) // Mask to ignore case in ASCII.
	kelvin       = '\u212a'
	smallLongEss = '\u017f'
)

// foldFunc returns one of four different case folding equivalence
// functions, from most general (and slow) to fastest:
//
// 1) bytes.EqualFold, if the key s contains any non-ASCII UTF-8
// 2) equalFoldRight, if s contains special folding ASCII ('k', 'K', 's', 'S')
// 3) asciiEqualFold, no special, but includes non-letters (including _)
// 4) simpleLetterEqualFold, no specials, no non-letters.
//
// The letters S and K are special because they map to 3 runes, not just 2:
//  * S maps to s and to U+017F 'ſ' Latin small letter long s
//  * k maps to K and to U+212A 'K' Kelvin sign
// See https://play.golang.org/p/tTxjOc0OGo
//
// The returned function is specialized for matching against s and
// should only be given s. It's not curried for performance reasons.
// [Min] 当 s 含有非单字节 utf8 字符时，返回bytes.EqualFold
// [Min] 当 s 全是单字节utf8 字符，但含有特殊字母 k，s，K，S返回equalFoldRight
// [Min] 当 s 全是单字节utf8 字符且含有非字母，且不含 k,s,K,S,返回asciiEqualFold
// [Min] 当 s 全是单字节utf8 字符且全是字母，且不含 k,s,K,S,返回simpleLetterEqualFold
// [Min] 以上返回的比较函数执行速度依次递增
func foldFunc(s []byte) func(s, t []byte) bool {
	nonLetter := false
	special := false // special letter
	for _, b := range s {
		if b >= utf8.RuneSelf {
			return bytes.EqualFold
		}
		// [Min] 如果是字母，会返回大写字母，如果返回的不是大写字母，说明有非字母
		upper := b & caseMask
		if upper < 'A' || upper > 'Z' {
			nonLetter = true
		} else if upper == 'K' || upper == 'S' {
			// [Min] 如果全是字母，但是为K或S ，则记为 special 字符
			// See above for why these letters are special.
			special = true
		}
	}
	// [Min] 还有k,s返回equalFoldRight
	if special {
		return equalFoldRight
	}
	// [Min] 含有非字母，返回asciiEqualFold
	if nonLetter {
		return asciiEqualFold
	}
	return simpleLetterEqualFold
}

// equalFoldRight is a specialization of bytes.EqualFold when s is
// known to be all ASCII (including punctuation), but contains an 's',
// 'S', 'k', or 'K', requiring a Unicode fold on the bytes in t.
// See comments on foldFunc.
// [Min] 已知 s 中全是字母且包含 k,s,K,S 中的至少一种，用来和 t 比较是否等价
// [Min] 会忽略大小写，和 k，s 对应的特殊字符
func equalFoldRight(s, t []byte) bool {
	for _, sb := range s {
		// [Min] t已经完了而 s 还没完，不一致
		if len(t) == 0 {
			return false
		}
		tb := t[0]
		// [Min] 如果目标字符也是utf8单字节字符，说明不会是特殊多字节字符，
		// [Min] 如果相等，直接下一个比较，
		// [Min] 如果不等，如果是字母的话，忽略大小写比较
		if tb < utf8.RuneSelf {
			if sb != tb {
				sbUpper := sb & caseMask
				if 'A' <= sbUpper && sbUpper <= 'Z' {
					if sbUpper != tb&caseMask {
						return false
					}
				} else {
					return false
				}
			}
			t = t[1:]
			continue
		}
		// sb is ASCII and t is not. t must be either kelvin
		// sign or long s; sb must be s, S, k, or K.
		// [Min] 如果目标字符不是单字节 utf8字符，先解码得到对应的 unicode 码值
		// [Min] 如果源字符是 s，S，则解码的值必须和smallLongEss相等
		// [Min] 如果源字符是 k，K，则解码的值必须和kelvin相等
		// [Min] 其他源字符，返回 false
		tr, size := utf8.DecodeRune(t)
		switch sb {
		case 's', 'S':
			if tr != smallLongEss {
				return false
			}
		case 'k', 'K':
			if tr != kelvin {
				return false
			}
		default:
			return false
		}
		t = t[size:]

	}
	// [Min] 如果 t 还有剩余，不一致
	if len(t) > 0 {
		return false
	}
	return true
}

// asciiEqualFold is a specialization of bytes.EqualFold for use when
// s is all ASCII (but may contain non-letters) and contains no
// special-folding letters.
// See comments on foldFunc.
// [Min] 已知 s 全是单字节 utf8 字符且含有非字母，比较s 和 t 是否一致
func asciiEqualFold(s, t []byte) bool {
	// [Min] 长度必须相同
	if len(s) != len(t) {
		return false
	}
	for i, sb := range s {
		tb := t[i]
		// [Min] 直接相等，继续下一个比较
		if sb == tb {
			continue
		}
		// [Min] 不等，如果是字母的话，忽略大小写看是否相等
		if ('a' <= sb && sb <= 'z') || ('A' <= sb && sb <= 'Z') {
			if sb&caseMask != tb&caseMask {
				return false
			}
		} else {
			return false
		}
	}
	return true
}

// simpleLetterEqualFold is a specialization of bytes.EqualFold for
// use when s is all ASCII letters (no underscores, etc) and also
// doesn't contain 'k', 'K', 's', or 'S'.
// See comments on foldFunc.
// [Min] 全字母比较，不含k,s,K,S
func simpleLetterEqualFold(s, t []byte) bool {
	if len(s) != len(t) {
		return false
	}
	for i, b := range s {
		if b&caseMask != t[i]&caseMask {
			return false
		}
	}
	return true
}
