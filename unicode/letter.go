// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package unicode provides data and functions to test some properties of
// Unicode code points.
package unicode

// Tables are regenerated each time we update the Unicode version.
//go:generate go run maketables.go -tables=all -output tables.go

const (
	MaxRune         = '\U0010FFFF' // Maximum valid Unicode code point.
	ReplacementChar = '\uFFFD'     // Represents invalid code points.
	MaxASCII        = '\u007F'     // maximum ASCII value.
	MaxLatin1       = '\u00FF'     // maximum Latin-1 value.
)

// [Min] Unicode 码点分布情况
// 	平面		始末字符值			中文名称							英文名称
// 0号平面	U+0000 - U+FFFF		基本多文种平面				Basic Multilingual Plane，简称BMP
// 1号平面	U+10000 - U+1FFFF	多文种补充平面				Supplementary Multilingual Plane，简称SMP
// 2号平面	U+20000 - U+2FFFF	表意文字补充平面			Supplementary Ideographic Plane，简称SIP
// 3号平面	U+30000 - U+3FFFF	表意文字第三平面			Tertiary Ideographic Plane，简称TIP
// 4号平面
// 至
// 13号平面	U+40000 - U+DFFFF	（尚未使用）
// 14号平面	U+E0000 - U+EFFFF	特别用途补充平面			Supplementary Special-purpose Plane，简称SSP
// 15号平面	U+F0000 - U+FFFFF	保留作为私人使用区（A区）	Private Use Area-A，简称PUA-A
// 16号平面	U+100000 - U+10FFFF	保留作为私人使用区（B区）	Private Use Area-B，简称PUA-B

// RangeTable defines a set of Unicode code points by listing the ranges of
// code points within the set. The ranges are listed in two slices
// to save space: a slice of 16-bit ranges and a slice of 32-bit ranges.
// The two slices must be in sorted order and non-overlapping.
// Also, R32 should contain only values >= 0x10000 (1<<16).
// [Min] RangeTable 包含了16位和32位的 unicode 码点范围，
// [Min] LatinOffset 表示 R16 中有多少个范围是不超过MaxLatin1
type RangeTable struct {
	R16         []Range16
	R32         []Range32
	LatinOffset int // number of entries in R16 with Hi <= MaxLatin1
}

// Range16 represents of a range of 16-bit Unicode code points. The range runs from Lo to Hi
// inclusive and has the specified stride.
// [Min] 一组16位 unicode 码点的取值范围，stride 为本范围内两个码点的差值
// [Min] 一般来说 unicode 码点值都是加1加1这样连续排下去的，
// [Min] 但是有时需要将码点值不连续的 unicode 按某一性质划归到同一范围内，Stride就是起到了这个作用
// [Min] 如Range16{0x00ad, 0x0600, 1363},其实只有两个码点
type Range16 struct {
	Lo     uint16
	Hi     uint16
	Stride uint16
}

// Range32 represents of a range of Unicode code points and is used when one or
// more of the values will not fit in 16 bits. The range runs from Lo to Hi
// inclusive and has the specified stride. Lo and Hi must always be >= 1<<16.
// [Min] 一组32位 unicode 码点的取值范围，stride 为本范围内两个码点的差值，码点最小值为1<<16
type Range32 struct {
	Lo     uint32
	Hi     uint32
	Stride uint32
}

// CaseRange represents a range of Unicode code points for simple (one
// code point to one code point) case conversion.
// The range runs from Lo to Hi inclusive, with a fixed stride of 1. Deltas
// are the number to add to the code point to reach the code point for a
// different case for that character. They may be negative. If zero, it
// means the character is in the corresponding case. There is a special
// case representing sequences of alternating corresponding Upper and Lower
// pairs. It appears with a fixed Delta of
//	{UpperLower, UpperLower, UpperLower}
// The constant UpperLower has an otherwise impossible delta value.
// [Min] 包含相同大小转换信息的一组码点（如大小写英文字母）
// [Min] Delta 中的数据分别为大写，小写，title 大写与该码点的差值，如果为0，说明该码点就是这种状态
// [Min] 当 Delta 是{UpperLower, UpperLower, UpperLower}时，（其中 UpperLower 为 MaxRune + 1，是一个无效的码点）
// [Min] 说明该范围内的码点由大写，小写交替排列，即 lo 为大写，lo+1为小写，后面依次类推
type CaseRange struct {
	Lo    uint32
	Hi    uint32
	Delta d
}

// SpecialCase represents language-specific case mappings such as Turkish.
// Methods of SpecialCase customize (by overriding) the standard mappings.
type SpecialCase []CaseRange

// BUG(r): There is no mechanism for full case folding, that is, for
// characters that involve multiple runes in the input or output.

// Indices into the Delta arrays inside CaseRanges for case mapping.
const (
	UpperCase = iota
	LowerCase
	TitleCase
	MaxCase
)

type d [MaxCase]rune // to make the CaseRanges text shorter

// If the Delta field of a CaseRange is UpperLower, it means
// this CaseRange represents a sequence of the form (say)
// Upper Lower Upper Lower.
const (
	UpperLower = MaxRune + 1 // (Cannot be a valid delta.)
)

// linearMax is the maximum size table for linear search for non-Latin1 rune.
// Derived by running 'go test -calibrate'.
// [Min] 当取值范围的个数小于等于18时，在搜索码点值大于MaxLatin1的 unicode 时，
// [Min] 会按顺序搜索每一个范围
const linearMax = 18

// is16 reports whether r is in the sorted slice of 16-bit ranges.
// [Min] 判断 r 是否在 ranges 中， ranges 为升序
// [Min] 当 r <= MaxLatin1 时，直接按顺序搜索每一个范围
// [Min] 当 r > MaxLatin1 时，如果待搜索的范围多余18个，则采用二分法搜索
func is16(ranges []Range16, r uint16) bool {
	if len(ranges) <= linearMax || r <= MaxLatin1 {
		for i := range ranges {
			range_ := &ranges[i]
			if r < range_.Lo {
				return false
			}
			if r <= range_.Hi {
				return range_.Stride == 1 || (r-range_.Lo)%range_.Stride == 0
			}
		}
		return false
	}

	// binary search over ranges
	// [Min] 二分法搜索
	lo := 0
	hi := len(ranges)
	for lo < hi {
		m := lo + (hi-lo)/2
		range_ := &ranges[m]
		if range_.Lo <= r && r <= range_.Hi {
			return range_.Stride == 1 || (r-range_.Lo)%range_.Stride == 0
		}
		if r < range_.Lo {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return false
}

// is32 reports whether r is in the sorted slice of 32-bit ranges.
// [Min] 同 is16
func is32(ranges []Range32, r uint32) bool {
	if len(ranges) <= linearMax {
		for i := range ranges {
			range_ := &ranges[i]
			if r < range_.Lo {
				return false
			}
			if r <= range_.Hi {
				return range_.Stride == 1 || (r-range_.Lo)%range_.Stride == 0
			}
		}
		return false
	}

	// binary search over ranges
	lo := 0
	hi := len(ranges)
	for lo < hi {
		m := lo + (hi-lo)/2
		range_ := ranges[m]
		if range_.Lo <= r && r <= range_.Hi {
			return range_.Stride == 1 || (r-range_.Lo)%range_.Stride == 0
		}
		if r < range_.Lo {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return false
}

// Is reports whether the rune is in the specified table of ranges.
// [Min] 判断 r 是否在 rangetable 中
func Is(rangeTab *RangeTable, r rune) bool {
	r16 := rangeTab.R16
	// [Min] 如果有 R16，并且 r 不超过 R16 中码点值最大的那组范围的最大码点值，
	// [Min] 说明 r 可能在这个 R16 中，调用 is16
	if len(r16) > 0 && r <= rune(r16[len(r16)-1].Hi) {
		return is16(r16, uint16(r))
	}
	r32 := rangeTab.R32
	// [Min] 如果 r 为32位 unicode，并且不比 R32 第一组范围的最小码点值小，
	// [Min] 说明 r 可能在 R32 中，调用 is32
	if len(r32) > 0 && r >= rune(r32[0].Lo) {
		return is32(r32, uint32(r))
	}
	return false
}

// [Min] 排除 rangetable 中所有 <= MaxLatin1 的码点后，判断 r 是否在该范围内
func isExcludingLatin(rangeTab *RangeTable, r rune) bool {
	r16 := rangeTab.R16
	if off := rangeTab.LatinOffset; len(r16) > off && r <= rune(r16[len(r16)-1].Hi) {
		return is16(r16[off:], uint16(r))
	}
	r32 := rangeTab.R32
	if len(r32) > 0 && r >= rune(r32[0].Lo) {
		return is32(r32, uint32(r))
	}
	return false
}

// IsUpper reports whether the rune is an upper case letter.
// [Min] 判断 r 是否为大写
func IsUpper(r rune) bool {
	// See comment in IsGraphic.
	// [Min] 如果 r <= MaxLatin1, 获取 properties 中预先定义好的所有小于等于MaxLatin1的码点的属性
	// [Min] 不同属性与 bit 位有关，只需要比较关注属性对应的 bit 位即可
	// [Min] 属性定义见 graphic.go
	if uint32(r) <= MaxLatin1 {
		return properties[uint8(r)]&pLmask == pLu
	}
	// [Min] 如果 r > MaxLatin1，在所有大写字符集 Upper 中查找
	return isExcludingLatin(Upper, r)
}

// IsLower reports whether the rune is a lower case letter.
// [Min] 判断 r 是否为小写
func IsLower(r rune) bool {
	// See comment in IsGraphic.
	if uint32(r) <= MaxLatin1 {
		return properties[uint8(r)]&pLmask == pLl
	}
	return isExcludingLatin(Lower, r)
}

// IsTitle reports whether the rune is a title case letter.
// [Min] 判断 r 是否为 title case 字符
func IsTitle(r rune) bool {
	if r <= MaxLatin1 {
		return false
	}
	return isExcludingLatin(Title, r)
}

// to maps the rune using the specified case mapping.
// [Min] 根据 caseRange，将 r 转为对应 case 的 unicode 码点
func to(_case int, r rune, caseRange []CaseRange) rune {
	if _case < 0 || MaxCase <= _case {
		return ReplacementChar // as reasonable an error as any
	}
	// binary search over ranges
	lo := 0
	hi := len(caseRange)
	for lo < hi {
		m := lo + (hi-lo)/2
		cr := caseRange[m]
		if rune(cr.Lo) <= r && r <= rune(cr.Hi) {
			// [Min] 获取对应 case 的 delta，如果超过 MaxRune，说明该范围由大小写对组成
			// [Min] UpperCase 和 TitleCase 对应的 case 索引为0，2，LowerCase 对应的 case 索引为1
			// [Min] 且 CaseRange 中 UpperCase 的码点落在偶数位，LowerCase 码点落在奇数位
			// [Min] 所以只需要根据 case 的奇偶来判断取奇数位还是偶数位的码点
			delta := cr.Delta[_case]
			if delta > MaxRune {
				// In an Upper-Lower sequence, which always starts with
				// an UpperCase letter, the real deltas always look like:
				//	{0, 1, 0}    UpperCase (Lower is next)
				//	{-1, 0, -1}  LowerCase (Upper, Title are previous)
				// The characters at even offsets from the beginning of the
				// sequence are upper case; the ones at odd offsets are lower.
				// The correct mapping can be done by clearing or setting the low
				// bit in the sequence offset.
				// The constants UpperCase and TitleCase are even while LowerCase
				// is odd so we take the low bit from _case.
				return rune(cr.Lo) + ((r-rune(cr.Lo))&^1 | rune(_case&1))
			}
			return r + delta
		}
		if r < rune(cr.Lo) {
			hi = m
		} else {
			lo = m + 1
		}
	}
	return r
}

// To maps the rune to the specified case: UpperCase, LowerCase, or TitleCase.
// [Min] 将 r 转为对应 case 的 unicode 码点
func To(_case int, r rune) rune {
	return to(_case, r, CaseRanges)
}

// ToUpper maps the rune to upper case.
// [Min] 将 r 转为大写
func ToUpper(r rune) rune {
	if r <= MaxASCII {
		if 'a' <= r && r <= 'z' {
			r -= 'a' - 'A'
		}
		return r
	}
	return To(UpperCase, r)
}

// ToLower maps the rune to lower case.
// [Min] 将 r 转为小写
func ToLower(r rune) rune {
	if r <= MaxASCII {
		if 'A' <= r && r <= 'Z' {
			r += 'a' - 'A'
		}
		return r
	}
	return To(LowerCase, r)
}

// ToTitle maps the rune to title case.
// [Min] 将 r 转为 Title case
func ToTitle(r rune) rune {
	if r <= MaxASCII {
		if 'a' <= r && r <= 'z' { // title case is upper case for ASCII
			r -= 'a' - 'A'
		}
		return r
	}
	return To(TitleCase, r)
}

// ToUpper maps the rune to upper case giving priority to the special mapping.
// [Min] 优先根据 SpecialCase 中的特殊转换配置将 r 转为大写，找不到再用常规 ToUpper 转
func (special SpecialCase) ToUpper(r rune) rune {
	r1 := to(UpperCase, r, []CaseRange(special))
	if r1 == r {
		r1 = ToUpper(r)
	}
	return r1
}

// ToTitle maps the rune to title case giving priority to the special mapping.
// [Min] 优先根据 SpecialCase 中的特殊转换配置将 r 转为title case，找不到再用常规 ToTitle 转
func (special SpecialCase) ToTitle(r rune) rune {
	r1 := to(TitleCase, r, []CaseRange(special))
	if r1 == r {
		r1 = ToTitle(r)
	}
	return r1
}

// ToLower maps the rune to lower case giving priority to the special mapping.
// [Min] 优先根据 SpecialCase 中的特殊转换配置将 r 转为小写，找不到再用常规 ToLower 转
func (special SpecialCase) ToLower(r rune) rune {
	r1 := to(LowerCase, r, []CaseRange(special))
	if r1 == r {
		r1 = ToLower(r)
	}
	return r1
}

// caseOrbit is defined in tables.go as []foldPair. Right now all the
// entries fit in uint16, so use uint16. If that changes, compilation
// will fail (the constants in the composite literal will not fit in uint16)
// and the types here can change to uint32.
type foldPair struct {
	From uint16
	To   uint16
}

// SimpleFold iterates over Unicode code points equivalent under
// the Unicode-defined simple case folding. Among the code points
// equivalent to rune (including rune itself), SimpleFold returns the
// smallest rune > r if one exists, or else the smallest rune >= 0.
// If r is not a valid Unicode code point, SimpleFold(r) returns r.
//
// For example:
//	SimpleFold('A') = 'a'
//	SimpleFold('a') = 'A'
//
//	SimpleFold('K') = 'k'
//	SimpleFold('k') = '\u212A' (Kelvin symbol, K)
//	SimpleFold('\u212A') = 'K'
//
//	SimpleFold('1') = '1'
//
//	SimpleFold(-2) = -2
//
// [Min] 如果 r 存在等价字符，优先将 r 转为比 r 大的最小的那个，否则转为最小的那个
// [Min] 等价规则由asciiFold，caseOrbit绝定，asciiFold 中直接给出了 ascii 码的等价码点
// [Min] caseOrbit 中给出了等价对
// [Min] 如果asciiFold，caseOrbit都无法确定，尝试将其转为小写，看是否与原码点相同，不同就返回小写，否则转为大写返回
func SimpleFold(r rune) rune {
	if r < 0 || r > MaxRune {
		return r
	}

	if int(r) < len(asciiFold) {
		return rune(asciiFold[r])
	}

	// Consult caseOrbit table for special cases.
	lo := 0
	hi := len(caseOrbit)
	for lo < hi {
		m := lo + (hi-lo)/2
		if rune(caseOrbit[m].From) < r {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo < len(caseOrbit) && rune(caseOrbit[lo].From) == r {
		return rune(caseOrbit[lo].To)
	}

	// No folding specified. This is a one- or two-element
	// equivalence class containing rune and ToLower(rune)
	// and ToUpper(rune) if they are different from rune.
	if l := ToLower(r); l != r {
		return l
	}
	return ToUpper(r)
}
