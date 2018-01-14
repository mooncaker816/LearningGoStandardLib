// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package strings implements simple functions to manipulate UTF-8 encoded strings.
//
// For information about UTF-8 strings in Go, see https://blog.golang.org/strings.
package strings

import (
	"unicode"
	"unicode/utf8"
)

// explode splits s into a slice of UTF-8 strings,
// one string per Unicode character up to a maximum of n (n < 0 means no limit).
// Invalid UTF-8 sequences become correct encodings of U+FFFD.
// [Min] 以每个utf8字符为单位，将前n个字符对应的string型组成新的slice返回
func explode(s string, n int) []string {
	l := utf8.RuneCountInString(s)
	if n < 0 || n > l {
		n = l
	}
	a := make([]string, n)
	for i := 0; i < n-1; i++ {
		ch, size := utf8.DecodeRuneInString(s)
		a[i] = s[:size]
		s = s[size:]
		if ch == utf8.RuneError {
			a[i] = string(utf8.RuneError)
		}
	}
	if n > 0 {
		a[n-1] = s
	}
	return a
}

// primeRK is the prime base used in Rabin-Karp algorithm.
const primeRK = 16777619

// hashStr returns the hash and the appropriate multiplicative
// factor for use in Rabin-Karp algorithm.
func hashStr(sep string) (uint32, uint32) {
	hash := uint32(0)
	for i := 0; i < len(sep); i++ {
		hash = hash*primeRK + uint32(sep[i])
	}
	var pow, sq uint32 = 1, primeRK
	for i := len(sep); i > 0; i >>= 1 {
		if i&1 != 0 {
			pow *= sq
		}
		sq *= sq
	}
	return hash, pow
}

// hashStrRev returns the hash of the reverse of sep and the
// appropriate multiplicative factor for use in Rabin-Karp algorithm.
func hashStrRev(sep string) (uint32, uint32) {
	hash := uint32(0)
	for i := len(sep) - 1; i >= 0; i-- {
		hash = hash*primeRK + uint32(sep[i])
	}
	var pow, sq uint32 = 1, primeRK
	for i := len(sep); i > 0; i >>= 1 {
		if i&1 != 0 {
			pow *= sq
		}
		sq *= sq
	}
	return hash, pow
}

// countGeneric implements Count.
// [Min] 返回s中有几个substr，若substr为空，则返回sutf8.RuneCount(s) + 1
func countGeneric(s, substr string) int {
	// special case
	if len(substr) == 0 {
		return utf8.RuneCountInString(s) + 1
	}
	n := 0
	for {
		i := Index(s, substr)
		if i == -1 {
			return n
		}
		n++
		s = s[i+len(substr):]
	}
}

// Contains reports whether substr is within s.
// [Min] s中是否含有substr
func Contains(s, substr string) bool {
	return Index(s, substr) >= 0
}

// ContainsAny reports whether any Unicode code points in chars are within s.
// [Min] s中是否含有字符串chars中的任意一个unicode字符
func ContainsAny(s, chars string) bool {
	return IndexAny(s, chars) >= 0
}

// ContainsRune reports whether the Unicode code point r is within s.
// [Min] s中是否含有rune r
func ContainsRune(s string, r rune) bool {
	return IndexRune(s, r) >= 0
}

// LastIndex returns the index of the last instance of substr in s, or -1 if substr is not present in s.
// [Min] 返回s中最后一个substr的位置，若substr为空，返回s的长度，若不含substr，则返回-1
func LastIndex(s, substr string) int {
	n := len(substr)
	switch {
	case n == 0:
		return len(s)
	case n == 1:
		return LastIndexByte(s, substr[0])
	case n == len(s):
		if substr == s {
			return 0
		}
		return -1
	case n > len(s):
		return -1
	}
	// Rabin-Karp search from the end of the string
	hashss, pow := hashStrRev(substr)
	last := len(s) - n
	var h uint32
	for i := len(s) - 1; i >= last; i-- {
		h = h*primeRK + uint32(s[i])
	}
	if h == hashss && s[last:] == substr {
		return last
	}
	for i := last - 1; i >= 0; i-- {
		h *= primeRK
		h += uint32(s[i])
		h -= pow * uint32(s[i+n])
		if h == hashss && s[i:i+n] == substr {
			return i
		}
	}
	return -1
}

// IndexRune returns the index of the first instance of the Unicode code point
// r, or -1 if rune is not present in s.
// If r is utf8.RuneError, it returns the first instance of any
// invalid UTF-8 byte sequence.
// [Min] 返回第一个r的位置，如果r无法解码为utf8又不是\uFFFD，认为没找到返回-1
func IndexRune(s string, r rune) int {
	switch {
	case 0 <= r && r < utf8.RuneSelf:
		return IndexByte(s, byte(r))
	case r == utf8.RuneError:
		for i, r := range s {
			if r == utf8.RuneError {
				return i
			}
		}
		return -1
	case !utf8.ValidRune(r):
		return -1
	default:
		return Index(s, string(r))
	}
}

// IndexAny returns the index of the first instance of any Unicode code point
// from chars in s, or -1 if no Unicode code point from chars is present in s.
// [Min] 返回chars中任意一个unicode字符在s中第一次出现的位置
func IndexAny(s, chars string) int {
	if chars == "" {
		// Avoid scanning all of s.
		return -1
	}
	if len(s) > 8 {
		if as, isASCII := makeASCIISet(chars); isASCII {
			for i := 0; i < len(s); i++ {
				if as.contains(s[i]) {
					return i
				}
			}
			return -1
		}
	}
	for i, c := range s {
		for _, m := range chars {
			if c == m {
				return i
			}
		}
	}
	return -1
}

// LastIndexAny returns the index of the last instance of any Unicode code
// point from chars in s, or -1 if no Unicode code point from chars is
// present in s.
// [Min] 返回chars中任意一个unicode字符在s中最后一次出现的位置
func LastIndexAny(s, chars string) int {
	if chars == "" {
		// Avoid scanning all of s.
		return -1
	}
	if len(s) > 8 {
		if as, isASCII := makeASCIISet(chars); isASCII {
			for i := len(s) - 1; i >= 0; i-- {
				if as.contains(s[i]) {
					return i
				}
			}
			return -1
		}
	}
	for i := len(s); i > 0; {
		r, size := utf8.DecodeLastRuneInString(s[:i])
		i -= size
		for _, c := range chars {
			if r == c {
				return i
			}
		}
	}
	return -1
}

// LastIndexByte returns the index of the last instance of c in s, or -1 if c is not present in s.
// [Min] 返回最后一个c的位置，没有则返回-1
func LastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// Generic split: splits after each instance of sep,
// including sepSave bytes of sep in the subarrays.
// [Min] 按sep划分s，返回前n个组成的slice，每个slice中sep的保留位数有sepSave决定，n小于0时，返回所有划分组成的slice
func genSplit(s, sep string, sepSave, n int) []string {
	if n == 0 {
		return nil
	}
	if sep == "" {
		return explode(s, n)
	}
	if n < 0 {
		n = Count(s, sep) + 1
	}

	a := make([]string, n)
	n--
	i := 0
	for i < n {
		m := Index(s, sep)
		if m < 0 {
			break
		}
		a[i] = s[:m+sepSave]
		s = s[m+len(sep):]
		i++
	}
	a[i] = s
	return a[:i+1]
}

// SplitN slices s into substrings separated by sep and returns a slice of
// the substrings between those separators.
//
// The count determines the number of substrings to return:
//   n > 0: at most n substrings; the last substring will be the unsplit remainder.
//   n == 0: the result is nil (zero substrings)
//   n < 0: all substrings
//
// Edge cases for s and sep (for example, empty strings) are handled
// as described in the documentation for Split.
// [Min] 按sep划分s，返回前n个划分的string组成的slice，每个划分的string不包含sep，n小于0返回所有划分组成的slice
func SplitN(s, sep string, n int) []string { return genSplit(s, sep, 0, n) }

// SplitAfterN slices s into substrings after each instance of sep and
// returns a slice of those substrings.
//
// The count determines the number of substrings to return:
//   n > 0: at most n substrings; the last substring will be the unsplit remainder.
//   n == 0: the result is nil (zero substrings)
//   n < 0: all substrings
//
// Edge cases for s and sep (for example, empty strings) are handled
// as described in the documentation for SplitAfter.
// [Min] 按sep划分s，返回前n个划分的string组成slice，每个划分包含sep
func SplitAfterN(s, sep string, n int) []string {
	return genSplit(s, sep, len(sep), n)
}

// Split slices s into all substrings separated by sep and returns a slice of
// the substrings between those separators.
//
// If s does not contain sep and sep is not empty, Split returns a
// slice of length 1 whose only element is s.
//
// If sep is empty, Split splits after each UTF-8 sequence. If both s
// and sep are empty, Split returns an empty slice.
//
// It is equivalent to SplitN with a count of -1.
// [Min] 返回所有的由sep划分的string组成的slice，每个划分不包含sep
func Split(s, sep string) []string { return genSplit(s, sep, 0, -1) }

// SplitAfter slices s into all substrings after each instance of sep and
// returns a slice of those substrings.
//
// If s does not contain sep and sep is not empty, SplitAfter returns
// a slice of length 1 whose only element is s.
//
// If sep is empty, SplitAfter splits after each UTF-8 sequence. If
// both s and sep are empty, SplitAfter returns an empty slice.
//
// It is equivalent to SplitAfterN with a count of -1.
// [Min] 返回所有的由sep划分的string组成的slice，每个划分包含sep
func SplitAfter(s, sep string) []string {
	return genSplit(s, sep, len(sep), -1)
}

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

// Fields splits the string s around each instance of one or more consecutive white space
// characters, as defined by unicode.IsSpace, returning a slice of substrings of s or an
// empty slice if s contains only white space.
// [Min] 按unicode.IsSpace划分s（所有连续的whitespce当成一个sep），返回所有的划分组成的slice
func Fields(s string) []string {
	// First count the fields.
	// This is an exact count if s is ASCII, otherwise it is an approximation.
	n := 0
	wasSpace := 1
	// setBits is used to track which bits are set in the bytes of s.
	setBits := uint8(0)
	for i := 0; i < len(s); i++ {
		r := s[i]
		setBits |= r
		isSpace := int(asciiSpace[r])
		n += wasSpace & ^isSpace
		wasSpace = isSpace
	}

	if setBits < utf8.RuneSelf { // ASCII fast path
		a := make([]string, n)
		na := 0
		fieldStart := 0
		i := 0
		// Skip spaces in the front of the input.
		for i < len(s) && asciiSpace[s[i]] != 0 {
			i++
		}
		fieldStart = i
		for i < len(s) {
			if asciiSpace[s[i]] == 0 {
				i++
				continue
			}
			a[na] = s[fieldStart:i]
			na++
			i++
			// Skip spaces in between fields.
			for i < len(s) && asciiSpace[s[i]] != 0 {
				i++
			}
			fieldStart = i
		}
		if fieldStart < len(s) { // Last field might end at EOF.
			a[na] = s[fieldStart:]
		}
		return a
	}

	// Some runes in the input string are not ASCII.
	return FieldsFunc(s, unicode.IsSpace)
}

// FieldsFunc splits the string s at each run of Unicode code points c satisfying f(c)
// and returns an array of slices of s. If all code points in s satisfy f(c) or the
// string is empty, an empty slice is returned.
// FieldsFunc makes no guarantees about the order in which it calls f(c).
// If f does not return consistent results for a given c, FieldsFunc may crash.
// [Min] 如果s中对应的一个rune满足f，则这个rune就是s的一个分隔符，返回s中所有分隔符划分的子string的slice
func FieldsFunc(s string, f func(rune) bool) []string {
	// A span is used to record a slice of s of the form s[start:end].
	// The start index is inclusive and the end index is exclusive.
	type span struct {
		start int
		end   int
	}
	spans := make([]span, 0, 32)

	// Find the field start and end indices.
	wasField := false
	fromIndex := 0
	for i, rune := range s {
		if f(rune) {
			if wasField {
				spans = append(spans, span{start: fromIndex, end: i})
				wasField = false
			}
		} else {
			if !wasField {
				fromIndex = i
				wasField = true
			}
		}
	}

	// Last field might end at EOF.
	if wasField {
		spans = append(spans, span{fromIndex, len(s)})
	}

	// Create strings from recorded field indices.
	a := make([]string, len(spans))
	for i, span := range spans {
		a[i] = s[span.start:span.end]
	}

	return a
}

// Join concatenates the elements of a to create a single string. The separator string
// sep is placed between elements in the resulting string.
// [Min] 将s中的元素用sep拼接起来，返回一个新的string
func Join(a []string, sep string) string {
	switch len(a) {
	case 0:
		return ""
	case 1:
		return a[0]
	case 2:
		// Special case for common small values.
		// Remove if golang.org/issue/6714 is fixed
		return a[0] + sep + a[1]
	case 3:
		// Special case for common small values.
		// Remove if golang.org/issue/6714 is fixed
		return a[0] + sep + a[1] + sep + a[2]
	}
	n := len(sep) * (len(a) - 1)
	for i := 0; i < len(a); i++ {
		n += len(a[i])
	}

	b := make([]byte, n)
	bp := copy(b, a[0])
	for _, s := range a[1:] {
		bp += copy(b[bp:], sep)
		bp += copy(b[bp:], s)
	}
	return string(b)
}

// HasPrefix tests whether the string s begins with prefix.
// [Min] 判断s是否以prefix开头
func HasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[0:len(prefix)] == prefix
}

// HasSuffix tests whether the string s ends with suffix.
// [Min] 判断s是否以suffix结尾
func HasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// Map returns a copy of the string s with all its characters modified
// according to the mapping function. If mapping returns a negative value, the character is
// dropped from the string with no replacement.
// [Min] 将s中对应的每个rune字符作用映射f得到新的字符，再将这些字符存储在一个新的string中返回
func Map(mapping func(rune) rune, s string) string {
	// In the worst case, the string can grow when mapped, making
	// things unpleasant. But it's so rare we barge in assuming it's
	// fine. It could also shrink but that falls out naturally.

	// The output buffer b is initialized on demand, the first
	// time a character differs.
	var b []byte
	// nbytes is the number of bytes encoded in b.
	var nbytes int

	for i, c := range s {
		r := mapping(c)
		if r == c {
			continue
		}

		b = make([]byte, len(s)+utf8.UTFMax)
		nbytes = copy(b, s[:i])
		if r >= 0 {
			if r <= utf8.RuneSelf {
				b[nbytes] = byte(r)
				nbytes++
			} else {
				nbytes += utf8.EncodeRune(b[nbytes:], r)
			}
		}

		if c == utf8.RuneError {
			// RuneError is the result of either decoding
			// an invalid sequence or '\uFFFD'. Determine
			// the correct number of bytes we need to advance.
			_, w := utf8.DecodeRuneInString(s[i:])
			i += w
		} else {
			i += utf8.RuneLen(c)
		}

		s = s[i:]
		break
	}

	if b == nil {
		return s
	}

	for _, c := range s {
		r := mapping(c)

		// common case
		if (0 <= r && r <= utf8.RuneSelf) && nbytes < len(b) {
			b[nbytes] = byte(r)
			nbytes++
			continue
		}

		// b is not big enough or r is not a ASCII rune.
		if r >= 0 {
			if nbytes+utf8.UTFMax >= len(b) {
				// Grow the buffer.
				nb := make([]byte, 2*len(b))
				copy(nb, b[:nbytes])
				b = nb
			}
			nbytes += utf8.EncodeRune(b[nbytes:], r)
		}
	}

	return string(b[:nbytes])
}

// Repeat returns a new string consisting of count copies of the string s.
//
// It panics if count is negative or if
// the result of (len(s) * count) overflows.
// [Min] 重复s count次，返回新的string
func Repeat(s string, count int) string {
	// Since we cannot return an error on overflow,
	// we should panic if the repeat will generate
	// an overflow.
	// See Issue golang.org/issue/16237
	if count < 0 {
		panic("strings: negative Repeat count")
	} else if count > 0 && len(s)*count/count != len(s) {
		panic("strings: Repeat count causes overflow")
	}

	b := make([]byte, len(s)*count)
	bp := copy(b, s)
	for bp < len(b) {
		copy(b[bp:], b[:bp])
		bp *= 2
	}
	return string(b)
}

// ToUpper returns a copy of the string s with all Unicode letters mapped to their upper case.
func ToUpper(s string) string {
	isASCII, hasLower := true, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			isASCII = false
			break
		}
		hasLower = hasLower || (c >= 'a' && c <= 'z')
	}

	if isASCII { // optimize for ASCII-only strings.
		if !hasLower {
			return s
		}
		b := make([]byte, len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			b[i] = c
		}
		return string(b)
	}
	return Map(unicode.ToUpper, s)
}

// ToLower returns a copy of the string s with all Unicode letters mapped to their lower case.
func ToLower(s string) string {
	isASCII, hasUpper := true, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			isASCII = false
			break
		}
		hasUpper = hasUpper || (c >= 'A' && c <= 'Z')
	}

	if isASCII { // optimize for ASCII-only strings.
		if !hasUpper {
			return s
		}
		b := make([]byte, len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			b[i] = c
		}
		return string(b)
	}
	return Map(unicode.ToLower, s)
}

// ToTitle returns a copy of the string s with all Unicode letters mapped to their title case.
func ToTitle(s string) string { return Map(unicode.ToTitle, s) }

// ToUpperSpecial returns a copy of the string s with all Unicode letters mapped to their
// upper case, giving priority to the special casing rules.
// [Min] 只将SpecialCase范围里的字符转为大写
func ToUpperSpecial(c unicode.SpecialCase, s string) string {
	return Map(func(r rune) rune { return c.ToUpper(r) }, s)
}

// ToLowerSpecial returns a copy of the string s with all Unicode letters mapped to their
// lower case, giving priority to the special casing rules.
// [Min] 只将SpecialCase范围里的字符转为小写
func ToLowerSpecial(c unicode.SpecialCase, s string) string {
	return Map(func(r rune) rune { return c.ToLower(r) }, s)
}

// ToTitleSpecial returns a copy of the string s with all Unicode letters mapped to their
// title case, giving priority to the special casing rules.
// [Min] 只将SpecialCase范围里的字符转为Title
func ToTitleSpecial(c unicode.SpecialCase, s string) string {
	return Map(func(r rune) rune { return c.ToTitle(r) }, s)
}

// isSeparator reports whether the rune could mark a word boundary.
// TODO: update when package unicode captures more of the properties.
/* [Min]
r是否可以作为一个词（unicode）的分隔符
ascii码，数字，字母，下划线不可以
非ascii码，unicode的数字，字母不可以，剩下其他认为是unicode的space可以
*/
func isSeparator(r rune) bool {
	// ASCII alphanumerics and underscore are not separators
	if r <= 0x7F {
		switch {
		case '0' <= r && r <= '9':
			return false
		case 'a' <= r && r <= 'z':
			return false
		case 'A' <= r && r <= 'Z':
			return false
		case r == '_':
			return false
		}
		return true
	}
	// Letters and digits are not separators
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return false
	}
	// Otherwise, all we can do for now is treat spaces as separators.
	return unicode.IsSpace(r)
}

// Title returns a copy of the string s with all Unicode letters that begin words
// mapped to their title case.
//
// BUG(rsc): The rule Title uses for word boundaries does not handle Unicode punctuation properly.
// [Min] 调用Map，s中非词分隔符的字符转换为Title
func Title(s string) string {
	// Use a closure here to remember state.
	// Hackish but effective. Depends on Map scanning in order and calling
	// the closure once per rune.
	prev := ' '
	return Map(
		func(r rune) rune {
			if isSeparator(prev) {
				prev = r
				return unicode.ToTitle(r)
			}
			prev = r
			return r
		},
		s)
}

// TrimLeftFunc returns a slice of the string s with all leading
// Unicode code points c satisfying f(c) removed.
// [Min] 以左边起第一个不满足f的rune对应的utf8码开始到s末尾的子string
func TrimLeftFunc(s string, f func(rune) bool) string {
	i := indexFunc(s, f, false)
	if i == -1 {
		return ""
	}
	return s[i:]
}

// TrimRightFunc returns a slice of the string s with all trailing
// Unicode code points c satisfying f(c) removed.
// [Min] 以s头开始到从右边起第一个不满足f的rune对应的utf8码为终点的子string
func TrimRightFunc(s string, f func(rune) bool) string {
	i := lastIndexFunc(s, f, false)
	if i >= 0 && s[i] >= utf8.RuneSelf {
		_, wid := utf8.DecodeRuneInString(s[i:])
		i += wid
	} else {
		i++
	}
	return s[0:i]
}

// TrimFunc returns a slice of the string s with all leading
// and trailing Unicode code points c satisfying f(c) removed.
// [Min] 去掉左边和去掉右边的结合体
func TrimFunc(s string, f func(rune) bool) string {
	return TrimRightFunc(TrimLeftFunc(s, f), f)
}

// IndexFunc returns the index into s of the first Unicode
// code point satisfying f(c), or -1 if none do.
// [Min] 返回s中第一个满足f的rune字符对应的utf8码的起始位置
func IndexFunc(s string, f func(rune) bool) int {
	return indexFunc(s, f, true)
}

// LastIndexFunc returns the index into s of the last
// Unicode code point satisfying f(c), or -1 if none do.
// [Min] 返回s中最后一个满足f的rune字符对应的utf8码的起始位置
func LastIndexFunc(s string, f func(rune) bool) int {
	return lastIndexFunc(s, f, true)
}

// indexFunc is the same as IndexFunc except that if
// truth==false, the sense of the predicate function is
// inverted.
// [Min] 返回s中第一个在f作用下得到truth的rune字符对应的utf8码的起始位置
func indexFunc(s string, f func(rune) bool, truth bool) int {
	for i, r := range s {
		if f(r) == truth {
			return i
		}
	}
	return -1
}

// lastIndexFunc is the same as LastIndexFunc except that if
// truth==false, the sense of the predicate function is
// inverted.
// [Min] 返回s中最后一个在f作用下得到truth的rune字符对应的utf8码的起始位置
func lastIndexFunc(s string, f func(rune) bool, truth bool) int {
	for i := len(s); i > 0; {
		r, size := utf8.DecodeLastRuneInString(s[0:i])
		i -= size
		if f(r) == truth {
			return i
		}
	}
	return -1
}

// asciiSet is a 32-byte value, where each bit represents the presence of a
// given ASCII character in the set. The 128-bits of the lower 16 bytes,
// starting with the least-significant bit of the lowest word to the
// most-significant bit of the highest word, map to the full range of all
// 128 ASCII characters. The 128-bits of the upper 16 bytes will be zeroed,
// ensuring that any non-ASCII character will be reported as not in the set.
type asciiSet [8]uint32

// makeASCIISet creates a set of ASCII characters and reports whether all
// characters in chars are ASCII.
/* [Min]
返回s中碰到非ascii码之前所有ascii码的集合，以及s中是否都是ascii码
可以把asciiSet看成是一个32字节长度的值，其中低16字节共计128位表达128个ascii码[0,127]，高16字节用来比对非ascii码
具体存储：
asciiSet是一个含有8个元素的数组，每个元素有32位，共计256位，
其中元素的位置保存了该字符（uint8）对应的高3位（c>>5）的信息，
元素的内容保存了每个字符低5位（1<<uint(c&31)）的信息，5位最大是31（11111），
刚好uint32的每一位可以代表在相同高3位的情况下，所有字符的低5位情况，
这样就可以用数组的前4个元素完整表达128个ascii了
*/
func makeASCIISet(chars string) (as asciiSet, ok bool) {
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		if c >= utf8.RuneSelf {
			return as, false
		}
		as[c>>5] |= 1 << uint(c&31)
	}
	return as, true
}

// contains reports whether c is inside the set.
// [Min] c是否在as中
func (as *asciiSet) contains(c byte) bool {
	return (as[c>>5] & (1 << uint(c&31))) != 0
}

/* [Min]
返回一个判断r是否在cutset字符串中的函数
若为单字节字符串，则返回一个直接比较r是否和cutset相同的函数
根据cutset创建一个ascii码的集合，
如果全是ascii，则返回一个用来判断r是否在上述集合中的函数
如果含有非ascii，则返回一个逐一循环cutset中rune字符，判断r是否其中之一的函数
*/
func makeCutsetFunc(cutset string) func(rune) bool {
	if len(cutset) == 1 && cutset[0] < utf8.RuneSelf {
		return func(r rune) bool {
			return r == rune(cutset[0])
		}
	}
	if as, isASCII := makeASCIISet(cutset); isASCII {
		return func(r rune) bool {
			return r < utf8.RuneSelf && as.contains(byte(r))
		}
	}
	return func(r rune) bool { return IndexRune(cutset, r) >= 0 }
}

// Trim returns a slice of the string s with all leading and
// trailing Unicode code points contained in cutset removed.
// [Min] 将s左右两端连续属于cutset的rune字符去除，保留中间的子string
func Trim(s string, cutset string) string {
	if s == "" || cutset == "" {
		return s
	}
	return TrimFunc(s, makeCutsetFunc(cutset))
}

// TrimLeft returns a slice of the string s with all leading
// Unicode code points contained in cutset removed.
// [Min] 将s左边连续属于cutset的rune字符去除，返回剩下的子string
func TrimLeft(s string, cutset string) string {
	if s == "" || cutset == "" {
		return s
	}
	return TrimLeftFunc(s, makeCutsetFunc(cutset))
}

// TrimRight returns a slice of the string s, with all trailing
// Unicode code points contained in cutset removed.
// [Min] 将s右边连续属于cutset的rune字符去除，返回剩下的子string
func TrimRight(s string, cutset string) string {
	if s == "" || cutset == "" {
		return s
	}
	return TrimRightFunc(s, makeCutsetFunc(cutset))
}

// TrimSpace returns a slice of the string s, with all leading
// and trailing white space removed, as defined by Unicode.
// [Min] 去除s左右两端的whitespce，保留剩下的子string
func TrimSpace(s string) string {
	return TrimFunc(s, unicode.IsSpace)
}

// TrimPrefix returns s without the provided leading prefix string.
// If s doesn't start with prefix, s is returned unchanged.
// [Min] 去掉prefix后的子string
func TrimPrefix(s, prefix string) string {
	if HasPrefix(s, prefix) {
		return s[len(prefix):]
	}
	return s
}

// TrimSuffix returns s without the provided trailing suffix string.
// If s doesn't end with suffix, s is returned unchanged.
// [Min] 去掉suffix后的子string
func TrimSuffix(s, suffix string) string {
	if HasSuffix(s, suffix) {
		return s[:len(s)-len(suffix)]
	}
	return s
}

// Replace returns a copy of the string s with the first n
// non-overlapping instances of old replaced by new.
// If old is empty, it matches at the beginning of the string
// and after each UTF-8 sequence, yielding up to k+1 replacements
// for a k-rune string.
// If n < 0, there is no limit on the number of replacements.
// [Min] 将s中前n个old替换成new，返回一个新的string，n为负数或者n>old个数时，替换所有old
func Replace(s, old, new string, n int) string {
	if old == new || n == 0 {
		return s // avoid allocation
	}

	// Compute number of replacements.
	if m := Count(s, old); m == 0 {
		return s // avoid allocation
	} else if n < 0 || m < n {
		n = m
	}

	// Apply replacements to buffer.
	t := make([]byte, len(s)+n*(len(new)-len(old)))
	w := 0
	start := 0
	for i := 0; i < n; i++ {
		j := start
		if len(old) == 0 {
			if i > 0 {
				_, wid := utf8.DecodeRuneInString(s[start:])
				j += wid
			}
		} else {
			j += Index(s[start:], old)
		}
		w += copy(t[w:], s[start:j])
		w += copy(t[w:], new)
		start = j + len(old)
	}
	w += copy(t[w:], s[start:])
	return string(t[0:w])
}

// EqualFold reports whether s and t, interpreted as UTF-8 strings,
// are equal under Unicode case-folding.
// [Min] 判断s和t在不区分大小写（包括unicode case）的情况下是否相等
func EqualFold(s, t string) bool {
	for s != "" && t != "" {
		// Extract first rune from each string.
		var sr, tr rune
		if s[0] < utf8.RuneSelf {
			sr, s = rune(s[0]), s[1:]
		} else {
			r, size := utf8.DecodeRuneInString(s)
			sr, s = r, s[size:]
		}
		if t[0] < utf8.RuneSelf {
			tr, t = rune(t[0]), t[1:]
		} else {
			r, size := utf8.DecodeRuneInString(t)
			tr, t = r, t[size:]
		}

		// If they match, keep going; if not, return false.

		// Easy case.
		if tr == sr {
			continue
		}

		// Make sr < tr to simplify what follows.
		if tr < sr {
			tr, sr = sr, tr
		}
		// Fast check for ASCII.
		if tr < utf8.RuneSelf && 'A' <= sr && sr <= 'Z' {
			// ASCII, and sr is upper case.  tr must be lower case.
			if tr == sr+'a'-'A' {
				continue
			}
			return false
		}

		// General case. SimpleFold(x) returns the next equivalent rune > x
		// or wraps around to smaller values.
		r := unicode.SimpleFold(sr)
		for r != sr && r < tr {
			r = unicode.SimpleFold(r)
		}
		if r == tr {
			continue
		}
		return false
	}

	// One string is empty. Are both?
	return s == t
}

/* [Min]
返回第一个sep在s中的位置
Rabin-Karp字符串匹配算法和前面介绍的《朴素字符串匹配算法》类似，也是对应每一个字符进行比较，不同的是Rabin-Karp采用了把字符进行预处理，也就是对每个字符进行对应进制数并取模运算，类似于通过某种函数计算其函数值，比较的是每个字符的函数值。预处理时间O(m)，匹配时间是O((n-m+1)m)。

Rabin-Karp算法的思想：

假设待匹配字符串的长度为M，目标字符串的长度为N（N>M）；
首先计算待匹配字符串的hash值，计算目标字符串前M个字符的hash值；
比较前面计算的两个hash值，比较次数N-M+1：
若hash值不相等，则继续计算目标字符串的下一个长度为M的字符子串的hash值
若hash值相同，则需要使用朴素算法再次判断是否为相同的字串；
*/
func indexRabinKarp(s, substr string) int {
	// Rabin-Karp search
	hashss, pow := hashStr(substr)
	n := len(substr)
	var h uint32
	for i := 0; i < n; i++ {
		h = h*primeRK + uint32(s[i])
	}
	if h == hashss && s[:n] == substr {
		return 0
	}
	for i := n; i < len(s); {
		h *= primeRK
		h += uint32(s[i])
		h -= pow * uint32(s[i-n])
		i++
		if h == hashss && s[i-n:i] == substr {
			return i - n
		}
	}
	return -1

}
