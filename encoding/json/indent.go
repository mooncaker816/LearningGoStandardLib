// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import "bytes"

// Compact appends to dst the JSON-encoded src with
// insignificant space characters elided.
// [Min] 将 json 字符串中不重要的空格忽略，写入 dst 中
func Compact(dst *bytes.Buffer, src []byte) error {
	return compact(dst, src, false)
}

func compact(dst *bytes.Buffer, src []byte, escape bool) error {
	origLen := dst.Len()
	var scan scanner
	scan.reset()
	// [Min] start 用来标记 src 中一段需要写入的数据的位置，该段数据以空格分隔或者到了 json 末尾
	// [Min] 换句话说，当碰到需要跳过的空格，或者需要转义的字符时，将之前累积起来的字符串写入 dst 中
	start := 0
	for i, c := range src {
		// [Min] 将<,>,&写成\u00xx 的形式
		if escape && (c == '<' || c == '>' || c == '&') {
			if start < i {
				dst.Write(src[start:i])
			}
			dst.WriteString(`\u00`)
			dst.WriteByte(hex[c>>4])  // [Min] 高四位对应的十六进制数
			dst.WriteByte(hex[c&0xF]) // [Min] 低四位对应的十六进制数
			start = i + 1
		}
		// Convert U+2028 and U+2029 (E2 80 A8 and E2 80 A9).
		// [Min] 如果碰到三字节utf8字符E280A8 或 E280A9，将他们转为对应的\u2028 或 \u2029
		// [Min] 第一个字节为 0xE2，后续至少还要有两个字节，第二个字节为0x80，
		// [Min] A8,A9只有最末位不一样，与1 &^ 高位保持不变，末位置0，都是 A8
		if c == 0xE2 && i+2 < len(src) && src[i+1] == 0x80 && src[i+2]&^1 == 0xA8 {
			// [Min] 先将之前累积的写入 dst
			if start < i {
				dst.Write(src[start:i])
			}
			// [Min] 写入对应的 unicode
			dst.WriteString(`\u202`)
			dst.WriteByte(hex[src[i+2]&0xF])
			// [Min] 因为我们已经将这三个字节对应的字符写入了dst，所以 start 要加3
			start = i + 3
		}
		v := scan.step(&scan, c)
		// [Min] 如果是需要跳过的空格或 json 串完结，start 会指向下一个字符，从而跳过空格
		if v >= scanSkipSpace {
			if v == scanError {
				break
			}
			// [Min] 只有当 start 小于 i 的时候才会写入
			if start < i {
				dst.Write(src[start:i])
			}
			start = i + 1
		}
	}
	// [Min] 如果整个 json 解析有错，直接放弃之前所有写入的数据，只保留 buffer 中的原始数据
	if scan.eof() == scanError {
		dst.Truncate(origLen)
		return scan.err
	}
	// [Min] 写入最后一部分数据
	if start < len(src) {
		dst.Write(src[start:])
	}
	return nil
}

// [Min] 写入新行，并且根据前缀，深度按需缩进
func newline(dst *bytes.Buffer, prefix, indent string, depth int) {
	dst.WriteByte('\n')
	dst.WriteString(prefix)
	for i := 0; i < depth; i++ {
		dst.WriteString(indent)
	}
}

// Indent appends to dst an indented form of the JSON-encoded src.
// Each element in a JSON object or array begins on a new,
// indented line beginning with prefix followed by one or more
// copies of indent according to the indentation nesting.
// The data appended to dst does not begin with the prefix nor
// any indentation, to make it easier to embed inside other formatted JSON data.
// Although leading space characters (space, tab, carriage return, newline)
// at the beginning of src are dropped, trailing space characters
// at the end of src are preserved and copied to dst.
// For example, if src has no trailing spaces, neither will dst;
// if src ends in a trailing newline, so will dst.
// [Min] 按层级展开 json 字符串 - pretty print
func Indent(dst *bytes.Buffer, src []byte, prefix, indent string) error {
	origLen := dst.Len()
	var scan scanner
	scan.reset()
	needIndent := false
	depth := 0
	for _, c := range src {
		scan.bytes++
		v := scan.step(&scan, c)
		if v == scanSkipSpace {
			continue
		}
		if v == scanError {
			break
		}
		if needIndent && v != scanEndObject && v != scanEndArray {
			needIndent = false
			depth++
			newline(dst, prefix, indent, depth)
		}

		// Emit semantically uninteresting bytes
		// (in particular, punctuation in strings) unmodified.
		if v == scanContinue {
			dst.WriteByte(c)
			continue
		}

		// Add spacing around real punctuation.
		switch c {
		case '{', '[':
			// delay indent so that empty object and array are formatted as {} and [].
			needIndent = true
			dst.WriteByte(c)

		case ',':
			dst.WriteByte(c)
			newline(dst, prefix, indent, depth)

		case ':':
			dst.WriteByte(c)
			dst.WriteByte(' ')

		case '}', ']':
			if needIndent {
				// suppress indent in empty object/array
				needIndent = false
			} else {
				depth--
				newline(dst, prefix, indent, depth)
			}
			dst.WriteByte(c)

		default:
			dst.WriteByte(c)
		}
	}
	if scan.eof() == scanError {
		dst.Truncate(origLen)
		return scan.err
	}
	return nil
}
