// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bytes"
	"encoding/binary"
)

// The algorithm uses at most sniffLen bytes to make its decision.
const sniffLen = 512

// DetectContentType implements the algorithm described
// at http://mimesniff.spec.whatwg.org/ to determine the
// Content-Type of the given data. It considers at most the
// first 512 bytes of data. DetectContentType always returns
// a valid MIME type: if it cannot determine a more specific one, it
// returns "application/octet-stream".
// [Min] 通过样本数据 data 来嗅探该数据的类型
func DetectContentType(data []byte) string {
	if len(data) > sniffLen {
		data = data[:sniffLen]
	}

	// Index of the first non-whitespace byte in data.
	// [Min] 先找到第一个不是 white space 的字节位置
	firstNonWS := 0
	for ; firstNonWS < len(data) && isWS(data[firstNonWS]); firstNonWS++ {
	}

	// [Min] 然后用各种预定义好的不同类型文件的匹配模式和此样本数据开始匹配，匹配上了就返回
	// [Min] 其中数据的起始位置可能是firstNonWS，也可能不是，由模式决定
	for _, sig := range sniffSignatures {
		if ct := sig.match(data, firstNonWS); ct != "" {
			return ct
		}
	}

	return "application/octet-stream" // fallback
}

// [Min] 是否是 white space
func isWS(b byte) bool {
	switch b {
	case '\t', '\n', '\x0c', '\r', ' ':
		return true
	}
	return false
}

// [Min] 嗅探匹配接口
type sniffSig interface {
	// match returns the MIME type of the data, or "" if unknown.
	match(data []byte, firstNonWS int) string
}

// Data matching the table in section 6.
// [Min] 根据不同类型文件的编码特点，预定义的不同类型文件的匹配模式
var sniffSignatures = []sniffSig{
	htmlSig("<!DOCTYPE HTML"),
	htmlSig("<HTML"),
	htmlSig("<HEAD"),
	htmlSig("<SCRIPT"),
	htmlSig("<IFRAME"),
	htmlSig("<H1"),
	htmlSig("<DIV"),
	htmlSig("<FONT"),
	htmlSig("<TABLE"),
	htmlSig("<A"),
	htmlSig("<STYLE"),
	htmlSig("<TITLE"),
	htmlSig("<B"),
	htmlSig("<BODY"),
	htmlSig("<BR"),
	htmlSig("<P"),
	htmlSig("<!--"),

	&maskedSig{mask: []byte("\xFF\xFF\xFF\xFF\xFF"), pat: []byte("<?xml"), skipWS: true, ct: "text/xml; charset=utf-8"},

	&exactSig{[]byte("%PDF-"), "application/pdf"},
	&exactSig{[]byte("%!PS-Adobe-"), "application/postscript"},

	// UTF BOMs.
	&maskedSig{mask: []byte("\xFF\xFF\x00\x00"), pat: []byte("\xFE\xFF\x00\x00"), ct: "text/plain; charset=utf-16be"},
	&maskedSig{mask: []byte("\xFF\xFF\x00\x00"), pat: []byte("\xFF\xFE\x00\x00"), ct: "text/plain; charset=utf-16le"},
	&maskedSig{mask: []byte("\xFF\xFF\xFF\x00"), pat: []byte("\xEF\xBB\xBF\x00"), ct: "text/plain; charset=utf-8"},

	&exactSig{[]byte("GIF87a"), "image/gif"},
	&exactSig{[]byte("GIF89a"), "image/gif"},
	&exactSig{[]byte("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A"), "image/png"},
	&exactSig{[]byte("\xFF\xD8\xFF"), "image/jpeg"},
	&exactSig{[]byte("BM"), "image/bmp"},
	&maskedSig{
		mask: []byte("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF"),
		pat:  []byte("RIFF\x00\x00\x00\x00WEBPVP"),
		ct:   "image/webp",
	},
	&exactSig{[]byte("\x00\x00\x01\x00"), "image/vnd.microsoft.icon"},

	&maskedSig{
		mask: []byte("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"),
		pat:  []byte("RIFF\x00\x00\x00\x00WAVE"),
		ct:   "audio/wave",
	},
	&maskedSig{
		mask: []byte("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"),
		pat:  []byte("FORM\x00\x00\x00\x00AIFF"),
		ct:   "audio/aiff",
	},
	&maskedSig{
		mask: []byte("\xFF\xFF\xFF\xFF"),
		pat:  []byte(".snd"),
		ct:   "audio/basic",
	},
	&maskedSig{
		mask: []byte("\xFF\xFF\xFF\xFF\xFF"),
		pat:  []byte("OggS\x00"),
		ct:   "application/ogg",
	},
	&maskedSig{
		mask: []byte("\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"),
		pat:  []byte("MThd\x00\x00\x00\x06"),
		ct:   "audio/midi",
	},
	&maskedSig{
		mask: []byte("\xFF\xFF\xFF"),
		pat:  []byte("ID3"),
		ct:   "audio/mpeg",
	},
	&maskedSig{
		mask: []byte("\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF"),
		pat:  []byte("RIFF\x00\x00\x00\x00AVI "),
		ct:   "video/avi",
	},

	// Fonts
	&maskedSig{
		// 34 NULL bytes followed by the string "LP"
		pat: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x4C\x50"),
		// 34 NULL bytes followed by \xF\xF
		mask: []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF"),
		ct:   "application/vnd.ms-fontobject",
	},
	&exactSig{[]byte("\x00\x01\x00\x00"), "application/font-ttf"},
	&exactSig{[]byte("OTTO"), "application/font-off"},
	&exactSig{[]byte("ttcf"), "application/font-cff"},
	&exactSig{[]byte("wOFF"), "application/font-woff"},

	&exactSig{[]byte("\x1A\x45\xDF\xA3"), "video/webm"},
	&exactSig{[]byte("\x52\x61\x72\x20\x1A\x07\x00"), "application/x-rar-compressed"},
	&exactSig{[]byte("\x50\x4B\x03\x04"), "application/zip"},
	&exactSig{[]byte("\x1F\x8B\x08"), "application/x-gzip"},

	mp4Sig{},

	textSig{}, // should be last
}

// [Min] 完全匹配模式，数据的头部需和 sig 一致
type exactSig struct {
	sig []byte
	ct  string
}

// [Min] 比较数据是否以 sig 为前缀
func (e *exactSig) match(data []byte, firstNonWS int) string {
	if bytes.HasPrefix(data, e.sig) {
		return e.ct
	}
	return ""
}

// [Min] mask 匹配模式
type maskedSig struct {
	mask, pat []byte
	skipWS    bool
	ct        string
}

// [Min] 将数据的每一位和 mask对应的每一位做与运算，再逐一比较是否和 pat 中每一位一致，
// [Min] 比较之前，数据应先由 skipWS 判断是否需要忽略掉 WS
func (m *maskedSig) match(data []byte, firstNonWS int) string {
	// pattern matching algorithm section 6
	// https://mimesniff.spec.whatwg.org/#pattern-matching-algorithm

	if m.skipWS {
		data = data[firstNonWS:]
	}
	if len(m.pat) != len(m.mask) {
		return ""
	}
	// [Min] 确保 mask 后的到数据的位长与 mask 相同
	if len(data) < len(m.mask) {
		return ""
	}
	for i, mask := range m.mask {
		db := data[i] & mask
		if db != m.pat[i] {
			return ""
		}
	}
	return m.ct
}

// [Min] html 匹配模式
type htmlSig []byte

// [Min] 先去掉 WS
func (h htmlSig) match(data []byte, firstNonWS int) string {
	data = data[firstNonWS:]
	// [Min] data的长度要大于 h 的长度
	if len(data) < len(h)+1 {
		return ""
	}
	// [Min] 忽略 ascii 码英文字母大小写的比较
	for i, b := range h {
		db := data[i]
		// [Min] https://blog.cloudflare.com/the-oldest-trick-in-the-ascii-book/
		// [Min]	    0123456789ABCDEF0123456789ABCDEF
		// [Min]	   +--------------------------------
		// [Min] 0x20| !"#$%&'()*+,-./0123456789:;<=>?
		// [Min] 0x40|@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_
		// [Min] 0x60|`abcdefghijklmnopqrstuvwxyz{|}~
		// [Min]
		// [Min] 对于一个小写的英文字母，如果和 0xDF 做与运算，可以得到大写字母
		// [Min] 对于一个大写的英文字母，如果和 0xDF 做与运算，保持不变，得到的是其本身
		// [Min] 因为对应的大小写字母之间相差 0x20（00100000），所以只要和0xDF（11011111）做与运算
		// [Min] 就能将0x20从小写字母中扣去，而对于大写字母保持不变
		if 'A' <= b && b <= 'Z' {
			db &= 0xDF
		}
		if b != db {
			return ""
		}
	}
	// Next byte must be space or right angle bracket.
	// [Min] 下一位必须是空格或'>'
	if db := data[len(h)]; db != ' ' && db != '>' {
		return ""
	}
	return "text/html; charset=utf-8"
}

var mp4ftype = []byte("ftyp")
var mp4 = []byte("mp4")

// [Min] mp4 匹配模式
type mp4Sig struct{}

func (mp4Sig) match(data []byte, firstNonWS int) string {
	// https://mimesniff.spec.whatwg.org/#signature-for-mp4
	// c.f. section 6.2.1
	if len(data) < 12 {
		return ""
	}
	// [Min] 按大端读取前四位二进制数，得到 boxSize，boxSize 必须整除4，且样本数据长度不能小于 boxSize
	// [Min] 大致可以理解为在mp4数据中，头部 boxSize 长的部分中有识别标志
	boxSize := int(binary.BigEndian.Uint32(data[:4]))
	if boxSize%4 != 0 || len(data) < boxSize {
		return ""
	}
	// [Min] 4-7位应该为ftyp
	if !bytes.Equal(data[4:8], mp4ftype) {
		return ""
	}
	// [Min] 在boxSize的范围内，从第8个字节开始每4个字节为一组，比较头三个字节是否为 mp4，跳过以第2组（第12个字节开始的那一组）
	for st := 8; st < boxSize; st += 4 {
		if st == 12 {
			// minor version number
			continue
		}
		if bytes.Equal(data[st:st+3], mp4) {
			return "video/mp4"
		}
	}
	return ""
}

// [Min] 文本匹配模式
type textSig struct{}

func (textSig) match(data []byte, firstNonWS int) string {
	// c.f. section 5, step 4.
	// [Min] 对每一个字节判断是否在非文本的取值范围内，是就返回空，如果全都是文本字符允许的，则匹配成功
	for _, b := range data[firstNonWS:] {
		switch {
		case b <= 0x08,
			b == 0x0B,
			0x0E <= b && b <= 0x1A,
			0x1C <= b && b <= 0x1F:
			return ""
		}
	}
	return "text/plain; charset=utf-8"
}
