// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bytes

import (
	"errors"
	"io"
	"unicode/utf8"
)

// A Reader implements the io.Reader, io.ReaderAt, io.WriterTo, io.Seeker,
// io.ByteScanner, and io.RuneScanner interfaces by reading from
// a byte slice.
// Unlike a Buffer, a Reader is read-only and supports seeking.
// [Min] Reader是只读的，和Buffer不一样
type Reader struct {
	s        []byte
	i        int64 // current reading index
	prevRune int   // index of previous rune; or < 0
}

// Len returns the number of bytes of the unread portion of the
// slice.
// [Min] 返回数据的有效长度
func (r *Reader) Len() int {
	if r.i >= int64(len(r.s)) {
		return 0
	}
	return int(int64(len(r.s)) - r.i)
}

// Size returns the original length of the underlying byte slice.
// Size is the number of bytes available for reading via ReadAt.
// The returned value is always the same and is not affected by calls
// to any other method.
// [Min] 返回s的长度
func (r *Reader) Size() int64 { return int64(len(r.s)) }

// Read implements the io.Reader interface.
// [Min] 将r.s中的数据读入b中，返回读取的字节长度
func (r *Reader) Read(b []byte) (n int, err error) {
	if r.i >= int64(len(r.s)) {
		return 0, io.EOF
	}
	r.prevRune = -1
	n = copy(b, r.s[r.i:])
	r.i += int64(n)
	return
}

// ReadAt implements the io.ReaderAt interface.
// [Min] 从r.s的off位开始读取数据到b中，返回读取字节数，但是不改变r的状态
func (r *Reader) ReadAt(b []byte, off int64) (n int, err error) {
	// cannot modify state - see io.ReaderAt
	if off < 0 {
		return 0, errors.New("bytes.Reader.ReadAt: negative offset")
	}
	if off >= int64(len(r.s)) {
		return 0, io.EOF
	}
	n = copy(b, r.s[off:])
	if n < len(b) {
		err = io.EOF
	}
	return
}

// ReadByte implements the io.ByteReader interface.
// [Min] 读取一个字节返回该字节，没有有效数据的话返回0，EOF
func (r *Reader) ReadByte() (byte, error) {
	r.prevRune = -1
	if r.i >= int64(len(r.s)) {
		return 0, io.EOF
	}
	b := r.s[r.i]
	r.i++
	return b, nil
}

// UnreadByte complements ReadByte in implementing the io.ByteScanner interface.
// [Min] 回退一个字节的读取，只有当i可以减一的时候，似乎也可以对readrune做回退动作
func (r *Reader) UnreadByte() error {
	r.prevRune = -1
	if r.i <= 0 {
		return errors.New("bytes.Reader.UnreadByte: at beginning of slice")
	}
	r.i--
	return nil
}

// ReadRune implements the io.RuneReader interface.
// [Min] 读取一个rune字符，返回该字符和它对应的utf8码字节长度
func (r *Reader) ReadRune() (ch rune, size int, err error) {
	if r.i >= int64(len(r.s)) {
		r.prevRune = -1
		return 0, 0, io.EOF
	}
	r.prevRune = int(r.i)
	if c := r.s[r.i]; c < utf8.RuneSelf {
		r.i++
		return rune(c), 1, nil
	}
	ch, size = utf8.DecodeRune(r.s[r.i:])
	r.i += int64(size)
	return
}

// UnreadRune complements ReadRune in implementing the io.RuneScanner interface.
// [Min] 回退一个rune read动作，只有上次read是rune的时候才可以
func (r *Reader) UnreadRune() error {
	if r.prevRune < 0 {
		return errors.New("bytes.Reader.UnreadRune: previous operation was not ReadRune")
	}
	r.i = int64(r.prevRune)
	r.prevRune = -1
	return nil
}

// Seek implements the io.Seeker interface.
// [Min] 根据whence修改r.i
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	r.prevRune = -1
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.i + offset
	case io.SeekEnd:
		abs = int64(len(r.s)) + offset
	default:
		return 0, errors.New("bytes.Reader.Seek: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("bytes.Reader.Seek: negative position")
	}
	r.i = abs
	return abs, nil
}

// WriteTo implements the io.WriterTo interface.
// [Min] 将r中的数据写入w中，返回写入字节数
func (r *Reader) WriteTo(w io.Writer) (n int64, err error) {
	r.prevRune = -1
	if r.i >= int64(len(r.s)) {
		return 0, nil
	}
	b := r.s[r.i:]
	m, err := w.Write(b)
	if m > len(b) {
		panic("bytes.Reader.WriteTo: invalid Write count")
	}
	r.i += int64(m)
	n = int64(m)
	if m != len(b) && err == nil {
		err = io.ErrShortWrite
	}
	return
}

// Reset resets the Reader to be reading from b.
// [Min] 以b重置r
func (r *Reader) Reset(b []byte) { *r = Reader{b, 0, -1} }

// NewReader returns a new Reader reading from b.
// [Min] 以b初始化Reader
func NewReader(b []byte) *Reader { return &Reader{b, 0, -1} }
