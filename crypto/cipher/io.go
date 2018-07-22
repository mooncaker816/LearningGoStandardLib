// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import "io"

// The Stream* objects are so simple that all their members are public. Users
// can create them themselves.

// StreamReader wraps a Stream into an io.Reader. It calls XORKeyStream
// to process each slice of data which passes through.
// [Min] 明文或密文在R中，通过调用Read方法，从而调用XORKeyStream达到加解密
type StreamReader struct {
	S Stream
	R io.Reader
}

// [Min] Read方法先将明文或密文从R中读取到dst中，然后进行加解密
func (r StreamReader) Read(dst []byte) (n int, err error) {
	n, err = r.R.Read(dst)
	r.S.XORKeyStream(dst[:n], dst[:n])
	return
}

// StreamWriter wraps a Stream into an io.Writer. It calls XORKeyStream
// to process each slice of data which passes through. If any Write call
// returns short then the StreamWriter is out of sync and must be discarded.
// A StreamWriter has no internal buffering; Close does not need
// to be called to flush write data.
// [Min] 通过对输入的数据进行加解密（XOR），然后写入W中
type StreamWriter struct {
	S   Stream
	W   io.Writer
	Err error // unused
}

// [Min] 将src中明文或密文进行相应的加密或解密，得到密文或明文后，写入W中
func (w StreamWriter) Write(src []byte) (n int, err error) {
	c := make([]byte, len(src))
	w.S.XORKeyStream(c, src)
	n, err = w.W.Write(c)
	if n != len(src) && err == nil { // should never happen
		err = io.ErrShortWrite
	}
	return
}

// Close closes the underlying Writer and returns its Close return value, if the Writer
// is also an io.Closer. Otherwise it returns nil.
// [Min] 关闭Writer，如果有需要的话
func (w StreamWriter) Close() error {
	if c, ok := w.W.(io.Closer); ok {
		return c.Close()
	}
	return nil
}
