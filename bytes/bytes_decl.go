// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bytes

//go:noescape

// IndexByte returns the index of the first instance of c in s, or -1 if c is not present in s.
// [Min] 返回 c 在 s 中的索引
func IndexByte(s []byte, c byte) int // ../runtime/asm_$GOARCH.s

//go:noescape

// Equal returns a boolean reporting whether a and b
// are the same length and contain the same bytes.
// A nil argument is equivalent to an empty slice.
// [Min] 判断a,b 两个 byte slice是否相同
func Equal(a, b []byte) bool // ../runtime/asm_$GOARCH.s

//go:noescape

// Compare returns an integer comparing two byte slices lexicographically.
// The result will be 0 if a==b, -1 if a < b, and +1 if a > b.
// A nil argument is equivalent to an empty slice.
// [Min] 字典序比较a,b 两个 byte slice
func Compare(a, b []byte) int // ../runtime/noasm.go or ../runtime/asm_{386,amd64}.s
