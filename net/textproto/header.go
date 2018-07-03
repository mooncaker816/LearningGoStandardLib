// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package textproto

// A MIMEHeader represents a MIME-style header mapping
// keys to sets of values.
// [Min] MIME https://zh.wikipedia.org/wiki/%E5%A4%9A%E7%94%A8%E9%80%94%E4%BA%92%E8%81%AF%E7%B6%B2%E9%83%B5%E4%BB%B6%E6%93%B4%E5%B1%95
// [Min] 其中 key 都是经过CanonicalMIMEHeaderKey标准化的
type MIMEHeader map[string][]string

// Add adds the key, value pair to the header.
// It appends to any existing values associated with key.
// [Min] 添加 key-value 至 h 中，同一个 key 可以有多个 value，key 会先进行CanonicalMIMEHeaderKey标准化
func (h MIMEHeader) Add(key, value string) {
	key = CanonicalMIMEHeaderKey(key)
	h[key] = append(h[key], value)
}

// Set sets the header entries associated with key to
// the single element value. It replaces any existing
// values associated with key.
// [Min] 覆盖 key 的值
func (h MIMEHeader) Set(key, value string) {
	h[CanonicalMIMEHeaderKey(key)] = []string{value}
}

// Get gets the first value associated with the given key.
// It is case insensitive; CanonicalMIMEHeaderKey is used
// to canonicalize the provided key.
// If there are no values associated with the key, Get returns "".
// To access multiple values of a key, or to use non-canonical keys,
// access the map directly.
// [Min] 获取key 的首个值
func (h MIMEHeader) Get(key string) string {
	if h == nil {
		return ""
	}
	v := h[CanonicalMIMEHeaderKey(key)]
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// Del deletes the values associated with key.
// [Min] 删除 key
func (h MIMEHeader) Del(key string) {
	delete(h, CanonicalMIMEHeaderKey(key))
}
