// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

import (
	"strings"
)

// tagOptions is the string following a comma in a struct field's "json"
// tag, or the empty string. It does not include the leading comma.
type tagOptions string

// parseTag splits a struct field's json tag into its name and
// comma-separated options.
// [Min] 以第一个','分隔 tag name 和 tagOptions（除去 tag name 的剩余部分），解析 struct 中字段包含的 tag
// [Min] 注意，这里输入的 tag 指的是 `json:"f_3,omitempty"` 中双引号内的部分
func parseTag(tag string) (string, tagOptions) {
	if idx := strings.Index(tag, ","); idx != -1 {
		return tag[:idx], tagOptions(tag[idx+1:])
	}
	return tag, tagOptions("")
}

// Contains reports whether a comma-separated list of options
// contains a particular substr flag. substr must be surrounded by a
// string boundary or commas.
// [Min] 判断 tagOptions 中是否包含某一项 option，不同 option 以','分隔
func (o tagOptions) Contains(optionName string) bool {
	if len(o) == 0 {
		return false
	}
	s := string(o)
	for s != "" {
		var next string
		// [Min] 以','分隔出当前第一个 option，比较该 option 是否为给定的 option
		// [Min] 是，返回 true，否，继续用后面的 option 来比较
		i := strings.Index(s, ",")
		if i >= 0 {
			s, next = s[:i], s[i+1:]
		}
		if s == optionName {
			return true
		}
		s = next
	}
	return false
}
