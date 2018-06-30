// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

// parsePort parses service as a decimal integer and returns the
// corresponding value as port. It is the caller's responsibility to
// parse service as a non-decimal integer when needsLookup is true.
//
// Some system resolvers will return a valid port number when given a number
// over 65536 (see https://golang.org/issues/11715). Alas, the parser
// can't bail early on numbers > 65536. Therefore reasonably large/small
// numbers are parsed in full and rejected if invalid.
// [Min] 解析端口号，如果不是数字，needsLookup 为真
func parsePort(service string) (port int, needsLookup bool) {
	if service == "" {
		// Lock in the legacy behavior that an empty string
		// means port 0. See golang.org/issue/13610.
		return 0, false
	}
	const (
		max    = uint32(1<<32 - 1)
		cutoff = uint32(1 << 30)
	)
	// [Min] 根据首位判断符号
	neg := false
	if service[0] == '+' {
		service = service[1:]
	} else if service[0] == '-' {
		neg = true
		service = service[1:]
	}
	var n uint32
	// [Min] 解析每一个数字，如果大于等于1<<30，跳出
	for _, d := range service {
		if '0' <= d && d <= '9' {
			d -= '0'
		} else {
			return 0, true
		}
		if n >= cutoff {
			n = max
			break
		}
		n *= 10
		nn := n + uint32(d)
		if nn < n || nn > max {
			n = max
			break
		}
		n = nn
	}
	// [Min] 最终范围为[-1<<30,1<<30-1] [-1073741824,1073741823]
	if !neg && n >= cutoff {
		port = int(cutoff - 1)
	} else if neg && n > cutoff {
		port = int(cutoff)
	} else {
		port = int(n)
	}
	if neg {
		port = -port
	}
	return port, false
}
