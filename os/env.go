// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// General environment variables.

package os

import (
	"internal/testlog"
	"syscall"
)

// Expand replaces ${var} or $var in the string based on the mapping function.
// For example, os.ExpandEnv(s) is equivalent to os.Expand(s, os.Getenv).
// [Min] 将 s 中的 ${var}，$var 按定义好的 mapping 展开
func Expand(s string, mapping func(string) string) string {
	var buf []byte
	// ${} is all ASCII, so bytes are fine for this operation.
	i := 0
	for j := 0; j < len(s); j++ {
		// [Min] j 为 $ 标记所在索引，且 $ 不能为 s 的结尾
		if s[j] == '$' && j+1 < len(s) {
			if buf == nil {
				// [Min] 初始化 buf
				buf = make([]byte, 0, 2*len(s))
			}
			// [Min] 将 $ 之前不需要展开的部分写入 buf 中
			buf = append(buf, s[i:j]...)
			// [Min] 获取壳符号的 key，以及该壳符号所占的长度
			name, w := getShellName(s[j+1:])
			if name == "" && w > 0 {
				// Encountered invalid syntax; eat the
				// characters.
			} else if name == "" {
				// Valid syntax, but $ was not followed by a
				// name. Leave the dollar character untouched.
				buf = append(buf, s[j])
			} else {
				buf = append(buf, mapping(name)...)
			}
			j += w
			i = j + 1
		}
	}
	// [Min] 不存在有效的 $，无需展开，直接返回 s
	if buf == nil {
		return s
	}
	// [Min] 将后续不用展开的字符串添加到尾部，并返回最终结果
	return string(buf) + s[i:]
}

// ExpandEnv replaces ${var} or $var in the string according to the values
// of the current environment variables. References to undefined
// variables are replaced by the empty string.
// [Min] 根据环境变量的设置展开 s
func ExpandEnv(s string) string {
	return Expand(s, Getenv)
}

// isShellSpecialVar reports whether the character identifies a special
// shell variable such as $*.
// [Min] 特殊壳字符
func isShellSpecialVar(c uint8) bool {
	switch c {
	case '*', '#', '$', '@', '!', '?', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return true
	}
	return false
}

// isAlphaNum reports whether the byte is an ASCII letter, number, or underscore
// [Min] 下划线，数字，字母
func isAlphaNum(c uint8) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// getShellName returns the name that begins the string and the number of bytes
// consumed to extract it. If the name is enclosed in {}, it's part of a ${}
// expansion and two more bytes are needed than the length of the name.
// [Min] 获取壳符号真正的壳值，用于 mapping 函数
func getShellName(s string) (string, int) {
	switch {
	case s[0] == '{':
		// [Min] ${1} 等特殊单字符，直接返回该字符和该“壳符号”所占总长3
		if len(s) > 2 && isShellSpecialVar(s[1]) && s[2] == '}' {
			return s[1:2], 3
		}
		// Scan to closing brace
		// [Min] 查找与 s[0] '{' 匹配的 '}'，返回括号中的内容和相应的总长
		for i := 1; i < len(s); i++ {
			if s[i] == '}' {
				if i == 1 {
					return "", 2 // Bad syntax; eat "${}"
				}
				return s[1:i], i + 1
			}
		}
		// [Min] 没有匹配的 '}'，返回空字符串和1
		return "", 1 // Bad syntax; eat "${"
	case isShellSpecialVar(s[0]):
		// [Min] $1，$# 这种特殊单字符
		return s[0:1], 1
	}
	// Scan alphanumerics.
	// [Min] 下划线，数字，字母的组合看成一个整体
	var i int
	for i = 0; i < len(s) && isAlphaNum(s[i]); i++ {
	}
	return s[:i], i
}

// Getenv retrieves the value of the environment variable named by the key.
// It returns the value, which will be empty if the variable is not present.
// To distinguish between an empty value and an unset value, use LookupEnv.
// [Min] 获取环境变量 key 的值，如果 key 不存在于环境变量中，返回空
// [Min] 需要注意的是如果 key 在环境变量中有但是没有设置具体的值，也返回空，
// [Min] 如果需要区分不同的空值，则需要调用 LookupEnv 函数
func Getenv(key string) string {
	testlog.Getenv(key)
	v, _ := syscall.Getenv(key)
	return v
}

// LookupEnv retrieves the value of the environment variable named
// by the key. If the variable is present in the environment the
// value (which may be empty) is returned and the boolean is true.
// Otherwise the returned value will be empty and the boolean will
// be false.
// [Min] LookupEnv 和 Getenv 差不多，多一个 bool 变量用于判断 key 是否存在
func LookupEnv(key string) (string, bool) {
	testlog.Getenv(key)
	return syscall.Getenv(key)
}

// Setenv sets the value of the environment variable named by the key.
// It returns an error, if any.
// [Min] 设置环境变量
func Setenv(key, value string) error {
	err := syscall.Setenv(key, value)
	if err != nil {
		return NewSyscallError("setenv", err)
	}
	return nil
}

// Unsetenv unsets a single environment variable.
// [Min] 取消环境变量
func Unsetenv(key string) error {
	return syscall.Unsetenv(key)
}

// Clearenv deletes all environment variables.
// [Min] 清除所有的环境变量
func Clearenv() {
	syscall.Clearenv()
}

// Environ returns a copy of strings representing the environment,
// in the form "key=value".
// [Min] 以“ key=value ”的格式返回表示所有环境变量的字符串
func Environ() []string {
	return syscall.Environ()
}
