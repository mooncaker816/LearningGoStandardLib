// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bytes"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// A Cookie represents an HTTP cookie as sent in the Set-Cookie header of an
// HTTP response or the Cookie header of an HTTP request.
//
// See http://tools.ietf.org/html/rfc6265 for details.
type Cookie struct {
	Name  string
	Value string

	Path       string    // optional
	Domain     string    // optional
	Expires    time.Time // optional
	RawExpires string    // for reading cookies only

	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'
	// MaxAge>0 means Max-Age attribute present and given in seconds
	MaxAge   int
	Secure   bool
	HttpOnly bool
	Raw      string
	Unparsed []string // Raw text of unparsed attribute-value pairs
}

// readSetCookies parses all "Set-Cookie" values from
// the header h and returns the successfully parsed Cookies.
// [Min] 从 header 中读取Set-Cookie的内容并解析为 cookies 返回
func readSetCookies(h Header) []*Cookie {
	cookieCount := len(h["Set-Cookie"])
	// [Min] 没有 cookie 返回空
	if cookieCount == 0 {
		return []*Cookie{}
	}
	cookies := make([]*Cookie, 0, cookieCount)
	for _, line := range h["Set-Cookie"] {
		// [Min] 以";"为间隔分离每一段 cookie 字符串
		parts := strings.Split(strings.TrimSpace(line), ";")
		// [Min] 如果只有一个空的 cookie 字符串，则跳过，继续处理后续的Set-Cookie
		if len(parts) == 1 && parts[0] == "" {
			continue
		}
		// [Min] 处理第一段也就是 name = value
		parts[0] = strings.TrimSpace(parts[0])
		// [Min] 以"="分离出 name 和 value
		j := strings.Index(parts[0], "=")
		if j < 0 {
			continue
		}
		name, value := parts[0][:j], parts[0][j+1:]
		// [Min] 分别验证 name 和 value 的有效性
		if !isCookieNameValid(name) {
			continue
		}
		value, ok := parseCookieValue(value, true)
		if !ok {
			continue
		}
		c := &Cookie{
			Name:  name,
			Value: value,
			Raw:   line,
		}
		// [Min] 对后续的每一段设置 cookie 的属性
		for i := 1; i < len(parts); i++ {
			parts[i] = strings.TrimSpace(parts[i])
			if len(parts[i]) == 0 {
				continue
			}
			// [Min] 同样以"="分隔属性名和属性值
			attr, val := parts[i], ""
			if j := strings.Index(attr, "="); j >= 0 {
				attr, val = attr[:j], attr[j+1:]
			}
			// [Min] 转属性名为小写，用于后续比较
			lowerAttr := strings.ToLower(attr)
			val, ok = parseCookieValue(val, false)
			// [Min] 如果属性值解析失败，添加该段字符串到该 cookie 的 unparsed 切片中
			if !ok {
				c.Unparsed = append(c.Unparsed, parts[i])
				continue
			}
			// [Min] 对比属性名，设置一系列已知的属性
			switch lowerAttr {
			case "secure":
				c.Secure = true
				continue
			case "httponly":
				c.HttpOnly = true
				continue
			case "domain":
				c.Domain = val
				continue
			case "max-age":
				secs, err := strconv.Atoi(val)
				if err != nil || secs != 0 && val[0] == '0' {
					break
				}
				if secs <= 0 {
					secs = -1
				}
				c.MaxAge = secs
				continue
			case "expires":
				c.RawExpires = val
				exptime, err := time.Parse(time.RFC1123, val)
				if err != nil {
					exptime, err = time.Parse("Mon, 02-Jan-2006 15:04:05 MST", val)
					if err != nil {
						c.Expires = time.Time{}
						break
					}
				}
				c.Expires = exptime.UTC()
				continue
			case "path":
				c.Path = val
				continue
			}
			// [Min] 将未知的属性名归到 unparsed 类别中
			c.Unparsed = append(c.Unparsed, parts[i])
		}
		cookies = append(cookies, c)
	}
	return cookies
}

// SetCookie adds a Set-Cookie header to the provided ResponseWriter's headers.
// The provided cookie must have a valid Name. Invalid cookies may be
// silently dropped.
// [Min] 在 w 的 header 中添加Set-Cookie
func SetCookie(w ResponseWriter, cookie *Cookie) {
	if v := cookie.String(); v != "" {
		w.Header().Add("Set-Cookie", v)
	}
}

// String returns the serialization of the cookie for use in a Cookie
// header (if only Name and Value are set) or a Set-Cookie response
// header (if other fields are set).
// If c is nil or c.Name is invalid, the empty string is returned.
// [Min] cookie对应的字符串，相当于 Set-Cookie 的值
func (c *Cookie) String() string {
	if c == nil || !isCookieNameValid(c.Name) {
		return ""
	}
	// [Min] 先写入 name=value
	var b bytes.Buffer
	b.WriteString(sanitizeCookieName(c.Name))
	b.WriteRune('=')
	b.WriteString(sanitizeCookieValue(c.Value))

	// [Min] 再写入Path 属性，以"; "分隔
	if len(c.Path) > 0 {
		b.WriteString("; Path=")
		b.WriteString(sanitizeCookiePath(c.Path))
	}
	if len(c.Domain) > 0 {
		// [Min] 检查 domain 是否有效，若有效写入，若无效，记日志
		if validCookieDomain(c.Domain) {
			// A c.Domain containing illegal characters is not
			// sanitized but simply dropped which turns the cookie
			// into a host-only cookie. A leading dot is okay
			// but won't be sent.
			d := c.Domain
			if d[0] == '.' {
				d = d[1:]
			}
			b.WriteString("; Domain=")
			b.WriteString(d)
		} else {
			log.Printf("net/http: invalid Cookie.Domain %q; dropping domain attribute", c.Domain)
		}
	}
	// [Min] 以TimeFormat的格式写入过期时间
	if validCookieExpires(c.Expires) {
		b.WriteString("; Expires=")
		b2 := b.Bytes()
		b.Reset()
		b.Write(c.Expires.UTC().AppendFormat(b2, TimeFormat))
	}
	// [Min] 写入 MaxAge，如果小于0，记为0
	if c.MaxAge > 0 {
		b.WriteString("; Max-Age=")
		b2 := b.Bytes()
		b.Reset()
		b.Write(strconv.AppendInt(b2, int64(c.MaxAge), 10))
	} else if c.MaxAge < 0 {
		b.WriteString("; Max-Age=0")
	}
	// [Min] 写入 HttpOnly
	if c.HttpOnly {
		b.WriteString("; HttpOnly")
	}
	// [Min] 写入 Secure
	if c.Secure {
		b.WriteString("; Secure")
	}
	return b.String()
}

// readCookies parses all "Cookie" values from the header h and
// returns the successfully parsed Cookies.
//
// if filter isn't empty, only cookies of that name are returned
// [Min] 从 header 中读取 cookie，如果 filter 不为空，则只返回以 filter为 name 的 cookie
// [Min] 和 readSetCookies 类似
func readCookies(h Header, filter string) []*Cookie {
	lines, ok := h["Cookie"]
	if !ok {
		return []*Cookie{}
	}

	cookies := []*Cookie{}
	for _, line := range lines {
		parts := strings.Split(strings.TrimSpace(line), ";")
		if len(parts) == 1 && parts[0] == "" {
			continue
		}
		// Per-line attributes
		for i := 0; i < len(parts); i++ {
			parts[i] = strings.TrimSpace(parts[i])
			if len(parts[i]) == 0 {
				continue
			}
			name, val := parts[i], ""
			if j := strings.Index(name, "="); j >= 0 {
				name, val = name[:j], name[j+1:]
			}
			if !isCookieNameValid(name) {
				continue
			}
			if filter != "" && filter != name {
				continue
			}
			val, ok := parseCookieValue(val, true)
			if !ok {
				continue
			}
			cookies = append(cookies, &Cookie{Name: name, Value: val})
		}
	}
	return cookies
}

// validCookieDomain returns whether v is a valid cookie domain-value.
// [Min] 检查 cookie 的 domain 属性是否有效
func validCookieDomain(v string) bool {
	// [Min] 先检查 v 是否是有效的字母字符串 domain，如 www.xxx.com
	if isCookieDomainName(v) {
		return true
	}
	// [Min] 检查是否为有效的 ip domain ，如192.xxx.xxx.xxx
	if net.ParseIP(v) != nil && !strings.Contains(v, ":") {
		return true
	}
	return false
}

// validCookieExpires returns whether v is a valid cookie expires-value.
// [Min] cookie的过期时间是否有效，年份需大于1601
func validCookieExpires(t time.Time) bool {
	// IETF RFC 6265 Section 5.1.1.5, the year must not be less than 1601
	return t.Year() >= 1601
}

// isCookieDomainName returns whether s is a valid domain name or a valid
// domain name with a leading dot '.'.  It is almost a direct copy of
// package net's isDomainName.
// [Min] 检查 s 是否为 domain name
func isCookieDomainName(s string) bool {
	if len(s) == 0 {
		return false
	}
	if len(s) > 255 {
		return false
	}

	if s[0] == '.' {
		// A cookie a domain attribute may start with a leading dot.
		s = s[1:]
	}
	last := byte('.')
	ok := false // Ok once we've seen a letter.
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
			// No '_' allowed here (in contrast to package net).
			ok = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return ok
}

var cookieNameSanitizer = strings.NewReplacer("\n", "-", "\r", "-")

// [Min] 将 cookie name 中的'\r','\n'替换为'-'
func sanitizeCookieName(n string) string {
	return cookieNameSanitizer.Replace(n)
}

// http://tools.ietf.org/html/rfc6265#section-4.1.1
// cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
// cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
//           ; US-ASCII characters excluding CTLs,
//           ; whitespace DQUOTE, comma, semicolon,
//           ; and backslash
// We loosen this as spaces and commas are common in cookie values
// but we produce a quoted cookie-value in when value starts or ends
// with a comma or space.
// See https://golang.org/issue/7243 for the discussion.
func sanitizeCookieValue(v string) string {
	// [Min] 忽略无效字节后的字符串 v
	v = sanitizeOrWarn("Cookie.Value", validCookieValueByte, v)
	if len(v) == 0 {
		return v
	}
	// [Min] 如果 value 中还有空格或逗号，则在 value 外加上双引号
	if strings.IndexByte(v, ' ') >= 0 || strings.IndexByte(v, ',') >= 0 {
		return `"` + v + `"`
	}
	return v
}

// [Min] cookie value 单字节是否有效
func validCookieValueByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != '"' && b != ';' && b != '\\'
}

// path-av           = "Path=" path-value
// path-value        = <any CHAR except CTLs or ";">
// [Min] 预处理 path 的 value，忽略无效字节
func sanitizeCookiePath(v string) string {
	return sanitizeOrWarn("Cookie.Path", validCookiePathByte, v)
}

// [Min] cookie path 的字节是否有效
func validCookiePathByte(b byte) bool {
	return 0x20 <= b && b < 0x7f && b != ';'
}

// [Min] 逐个字节检查v 是否有效，如有无效的字节，则记录日志，并返回忽略无效字节后的字符串
func sanitizeOrWarn(fieldName string, valid func(byte) bool, v string) string {
	ok := true
	for i := 0; i < len(v); i++ {
		if valid(v[i]) {
			continue
		}
		log.Printf("net/http: invalid byte %q in %s; dropping invalid bytes", v[i], fieldName)
		ok = false
		break
	}
	if ok {
		return v
	}
	buf := make([]byte, 0, len(v))
	for i := 0; i < len(v); i++ {
		if b := v[i]; valid(b) {
			buf = append(buf, b)
		}
	}
	return string(buf)
}

// [Min] 解析 cookie value
func parseCookieValue(raw string, allowDoubleQuote bool) (string, bool) {
	// Strip the quotes, if present.
	// [Min] 如果是双引号引起来的值，先去掉双引号
	if allowDoubleQuote && len(raw) > 1 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		raw = raw[1 : len(raw)-1]
	}
	// [Min] 验证 value 中的每个字节是否有效
	for i := 0; i < len(raw); i++ {
		if !validCookieValueByte(raw[i]) {
			return "", false
		}
	}
	return raw, true
}

// [Min] 检验 cookie name 是否有效
func isCookieNameValid(raw string) bool {
	if raw == "" {
		return false
	}
	return strings.IndexFunc(raw, isNotToken) < 0
}
