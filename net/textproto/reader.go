// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package textproto

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
)

// A Reader implements convenience methods for reading requests
// or responses from a text protocol network connection.
// [Min] 读取数据的载体
type Reader struct {
	R   *bufio.Reader
	dot *dotReader
	buf []byte // a re-usable buffer for readContinuedLineSlice
}

// NewReader returns a new Reader reading from r.
//
// To avoid denial of service attacks, the provided bufio.Reader
// should be reading from an io.LimitReader or similar Reader to bound
// the size of responses.
func NewReader(r *bufio.Reader) *Reader {
	return &Reader{R: r}
}

// ReadLine reads a single line from r,
// eliding the final \n or \r\n from the returned string.
// [Min] 在 r.R中读取一行
func (r *Reader) ReadLine() (string, error) {
	line, err := r.readLineSlice()
	return string(line), err
}

// ReadLineBytes is like ReadLine but returns a []byte instead of a string.
// [Min] 在 r.R 中读取一行，返回数据的拷贝
func (r *Reader) ReadLineBytes() ([]byte, error) {
	line, err := r.readLineSlice()
	if line != nil {
		buf := make([]byte, len(line))
		copy(buf, line)
		line = buf
	}
	return line, err
}

// [Min] 在 r.R 中读取一行，由于调用的是 bufio.ReadLine，返回的是源 buf 的部分引用，要及时处理
func (r *Reader) readLineSlice() ([]byte, error) {
	r.closeDot()
	var line []byte
	for {
		l, more, err := r.R.ReadLine()
		if err != nil {
			return nil, err
		}
		// Avoid the copy if the first call produced a full line.
		if line == nil && !more {
			return l, nil
		}
		line = append(line, l...)
		if !more {
			break
		}
	}
	return line, nil
}

// ReadContinuedLine reads a possibly continued line from r,
// eliding the final trailing ASCII white space.
// Lines after the first are considered continuations if they
// begin with a space or tab character. In the returned data,
// continuation lines are separated from the previous line
// only by a single space: the newline and leading white space
// are removed.
//
// For example, consider this input:
//
//	Line 1
//	  continued...
//	Line 2
//
// The first call to ReadContinuedLine will return "Line 1 continued..."
// and the second will return "Line 2".
//
// A line consisting of only white space is never continued.
//
// [Min] 读取连续行
func (r *Reader) ReadContinuedLine() (string, error) {
	line, err := r.readContinuedLineSlice()
	return string(line), err
}

// trim returns s with leading and trailing spaces and tabs removed.
// It does not assume Unicode or UTF-8.
// [Min] 去掉头尾的' '和'\t'
func trim(s []byte) []byte {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	n := len(s)
	for n > i && (s[n-1] == ' ' || s[n-1] == '\t') {
		n--
	}
	return s[i:n]
}

// ReadContinuedLineBytes is like ReadContinuedLine but
// returns a []byte instead of a string.
// [Min] 读取连续行，返回拷贝
func (r *Reader) ReadContinuedLineBytes() ([]byte, error) {
	line, err := r.readContinuedLineSlice()
	if line != nil {
		buf := make([]byte, len(line))
		copy(buf, line)
		line = buf
	}
	return line, err
}

// [Min] 读取连续的行，即行首为 space 或 tab 的行默认为上一行的延续
func (r *Reader) readContinuedLineSlice() ([]byte, error) {
	// Read the first line.
	line, err := r.readLineSlice()
	if err != nil {
		return nil, err
	}
	if len(line) == 0 { // blank line - no continuation
		return line, nil
	}

	// Optimistically assume that we have started to buffer the next line
	// and it starts with an ASCII letter (the next header key), so we can
	// avoid copying that buffered data around in memory and skipping over
	// non-existent whitespace.
	// [Min] 下一行开头是字母，则不是连续行，直接返回
	if r.R.Buffered() > 1 {
		peek, err := r.R.Peek(1)
		if err == nil && isASCIILetter(peek[0]) {
			return trim(line), nil
		}
	}

	// ReadByte or the next readLineSlice will flush the read buffer;
	// copy the slice into buf.
	// [Min] 暂存当前已读行，为拼接连续行做准备
	r.buf = append(r.buf[:0], trim(line)...)

	// Read continuation lines.
	// [Min] 读取接下来的所有连续行，用' '连接
	for r.skipSpace() > 0 {
		line, err := r.readLineSlice()
		if err != nil {
			break
		}
		r.buf = append(r.buf, ' ')
		r.buf = append(r.buf, trim(line)...)
	}
	// [Min] 从暂存 buf 中返回连续行
	return r.buf, nil
}

// skipSpace skips R over all spaces and returns the number of bytes skipped.
// [Min] 跳过' '和'\t'，返回跳过的字符数
func (r *Reader) skipSpace() int {
	n := 0
	for {
		c, err := r.R.ReadByte()
		if err != nil {
			// Bufio will keep err until next read.
			break
		}
		if c != ' ' && c != '\t' {
			r.R.UnreadByte()
			break
		}
		n++
	}
	return n
}

func (r *Reader) readCodeLine(expectCode int) (code int, continued bool, message string, err error) {
	line, err := r.ReadLine()
	if err != nil {
		return
	}
	return parseCodeLine(line, expectCode)
}

// [Min] 解析 codeline：3位 code + 连接符' '/'-' + msg
func parseCodeLine(line string, expectCode int) (code int, continued bool, message string, err error) {
	// [Min] line 总长小于4或者 code 和 msg 的连接符不是' ','-'，报错
	if len(line) < 4 || line[3] != ' ' && line[3] != '-' {
		err = ProtocolError("short response: " + line)
		return
	}
	continued = line[3] == '-'          // [Min] 连接符是否为'-'
	code, err = strconv.Atoi(line[0:3]) // [Min] 解析 code
	if err != nil || code < 100 {
		err = ProtocolError("invalid response code: " + line)
		return
	}
	message = line[4:]
	// [Min] code和 expectcode 左边需匹配，expectcode <= 0 时无需匹配
	if 1 <= expectCode && expectCode < 10 && code/100 != expectCode ||
		10 <= expectCode && expectCode < 100 && code/10 != expectCode ||
		100 <= expectCode && expectCode < 1000 && code != expectCode {
		err = &Error{code, message}
	}
	return
}

// ReadCodeLine reads a response code line of the form
//	code message
// where code is a three-digit status code and the message
// extends to the rest of the line. An example of such a line is:
//	220 plan9.bell-labs.com ESMTP
//
// If the prefix of the status does not match the digits in expectCode,
// ReadCodeLine returns with err set to &Error{code, message}.
// For example, if expectCode is 31, an error will be returned if
// the status is not in the range [310,319].
//
// If the response is multi-line, ReadCodeLine returns an error.
//
// An expectCode <= 0 disables the check of the status code.
//
// [Min] 读取 codeline
func (r *Reader) ReadCodeLine(expectCode int) (code int, message string, err error) {
	code, continued, message, err := r.readCodeLine(expectCode)
	if err == nil && continued {
		err = ProtocolError("unexpected multi-line response: " + message)
	}
	return
}

// ReadResponse reads a multi-line response of the form:
//
//	code-message line 1
//	code-message line 2
//	...
//	code message line n
//
// where code is a three-digit status code. The first line starts with the
// code and a hyphen. The response is terminated by a line that starts
// with the same code followed by a space. Each line in message is
// separated by a newline (\n).
//
// See page 36 of RFC 959 (http://www.ietf.org/rfc/rfc959.txt) for
// details of another form of response accepted:
//
//  code-message line 1
//  message line 2
//  ...
//  code message line n
//
// If the prefix of the status does not match the digits in expectCode,
// ReadResponse returns with err set to &Error{code, message}.
// For example, if expectCode is 31, an error will be returned if
// the status is not in the range [310,319].
//
// An expectCode <= 0 disables the check of the status code.
//
// [Min] 读取多行返回信息
func (r *Reader) ReadResponse(expectCode int) (code int, message string, err error) {
	code, continued, message, err := r.readCodeLine(expectCode)
	multi := continued
	for continued {
		line, err := r.ReadLine()
		if err != nil {
			return 0, "", err
		}

		var code2 int
		var moreMessage string
		code2, continued, moreMessage, err = parseCodeLine(line, 0)
		if err != nil || code2 != code {
			message += "\n" + strings.TrimRight(line, "\r\n")
			continued = true
			continue
		}
		message += "\n" + moreMessage
	}
	if err != nil && multi && message != "" {
		// replace one line error message with all lines (full message)
		err = &Error{code, message}
	}
	return
}

// DotReader returns a new Reader that satisfies Reads using the
// decoded text of a dot-encoded block read from r.
// The returned Reader is only valid until the next call
// to a method on r.
//
// Dot encoding is a common framing used for data blocks
// in text protocols such as SMTP.  The data consists of a sequence
// of lines, each of which ends in "\r\n".  The sequence itself
// ends at a line containing just a dot: ".\r\n".  Lines beginning
// with a dot are escaped with an additional dot to avoid
// looking like the end of the sequence.
//
// The decoded form returned by the Reader's Read method
// rewrites the "\r\n" line endings into the simpler "\n",
// removes leading dot escapes if present, and stops with error io.EOF
// after consuming (and discarding) the end-of-sequence line.
// [Min] 构造 dotReader，其中Reader 指向自己 r
func (r *Reader) DotReader() io.Reader {
	r.closeDot()
	r.dot = &dotReader{r: r}
	return r.dot
}

type dotReader struct {
	r     *Reader
	state int
}

// Read satisfies reads by decoding dot-encoded data read from d.r.
// [Min] 以 dotReader 的形式读取数据至 b
func (d *dotReader) Read(b []byte) (n int, err error) {
	// Run data through a simple state machine to
	// elide leading dots, rewrite trailing \r\n into \n,
	// and detect ending .\r\n line.
	const (
		stateBeginLine = iota // beginning of line; initial state; must be zero
		stateDot              // read . at beginning of line
		stateDotCR            // read .\r at beginning of line
		stateCR               // read \r (possibly at end of line)
		stateData             // reading data in middle of line
		stateEOF              // reached .\r\n end marker line
	)
	br := d.r.R
	for n < len(b) && d.state != stateEOF {
		var c byte
		c, err = br.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			break
		}
		switch d.state {
		case stateBeginLine:
			if c == '.' {
				d.state = stateDot
				continue
			}
			if c == '\r' {
				d.state = stateCR
				continue
			}
			d.state = stateData

		case stateDot:
			if c == '\r' {
				d.state = stateDotCR
				continue
			}
			if c == '\n' {
				d.state = stateEOF
				continue
			}
			d.state = stateData

		case stateDotCR:
			if c == '\n' {
				d.state = stateEOF
				continue
			}
			// Not part of .\r\n.
			// Consume leading dot and emit saved \r.
			br.UnreadByte()
			c = '\r'
			d.state = stateData

		case stateCR:
			if c == '\n' {
				d.state = stateBeginLine
				break
			}
			// Not part of \r\n. Emit saved \r
			br.UnreadByte()
			c = '\r'
			d.state = stateData

		case stateData:
			if c == '\r' {
				d.state = stateCR
				continue
			}
			if c == '\n' {
				d.state = stateBeginLine
			}
		}
		b[n] = c
		n++
	}
	if err == nil && d.state == stateEOF {
		err = io.EOF
	}
	if err != nil && d.r.dot == d {
		d.r.dot = nil
	}
	return
}

// closeDot drains the current DotReader if any,
// making sure that it reads until the ending dot line.
// [Min] 清空 r.dot 中的数据并置 r.dot = nil
func (r *Reader) closeDot() {
	if r.dot == nil {
		return
	}
	buf := make([]byte, 128)
	for r.dot != nil {
		// When Read reaches EOF or an error,
		// it will set r.dot == nil.
		r.dot.Read(buf)
	}
}

// ReadDotBytes reads a dot-encoding and returns the decoded data.
//
// See the documentation for the DotReader method for details about dot-encoding.
func (r *Reader) ReadDotBytes() ([]byte, error) {
	return ioutil.ReadAll(r.DotReader())
}

// ReadDotLines reads a dot-encoding and returns a slice
// containing the decoded lines, with the final \r\n or \n elided from each.
//
// See the documentation for the DotReader method for details about dot-encoding.
func (r *Reader) ReadDotLines() ([]string, error) {
	// We could use ReadDotBytes and then Split it,
	// but reading a line at a time avoids needing a
	// large contiguous block of memory and is simpler.
	var v []string
	var err error
	for {
		var line string
		line, err = r.ReadLine()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			break
		}

		// Dot by itself marks end; otherwise cut one dot.
		if len(line) > 0 && line[0] == '.' {
			if len(line) == 1 {
				break
			}
			line = line[1:]
		}
		v = append(v, line)
	}
	return v, err
}

// ReadMIMEHeader reads a MIME-style header from r.
// The header is a sequence of possibly continued Key: Value lines
// ending in a blank line.
// The returned map m maps CanonicalMIMEHeaderKey(key) to a
// sequence of values in the same order encountered in the input.
//
// For example, consider this input:
//
//	My-Key: Value 1
//	Long-Key: Even
//	       Longer Value
//	My-Key: Value 2
//
// Given that input, ReadMIMEHeader returns the map:
//
//	map[string][]string{
//		"My-Key": {"Value 1", "Value 2"},
//		"Long-Key": {"Even Longer Value"},
//	}
// [Min] 从 r 中读取数据并返回MIMEHeader
func (r *Reader) ReadMIMEHeader() (MIMEHeader, error) {
	// Avoid lots of small slice allocations later by allocating one
	// large one ahead of time which we'll cut up into smaller
	// slices. If this isn't big enough later, we allocate small ones.
	var strs []string
	hint := r.upcomingHeaderNewlines()
	if hint > 0 {
		strs = make([]string, hint)
	}

	m := make(MIMEHeader, hint)

	// The first line cannot start with a leading space.
	// [Min] 第一行不能以' '，'\t'开头
	if buf, err := r.R.Peek(1); err == nil && (buf[0] == ' ' || buf[0] == '\t') {
		line, err := r.readLineSlice()
		if err != nil {
			return m, err
		}
		return m, ProtocolError("malformed MIME header initial line: " + string(line))
	}

	for {
		kv, err := r.readContinuedLineSlice()
		if len(kv) == 0 {
			return m, err
		}

		// Key ends at first colon; should not have trailing spaces
		// but they appear in the wild, violating specs, so we remove
		// them if present.
		// [Min] ':'前为 key，去除右边的' '并canonicalMIMEHeaderKey标准化
		i := bytes.IndexByte(kv, ':')
		if i < 0 {
			return m, ProtocolError("malformed MIME header line: " + string(kv))
		}
		endKey := i
		for endKey > 0 && kv[endKey-1] == ' ' {
			endKey--
		}
		key := canonicalMIMEHeaderKey(kv[:endKey])

		// As per RFC 7230 field-name is a token, tokens consist of one or more chars.
		// We could return a ProtocolError here, but better to be liberal in what we
		// accept, so if we get an empty key, skip it.
		if key == "" {
			continue
		}

		// Skip initial spaces in value.
		i++ // skip colon
		for i < len(kv) && (kv[i] == ' ' || kv[i] == '\t') {
			i++
		}
		value := string(kv[i:])

		vv := m[key]
		if vv == nil && len(strs) > 0 {
			// More than likely this will be a single-element key.
			// Most headers aren't multi-valued.
			// Set the capacity on strs[0] to 1, so any future append
			// won't extend the slice into the other strings.
			vv, strs = strs[:1:1], strs[1:]
			vv[0] = value
			m[key] = vv
		} else {
			m[key] = append(vv, value)
		}

		if err != nil {
			return m, err
		}
	}
}

// upcomingHeaderNewlines returns an approximation of the number of newlines
// that will be in this header. If it gets confused, it returns 0.
// [Min] 返回 r.R 中的行数
func (r *Reader) upcomingHeaderNewlines() (n int) {
	// Try to determine the 'hint' size.
	r.R.Peek(1) // force a buffer load if empty
	s := r.R.Buffered()
	if s == 0 {
		return
	}
	peek, _ := r.R.Peek(s)
	for len(peek) > 0 {
		i := bytes.IndexByte(peek, '\n')
		if i < 3 {
			// Not present (-1) or found within the next few bytes,
			// implying we're at the end ("\r\n\r\n" or "\n\n")
			return
		}
		n++
		peek = peek[i+1:]
	}
	return
}

// CanonicalMIMEHeaderKey returns the canonical format of the
// MIME header key s. The canonicalization converts the first
// letter and any letter following a hyphen to upper case;
// the rest are converted to lowercase. For example, the
// canonical key for "accept-encoding" is "Accept-Encoding".
// MIME header keys are assumed to be ASCII only.
// If s contains a space or invalid header field bytes, it is
// returned without modifications.
// [Min] 标准化 header KEY，首字母大写，'-'后字母大写
func CanonicalMIMEHeaderKey(s string) string {
	// Quick check for canonical encoding.
	upper := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !validHeaderFieldByte(c) {
			return s
		}
		if upper && 'a' <= c && c <= 'z' {
			return canonicalMIMEHeaderKey([]byte(s))
		}
		if !upper && 'A' <= c && c <= 'Z' {
			return canonicalMIMEHeaderKey([]byte(s))
		}
		upper = c == '-'
	}
	return s
}

const toLower = 'a' - 'A'

// validHeaderFieldByte reports whether b is a valid byte in a header
// field name. RFC 7230 says:
//   header-field   = field-name ":" OWS field-value OWS
//   field-name     = token
//   tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
//           "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
//   token = 1*tchar
// [Min] Header 的有效字符
func validHeaderFieldByte(b byte) bool {
	return int(b) < len(isTokenTable) && isTokenTable[b]
}

// canonicalMIMEHeaderKey is like CanonicalMIMEHeaderKey but is
// allowed to mutate the provided byte slice before returning the
// string.
//
// For invalid inputs (if a contains spaces or non-token bytes), a
// is unchanged and a string copy is returned.
// [Min] canonicalMIMEHeaderKey标准化 KEY
func canonicalMIMEHeaderKey(a []byte) string {
	// See if a looks like a header key. If not, return it unchanged.
	for _, c := range a {
		if validHeaderFieldByte(c) {
			continue
		}
		// Don't canonicalize.
		return string(a)
	}

	upper := true
	for i, c := range a {
		// Canonicalize: first letter upper case
		// and upper case after each dash.
		// (Host, User-Agent, If-Modified-Since).
		// MIME headers are ASCII only, so no Unicode issues.
		if upper && 'a' <= c && c <= 'z' {
			c -= toLower
		} else if !upper && 'A' <= c && c <= 'Z' {
			c += toLower
		}
		a[i] = c
		upper = c == '-' // for next time
	}
	// The compiler recognizes m[string(byteSlice)] as a special
	// case, so a copy of a's bytes into a new string does not
	// happen in this map lookup:
	if v := commonHeader[string(a)]; v != "" {
		return v
	}
	return string(a)
}

// commonHeader interns common header strings.
var commonHeader = make(map[string]string)

func init() {
	for _, v := range []string{
		"Accept",
		"Accept-Charset",
		"Accept-Encoding",
		"Accept-Language",
		"Accept-Ranges",
		"Cache-Control",
		"Cc",
		"Connection",
		"Content-Id",
		"Content-Language",
		"Content-Length",
		"Content-Transfer-Encoding",
		"Content-Type",
		"Cookie",
		"Date",
		"Dkim-Signature",
		"Etag",
		"Expires",
		"From",
		"Host",
		"If-Modified-Since",
		"If-None-Match",
		"In-Reply-To",
		"Last-Modified",
		"Location",
		"Message-Id",
		"Mime-Version",
		"Pragma",
		"Received",
		"Return-Path",
		"Server",
		"Set-Cookie",
		"Subject",
		"To",
		"User-Agent",
		"Via",
		"X-Forwarded-For",
		"X-Imforwards",
		"X-Powered-By",
	} {
		commonHeader[v] = v
	}
}

// isTokenTable is a copy of net/http/lex.go's isTokenTable.
// See https://httpwg.github.io/specs/rfc7230.html#rule.token.separators
var isTokenTable = [127]bool{
	'!':  true,
	'#':  true,
	'$':  true,
	'%':  true,
	'&':  true,
	'\'': true,
	'*':  true,
	'+':  true,
	'-':  true,
	'.':  true,
	'0':  true,
	'1':  true,
	'2':  true,
	'3':  true,
	'4':  true,
	'5':  true,
	'6':  true,
	'7':  true,
	'8':  true,
	'9':  true,
	'A':  true,
	'B':  true,
	'C':  true,
	'D':  true,
	'E':  true,
	'F':  true,
	'G':  true,
	'H':  true,
	'I':  true,
	'J':  true,
	'K':  true,
	'L':  true,
	'M':  true,
	'N':  true,
	'O':  true,
	'P':  true,
	'Q':  true,
	'R':  true,
	'S':  true,
	'T':  true,
	'U':  true,
	'W':  true,
	'V':  true,
	'X':  true,
	'Y':  true,
	'Z':  true,
	'^':  true,
	'_':  true,
	'`':  true,
	'a':  true,
	'b':  true,
	'c':  true,
	'd':  true,
	'e':  true,
	'f':  true,
	'g':  true,
	'h':  true,
	'i':  true,
	'j':  true,
	'k':  true,
	'l':  true,
	'm':  true,
	'n':  true,
	'o':  true,
	'p':  true,
	'q':  true,
	'r':  true,
	's':  true,
	't':  true,
	'u':  true,
	'v':  true,
	'w':  true,
	'x':  true,
	'y':  true,
	'z':  true,
	'|':  true,
	'~':  true,
}
