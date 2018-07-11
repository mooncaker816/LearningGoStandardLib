// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP file system request handler

package http

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// A Dir implements FileSystem using the native file system restricted to a
// specific directory tree.
//
// While the FileSystem.Open method takes '/'-separated paths, a Dir's string
// value is a filename on the native file system, not a URL, so it is separated
// by filepath.Separator, which isn't necessarily '/'.
//
// Note that Dir will allow access to files and directories starting with a
// period, which could expose sensitive directories like a .git directory or
// sensitive files like .htpasswd. To exclude files with a leading period,
// remove the files/directories from the server or create a custom FileSystem
// implementation.
//
// An empty Dir is treated as ".".
type Dir string

// mapDirOpenError maps the provided non-nil error from opening name
// to a possibly better non-nil error. In particular, it turns OS-specific errors
// about opening files in non-directories into os.ErrNotExist. See Issue 18984.
// [Min]  细分 Dir.Open 的 error
func mapDirOpenError(originalErr error, name string) error {
	// [Min] 首先检查是否是IsNotExist，或者IsPermission，是就直接返回
	if os.IsNotExist(originalErr) || os.IsPermission(originalErr) {
		return originalErr
	}
	// [Min] 如果不是以上两类错误，则从 root 开始累加每一层目录为路径，依次进行 Stat，
	// [Min] 如果报错，则直接返回原始错误，如果不报错，则当前路径必须是目录才可以，否则返回ErrNotExist
	parts := strings.Split(name, string(filepath.Separator))
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		fi, err := os.Stat(strings.Join(parts[:i+1], string(filepath.Separator)))
		if err != nil {
			return originalErr
		}
		if !fi.IsDir() {
			return os.ErrNotExist
		}
	}
	return originalErr
}

// [Min] 打开 Dir 目录下的 name 文件
func (d Dir) Open(name string) (File, error) {
	if filepath.Separator != '/' && strings.ContainsRune(name, filepath.Separator) {
		return nil, errors.New("http: invalid character in file path")
	}
	dir := string(d)
	if dir == "" {
		dir = "."
	}
	fullName := filepath.Join(dir, filepath.FromSlash(path.Clean("/"+name)))
	f, err := os.Open(fullName)
	if err != nil {
		return nil, mapDirOpenError(err, fullName)
	}
	return f, nil
}

// A FileSystem implements access to a collection of named files.
// The elements in a file path are separated by slash ('/', U+002F)
// characters, regardless of host operating system convention.
type FileSystem interface {
	Open(name string) (File, error)
}

// A File is returned by a FileSystem's Open method and can be
// served by the FileServer implementation.
//
// The methods should behave the same as those on an *os.File.
type File interface {
	io.Closer
	io.Reader
	io.Seeker
	Readdir(count int) ([]os.FileInfo, error)
	Stat() (os.FileInfo, error)
}

// [Min] 列出目录 f 下的所有文件和目录，并以<pre>标签包裹着路径链接的形式返回
func dirList(w ResponseWriter, r *Request, f File) {
	dirs, err := f.Readdir(-1)
	if err != nil {
		logf(r, "http: error reading directory: %v", err)
		Error(w, "Error reading directory", StatusInternalServerError)
		return
	}
	// [Min] 按路径名字典序排序
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name() < dirs[j].Name() })

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, "<pre>\n")
	for _, d := range dirs {
		name := d.Name()
		if d.IsDir() {
			name += "/"
		}
		// name may contain '?' or '#', which must be escaped to remain
		// part of the URL path, and not indicate the start of a query
		// string or fragment.
		url := url.URL{Path: name}
		// [Min] 对显示的文本名称 html 转义
		fmt.Fprintf(w, "<a href=\"%s\">%s</a>\n", url.String(), htmlReplacer.Replace(name))
	}
	fmt.Fprintf(w, "</pre>\n")
}

// ServeContent replies to the request using the content in the
// provided ReadSeeker. The main benefit of ServeContent over io.Copy
// is that it handles Range requests properly, sets the MIME type, and
// handles If-Match, If-Unmodified-Since, If-None-Match, If-Modified-Since,
// and If-Range requests.
//
// If the response's Content-Type header is not set, ServeContent
// first tries to deduce the type from name's file extension and,
// if that fails, falls back to reading the first block of the content
// and passing it to DetectContentType.
// The name is otherwise unused; in particular it can be empty and is
// never sent in the response.
//
// If modtime is not the zero time or Unix epoch, ServeContent
// includes it in a Last-Modified header in the response. If the
// request includes an If-Modified-Since header, ServeContent uses
// modtime to decide whether the content needs to be sent at all.
//
// The content's Seek method must work: ServeContent uses
// a seek to the end of the content to determine its size.
//
// If the caller has set w's ETag header formatted per RFC 7232, section 2.3,
// ServeContent uses it to handle requests using If-Match, If-None-Match, or If-Range.
//
// Note that *os.File implements the io.ReadSeeker interface.
func ServeContent(w ResponseWriter, req *Request, name string, modtime time.Time, content io.ReadSeeker) {
	// [Min] 获取 content 大小的函数
	sizeFunc := func() (int64, error) {
		size, err := content.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, errSeeker
		}
		_, err = content.Seek(0, io.SeekStart)
		if err != nil {
			return 0, errSeeker
		}
		return size, nil
	}
	serveContent(w, req, name, modtime, sizeFunc, content)
}

// errSeeker is returned by ServeContent's sizeFunc when the content
// doesn't seek properly. The underlying Seeker's error text isn't
// included in the sizeFunc reply so it's not sent over HTTP to end
// users.
var errSeeker = errors.New("seeker can't seek")

// errNoOverlap is returned by serveContent's parseRange if first-byte-pos of
// all of the byte-range-spec values is greater than the content size.
var errNoOverlap = errors.New("invalid range: failed to overlap")

// if name is empty, filename is unknown. (used for mime type, before sniffing)
// if modtime.IsZero(), modtime is unknown.
// content must be seeked to the beginning of the file.
// The sizeFunc is called at most once. Its error, if any, is sent in the HTTP response.
// [Min] name 为想要返回内容的文件名
func serveContent(w ResponseWriter, r *Request, name string, modtime time.Time, sizeFunc func() (int64, error), content io.ReadSeeker) {
	// [Min] 根据 modtime 设置 Last-Modified
	setLastModified(w, modtime)
	done, rangeReq := checkPreconditions(w, r, modtime)
	// [Min] 返回 done 为真，说明在Preconditions的检查阶段已经可以确定不需要返回 content 的实体内容了，
	// [Min] 相应的返回信息也已经在 Header 中标明，直接返回即可
	if done {
		return
	}
	// [Min] 后续操作，需要返回 content，设置 status 200
	code := StatusOK

	// If Content-Type isn't set, use the file's extension to find it, but
	// if the Content-Type is unset explicitly, do not sniff the type.
	// [Min] 如果没有设置Content-Type，先尝试根据文件名的扩展名来确定Content-Type
	// [Min] 如果没有扩展名，从 content 中读取一段512位长的字符串，再由该段内容来判断 Content-Type
	ctypes, haveType := w.Header()["Content-Type"]
	var ctype string
	if !haveType {
		ctype = mime.TypeByExtension(filepath.Ext(name))
		if ctype == "" {
			// read a chunk to decide between utf-8 text and binary
			var buf [sniffLen]byte
			n, _ := io.ReadFull(content, buf[:])
			ctype = DetectContentType(buf[:n])
			// [Min] 需要重置 content 的 offset
			_, err := content.Seek(0, io.SeekStart) // rewind to output whole file
			if err != nil {
				Error(w, "seeker can't seek", StatusInternalServerError)
				return
			}
		}
		// [Min] 设置Content-Type
		w.Header().Set("Content-Type", ctype)
	} else if len(ctypes) > 0 {
		// [Min] 如果有多个Content-Type，取第一个
		ctype = ctypes[0]
	}

	// [Min] 执行sizeFunc获得 content 的大小
	size, err := sizeFunc()
	if err != nil {
		Error(w, err.Error(), StatusInternalServerError)
		return
	}

	// handle Content-Range header.
	// [Min] 处理由checkPreconditions返回的 Range header，response 中的 header 为Content-Range
	// [Min] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Range
	// [Min] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Range
	sendSize := size
	var sendContent io.Reader = content
	if size >= 0 {
		ranges, err := parseRange(rangeReq, size)
		// [Min] range 段无效，报错
		if err != nil {
			if err == errNoOverlap {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", size))
			}
			Error(w, err.Error(), StatusRequestedRangeNotSatisfiable)
			return
		}
		// [Min] range段的总长超过文件大小，忽略 range，置 ranges 为nil
		if sumRangesSize(ranges) > size {
			// The total number of bytes in all the ranges
			// is larger than the size of the file by
			// itself, so this is probably an attack, or a
			// dumb client. Ignore the range request.
			ranges = nil
		}
		switch {
		case len(ranges) == 1:
			// RFC 2616, Section 14.16:
			// "When an HTTP message includes the content of a single
			// range (for example, a response to a request for a
			// single range, or to a request for a set of ranges
			// that overlap without any holes), this content is
			// transmitted with a Content-Range header, and a
			// Content-Length header showing the number of bytes
			// actually transferred.
			// ...
			// A response to a request for a single range MUST NOT
			// be sent using the multipart/byteranges media type."
			ra := ranges[0]
			if _, err := content.Seek(ra.start, io.SeekStart); err != nil {
				Error(w, err.Error(), StatusRequestedRangeNotSatisfiable)
				return
			}
			// [Min] sendSize 为该段 range 的长度
			sendSize = ra.length
			// [Min] 修改 code 为 206
			code = StatusPartialContent
			// [Min] 设置Content-Range，如 Content-Range: bytes 100-200/500
			w.Header().Set("Content-Range", ra.contentRange(size))
		case len(ranges) > 1:
			// [Min] 如果大于1个 range 段，先计算整个 multipart 实体的长度，如下是一个 multipart 的 response
			/* [Min]
			HTTP/1.1 206 Partial Content
			Content-Type: multipart/byteranges; boundary=3d6b6a416f9b5
			Content-Length: 282

			--3d6b6a416f9b5
			Content-Type: text/html
			Content-Range: bytes 0-50/1270

			<!doctype html>
			<html>
			<head>
			    <title>Example Do
			--3d6b6a416f9b5
			Content-Type: text/html
			Content-Range: bytes 100-150/1270

			eta http-equiv="Content-type" content="text/html; c
			--3d6b6a416f9b5--
			*/
			sendSize = rangesMIMESize(ranges, ctype, size)
			// [Min] 修改 code 为 206
			code = StatusPartialContent

			// [Min] 以 Pipe 的方式写入 multipart，并以 pw 为底层writer构造multipart writer
			pr, pw := io.Pipe()
			mw := multipart.NewWriter(pw)
			w.Header().Set("Content-Type", "multipart/byteranges; boundary="+mw.Boundary())
			sendContent = pr
			defer pr.Close() // cause writing goroutine to fail and exit if CopyN doesn't finish.
			// [Min] 发起goroutine，向 PipeWriter pw 中写入数据，等待从 PipeReader pr 中读取数据
			go func() {
				for _, ra := range ranges {
					// [Min] 为当前 range 段写入边界 + header + 空行，并返回共用实体的 writer
					part, err := mw.CreatePart(ra.mimeHeader(ctype, size))
					if err != nil {
						pw.CloseWithError(err)
						return
					}
					// [Min] 设置文件的读取位置为该 range 段的起始位置
					if _, err := content.Seek(ra.start, io.SeekStart); err != nil {
						pw.CloseWithError(err)
						return
					}
					// [Min] 将该 range 段在文件中对应的部分写入上述返回的 writer 中，以完成该 range 的写入
					if _, err := io.CopyN(part, content, ra.length); err != nil {
						pw.CloseWithError(err)
						return
					}
				}
				mw.Close()
				pw.Close()
			}()
		}

		// [Min] 设置 response 其他 header
		w.Header().Set("Accept-Ranges", "bytes")
		if w.Header().Get("Content-Encoding") == "" {
			w.Header().Set("Content-Length", strconv.FormatInt(sendSize, 10))
		}
	}

	w.WriteHeader(code)

	// [Min] HEAD 不用写 body
	if r.Method != "HEAD" {
		// [Min] 正式从 Pipe 中读取数据写入 ResponseWriter 中
		io.CopyN(w, sendContent, sendSize)
	}
}

// scanETag determines if a syntactically valid ETag is present at s. If so,
// the ETag and remaining text after consuming ETag is returned. Otherwise,
// it returns "", "".
// [Min] 获取 s 中的第一个 etag，并返回剩下的字符串
func scanETag(s string) (etag string, remain string) {
	s = textproto.TrimString(s)
	start := 0
	// [Min] 忽略 W/ 前缀
	if strings.HasPrefix(s, "W/") {
		start = 2
	}
	// [Min] etag 必须以双引号括起来，所以长度必须>=2，且起始字符为"，否则返回空
	if len(s[start:]) < 2 || s[start] != '"' {
		return "", ""
	}
	// ETag is either W/"text" or "text".
	// See RFC 7232 2.3.
	for i := start + 1; i < len(s); i++ {
		c := s[i]
		switch {
		// Character values allowed in ETags.
		// [Min] 碰到有效字符，继续循环
		case c == 0x21 || c >= 0x23 && c <= 0x7E || c >= 0x80:
		// [Min] 碰到"，说明当前 etag 结束，返回
		case c == '"':
			return s[:i+1], s[i+1:]
		// [Min] 无效字符，返回空
		default:
			return "", ""
		}
	}
	return "", ""
}

// etagStrongMatch reports whether a and b match using strong ETag comparison.
// Assumes a and b are valid ETags.
// [Min] 两个字符串必须完全相同，且不为空，不以"开头
func etagStrongMatch(a, b string) bool {
	return a == b && a != "" && a[0] == '"'
}

// etagWeakMatch reports whether a and b match using weak ETag comparison.
// Assumes a and b are valid ETags.
// [Min] 去掉前缀W/后，两个字符串相同
func etagWeakMatch(a, b string) bool {
	return strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// condResult is the result of an HTTP request precondition check.
// See https://tools.ietf.org/html/rfc7232 section 3.
type condResult int

const (
	condNone condResult = iota
	condTrue
	condFalse
)

// [Min] 检查 If-Match 中的 etag 是否匹配
// [Min] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Match
func checkIfMatch(w ResponseWriter, r *Request) condResult {
	im := r.Header.Get("If-Match")
	// [Min] 没有 If-Match，直接返回condNone
	if im == "" {
		return condNone
	}
	for {
		im = textproto.TrimString(im)
		if len(im) == 0 {
			break
		}
		if im[0] == ',' {
			im = im[1:]
			continue
		}
		// [Min] 如果是通配符，返回condTrue
		if im[0] == '*' {
			return condTrue
		}
		// [Min] 搜索一个 etag
		etag, remain := scanETag(im)
		if etag == "" {
			break
		}
		// [Min]  etag 强比较为真，则返回condTrue
		if etagStrongMatch(etag, w.Header().get("Etag")) {
			return condTrue
		}
		im = remain
	}

	// [Min] 全都没有匹配，返回condFalse
	return condFalse
}

// [Min] 检查If-Unmodified-Since
// [Min] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Unmodified-Since
func checkIfUnmodifiedSince(r *Request, modtime time.Time) condResult {
	ius := r.Header.Get("If-Unmodified-Since")
	// [Min] 没有If-Unmodified-Since或者时间为零时间，则返回condNone
	if ius == "" || isZeroTime(modtime) {
		return condNone
	}
	// [Min] 解析时间，如果 modtime 在ius 之前，则返回 condTrue，否则返回 condFalse
	// [Min] 解析时间失败返回condNone
	if t, err := ParseTime(ius); err == nil {
		// The Date-Modified header truncates sub-second precision, so
		// use mtime < t+1s instead of mtime <= t to check for unmodified.
		if modtime.Before(t.Add(1 * time.Second)) {
			return condTrue
		}
		return condFalse
	}
	return condNone
}

// [Min] 检查If-None-Match，当 etag 不匹配时为真，匹配为假
// [Min] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-None-Match
func checkIfNoneMatch(w ResponseWriter, r *Request) condResult {
	inm := r.Header.get("If-None-Match")
	// [Min] 没有If-None-Match，返回condNone
	if inm == "" {
		return condNone
	}
	buf := inm
	for {
		buf = textproto.TrimString(buf)
		if len(buf) == 0 {
			break
		}
		if buf[0] == ',' {
			buf = buf[1:]
		}
		// [Min] 通配符，返回condFalse
		if buf[0] == '*' {
			return condFalse
		}
		etag, remain := scanETag(buf)
		if etag == "" {
			break
		}
		// [Min] 弱比较，匹配返回condFalse
		if etagWeakMatch(etag, w.Header().get("Etag")) {
			return condFalse
		}
		buf = remain
	}
	// [Min] 全都没有匹配，返回condTrue
	return condTrue
}

// [Min] 检查If-Modified-Since
// [Min] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Modified-Since
func checkIfModifiedSince(r *Request, modtime time.Time) condResult {
	// [Min] 只对 GET,HEAD 有效，其他返回condNone
	if r.Method != "GET" && r.Method != "HEAD" {
		return condNone
	}
	ims := r.Header.Get("If-Modified-Since")
	// [Min] 没有If-Modified-Since或者 modtime 为零时间，返回condNone
	if ims == "" || isZeroTime(modtime) {
		return condNone
	}
	// [Min] 解析时间，失败返回condNone
	t, err := ParseTime(ims)
	if err != nil {
		return condNone
	}
	// The Date-Modified header truncates sub-second precision, so
	// use mtime < t+1s instead of mtime <= t to check for unmodified.
	// [Min] 如果 modtime 在 ims 之前，返回condFalse，否则返回condTrue
	if modtime.Before(t.Add(1 * time.Second)) {
		return condFalse
	}
	return condTrue
}

// [Min] 检查 If-Range，只有在返回为假的时候，才会将 Range 条件置空
// [Min] https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/If-Range
func checkIfRange(w ResponseWriter, r *Request, modtime time.Time) condResult {
	// [Min] 非 GET,HEAD method 返回 condNone
	if r.Method != "GET" && r.Method != "HEAD" {
		return condNone
	}
	ir := r.Header.get("If-Range")
	// [Min] 没有 If-Range 返回 condNone
	if ir == "" {
		return condNone
	}
	// [Min] 注意，If-Range 可能是比较 etag，也可能是比较 modtime，但不可能同时比较两者，优先比较 etag
	// [Min] 先检查 etag，如果有 etag，且能够匹配，返回condTrue，否则返回condFalse
	etag, _ := scanETag(ir)
	if etag != "" {
		if etagStrongMatch(etag, w.Header().Get("Etag")) {
			return condTrue
		} else {
			return condFalse
		}
	}
	// The If-Range value is typically the ETag value, but it may also be
	// the modtime date. See golang.org/issue/8367.
	// [Min] If-Range 也有可能是修改时间，如果 modtime 是零时间，返回 condFalse
	if modtime.IsZero() {
		return condFalse
	}
	// [Min] 解析时间，失败返回condFalse
	t, err := ParseTime(ir)
	if err != nil {
		return condFalse
	}
	// [Min] 如果两个时间相同，返回condTrue，否则返回condFalse
	if t.Unix() == modtime.Unix() {
		return condTrue
	}
	return condFalse
}

var unixEpochTime = time.Unix(0, 0)

// isZeroTime reports whether t is obviously unspecified (either zero or Unix()=0).
// [Min] 是否为1年1月1日0时，或全0
func isZeroTime(t time.Time) bool {
	return t.IsZero() || t.Equal(unixEpochTime)
}

// [Min] 如果 modtime 不是零时间，则设置 Response header 中的Last-Modified为 modtime
func setLastModified(w ResponseWriter, modtime time.Time) {
	if !isZeroTime(modtime) {
		w.Header().Set("Last-Modified", modtime.UTC().Format(TimeFormat))
	}
}

// [Min] 写入StatusNotModified
func writeNotModified(w ResponseWriter) {
	// RFC 7232 section 4.1:
	// a sender SHOULD NOT generate representation metadata other than the
	// above listed fields unless said metadata exists for the purpose of
	// guiding cache updates (e.g., Last-Modified might be useful if the
	// response does not have an ETag field).
	h := w.Header()
	delete(h, "Content-Type")
	delete(h, "Content-Length")
	if h.Get("Etag") != "" {
		delete(h, "Last-Modified")
	}
	w.WriteHeader(StatusNotModified)
}

// checkPreconditions evaluates request preconditions and reports whether a precondition
// resulted in sending StatusNotModified or StatusPreconditionFailed.
// [Min] 检查Preconditions
func checkPreconditions(w ResponseWriter, r *Request, modtime time.Time) (done bool, rangeHeader string) {
	// This function carefully follows RFC 7232 section 6.
	// [Min] 检查request If-Match
	ch := checkIfMatch(w, r)
	// [Min] 如果没有 If-Match，检查If-Unmodified-Since
	if ch == condNone {
		ch = checkIfUnmodifiedSince(r, modtime)
	}
	if ch == condFalse {
		w.WriteHeader(StatusPreconditionFailed) //412
		return true, ""
	}
	switch checkIfNoneMatch(w, r) {
	// [Min] 如果 If-None-Match 返回假，则说明 etag 匹配上了，
	// [Min] 对于 GET,HEAD，写入 NotModified 304
	// [Min] 对于其他 Method，写入412
	case condFalse:
		if r.Method == "GET" || r.Method == "HEAD" {
			writeNotModified(w)
			return true, ""
		} else {
			w.WriteHeader(StatusPreconditionFailed)
			return true, ""
		}
	// [Min] 如果 If-None-Match 返回none，说明没有If-None-Match，继续检查 If-Modified-Since
	// [Min] 如果checkIfModifiedSince返回假，说明文件没有变动，写入 NotModified 304
	case condNone:
		if checkIfModifiedSince(r, modtime) == condFalse {
			writeNotModified(w)
			return true, ""
		}
	}

	rangeHeader = r.Header.get("Range")
	// [Min] 获得 Range ，如果不为空，则检查If-Range，如果返回假则置 Range 条件为空
	if rangeHeader != "" && checkIfRange(w, r, modtime) == condFalse {
		rangeHeader = ""
	}
	// [Min] 最后返回 done 为 false，和经过 If-Range 检查后修改过的 rangeHeader
	return false, rangeHeader
}

// name is '/'-separated, not filepath.Separator.
// [Min] 此处 name 为路径名
func serveFile(w ResponseWriter, r *Request, fs FileSystem, name string, redirect bool) {
	const indexPage = "/index.html"

	// redirect .../index.html to .../
	// can't use Redirect() because that would make the path absolute,
	// which would be a problem running under StripPrefix
	// [Min] 如果 request 中 path 以/index.html结尾，则去掉index.html，转到./
	if strings.HasSuffix(r.URL.Path, indexPage) {
		localRedirect(w, r, "./")
		return
	}

	// [Min] 获取目录对应的 File
	f, err := fs.Open(name)
	if err != nil {
		msg, code := toHTTPError(err)
		Error(w, msg, code)
		return
	}
	defer f.Close()

	// [Min] 获取 f 的 FileInfo
	d, err := f.Stat()
	if err != nil {
		msg, code := toHTTPError(err)
		Error(w, msg, code)
		return
	}

	if redirect {
		// redirect to canonical path: / at end of directory url
		// r.URL.Path always begins with /
		url := r.URL.Path
		// [Min] 如果 d 是目录，但 url path 不以/结尾，则取最后一部分+/ 作为重定向的路径
		if d.IsDir() {
			if url[len(url)-1] != '/' {
				localRedirect(w, r, path.Base(url)+"/")
				return
			}
		} else {
			// [Min] 如果 d 不是目录，但 url path 以/结尾，则取../ + 最后一部分作为重定向路径
			if url[len(url)-1] == '/' {
				localRedirect(w, r, "../"+path.Base(url))
				return
			}
		}
	}

	// redirect if the directory name doesn't end in a slash
	// [Min] 如果 d 是目录，但 url path 不以/结尾，则取最后一部分+/ 作为重定向的路径
	if d.IsDir() {
		url := r.URL.Path
		if url[len(url)-1] != '/' {
			localRedirect(w, r, path.Base(url)+"/")
			return
		}
	}

	// use contents of index.html for directory, if present
	// [Min] 如果 d 为目录，且 d 下有 index.html 则将此 index.html作为内容返回
	if d.IsDir() {
		index := strings.TrimSuffix(name, "/") + indexPage
		ff, err := fs.Open(index)
		if err == nil {
			defer ff.Close()
			dd, err := ff.Stat()
			if err == nil {
				name = index
				d = dd
				f = ff
			}
		}
	}

	// Still a directory? (we didn't find an index.html file)
	// [Min] 如果 d 是目录，且 d 下面没有 index.html，
	// [Min] 则检查 request 中的If-Modified-Since 时间，看该目录是否在该时间后修改过
	// [Min] 没有改过，则直接返回NotModified，否则列出该目录下的所有文件、目录列表
	if d.IsDir() {
		if checkIfModifiedSince(r, d.ModTime()) == condFalse {
			writeNotModified(w)
			return
		}
		w.Header().Set("Last-Modified", d.ModTime().UTC().Format(TimeFormat))
		dirList(w, r, f)
		return
	}

	// serveContent will check modification time
	sizeFunc := func() (int64, error) { return d.Size(), nil }
	serveContent(w, r, d.Name(), d.ModTime(), sizeFunc, f)
}

// toHTTPError returns a non-specific HTTP error message and status code
// for a given non-nil error value. It's important that toHTTPError does not
// actually return err.Error(), since msg and httpStatus are returned to users,
// and historically Go's ServeContent always returned just "404 Not Found" for
// all errors. We don't want to start leaking information in error messages.
// [Min] 转为 http error
func toHTTPError(err error) (msg string, httpStatus int) {
	if os.IsNotExist(err) {
		return "404 page not found", StatusNotFound
	}
	if os.IsPermission(err) {
		return "403 Forbidden", StatusForbidden
	}
	// Default:
	return "500 Internal Server Error", StatusInternalServerError
}

// localRedirect gives a Moved Permanently response.
// It does not convert relative paths to absolute paths like Redirect does.
func localRedirect(w ResponseWriter, r *Request, newPath string) {
	if q := r.URL.RawQuery; q != "" {
		newPath += "?" + q
	}
	w.Header().Set("Location", newPath)
	w.WriteHeader(StatusMovedPermanently)
}

// ServeFile replies to the request with the contents of the named
// file or directory.
//
// If the provided file or directory name is a relative path, it is
// interpreted relative to the current directory and may ascend to parent
// directories. If the provided name is constructed from user input, it
// should be sanitized before calling ServeFile. As a precaution, ServeFile
// will reject requests where r.URL.Path contains a ".." path element.
//
// As a special case, ServeFile redirects any request where r.URL.Path
// ends in "/index.html" to the same path, without the final
// "index.html". To avoid such redirects either modify the path or
// use ServeContent.
func ServeFile(w ResponseWriter, r *Request, name string) {
	// [Min] 不能包含/../
	if containsDotDot(r.URL.Path) {
		// Too many programs use r.URL.Path to construct the argument to
		// serveFile. Reject the request under the assumption that happened
		// here and ".." may not be wanted.
		// Note that name might not contain "..", for example if code (still
		// incorrectly) used filepath.Join(myDir, r.URL.Path).
		Error(w, "invalid URL path", StatusBadRequest)
		return
	}
	dir, file := filepath.Split(name)
	serveFile(w, r, Dir(dir), file, false)
}

// [Min] 是否包含 .. 且恰好被SlashRune夹在中间
func containsDotDot(v string) bool {
	if !strings.Contains(v, "..") {
		return false
	}
	for _, ent := range strings.FieldsFunc(v, isSlashRune) {
		if ent == ".." {
			return true
		}
	}
	return false
}

func isSlashRune(r rune) bool { return r == '/' || r == '\\' }

type fileHandler struct {
	root FileSystem
}

// FileServer returns a handler that serves HTTP requests
// with the contents of the file system rooted at root.
//
// To use the operating system's file system implementation,
// use http.Dir:
//
//     http.Handle("/", http.FileServer(http.Dir("/tmp")))
//
// As a special case, the returned file server redirects any request
// ending in "/index.html" to the same path, without the final
// "index.html".
// [Min] 在以 root 为"根"目录下的文件服务器，Dir 实现了FileSystem，所以一般都是这样构造 FileServer
// [Min] http.FileServer(http.Dir("/tmp")
func FileServer(root FileSystem) Handler {
	return &fileHandler{root}
}

func (f *fileHandler) ServeHTTP(w ResponseWriter, r *Request) {
	upath := r.URL.Path
	// [Min] 确保 url path 以/开头
	if !strings.HasPrefix(upath, "/") {
		upath = "/" + upath
		r.URL.Path = upath
	}
	// [Min] 注意这里对 upath 进行了标准化，如果以/结尾会被清除，除非 upath 就是/
	// [Min] redirect 为真
	serveFile(w, r, f.root, path.Clean(upath), true)
}

// httpRange specifies the byte range to be sent to the client.
type httpRange struct {
	start, length int64
}

// [Min] 拼装 Content-Range 的内容
func (r httpRange) contentRange(size int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.start, r.start+r.length-1, size)
}

// [Min] 该 range 段的 MIMEHeader
func (r httpRange) mimeHeader(contentType string, size int64) textproto.MIMEHeader {
	return textproto.MIMEHeader{
		"Content-Range": {r.contentRange(size)},
		"Content-Type":  {contentType},
	}
}

// parseRange parses a Range header string as per RFC 2616.
// errNoOverlap is returned if none of the ranges overlap.
// [Min] 解析 Range header
func parseRange(s string, size int64) ([]httpRange, error) {
	// [Min] 如果为空，返回 nil
	if s == "" {
		return nil, nil // header not present
	}
	const b = "bytes="
	// [Min] Range 的值必须以"bytes="开头，如 Range: bytes=200-1000, 2000-6576, 19000-
	if !strings.HasPrefix(s, b) {
		return nil, errors.New("invalid range")
	}
	var ranges []httpRange
	noOverlap := false
	// [Min] 处理 bytes= 后面由 ，分隔的每一段字符串
	for _, ra := range strings.Split(s[len(b):], ",") {
		// [Min] 去掉前后空格
		ra = strings.TrimSpace(ra)
		if ra == "" {
			continue
		}
		// [Min] 必须有"-"，用来分隔起始和末尾位置
		i := strings.Index(ra, "-")
		if i < 0 {
			return nil, errors.New("invalid range")
		}
		// [Min] 获得该段 range 的起始，末尾位置
		start, end := strings.TrimSpace(ra[:i]), strings.TrimSpace(ra[i+1:])
		var r httpRange
		// [Min] 如果start为空，则 end 的值表示该段 range 的起始相对于整个文件末尾的位置
		if start == "" {
			// If no start is specified, end specifies the
			// range start relative to the end of the file.
			i, err := strconv.ParseInt(end, 10, 64)
			if err != nil {
				return nil, errors.New("invalid range")
			}
			// [Min] end不能超过 size 的大小
			if i > size {
				i = size
			}
			r.start = size - i
			r.length = size - r.start
		} else {
			// [Min] start 不为空，不能小于0
			i, err := strconv.ParseInt(start, 10, 64)
			if err != nil || i < 0 {
				return nil, errors.New("invalid range")
			}
			// [Min] 如果 start 大于等于文件长度，则忽略该段 range，并标记noOverlap 为 true
			if i >= size {
				// If the range begins after the size of the content,
				// then it does not overlap.
				noOverlap = true
				continue
			}
			r.start = i
			// [Min] 如果 end 为空，则表示该段 range 到文件末尾
			if end == "" {
				// If no end is specified, range extends to end of the file.
				r.length = size - r.start
			} else {
				// [Min] end 不为空，但不能小于 start，且 end 最大为 size - 1
				i, err := strconv.ParseInt(end, 10, 64)
				if err != nil || r.start > i {
					return nil, errors.New("invalid range")
				}
				if i >= size {
					i = size - 1
				}
				r.length = i - r.start + 1
			}
		}
		ranges = append(ranges, r)
	}
	// [Min] 如果所有的 range 段都与文件长度范围不重叠，则报错，
	// [Min] 若只是有个别与文件长度范围不重叠，则返回正常的 range 段
	if noOverlap && len(ranges) == 0 {
		// The specified ranges did not overlap with the content.
		return nil, errNoOverlap
	}
	return ranges, nil
}

// countingWriter counts how many bytes have been written to it.
// [Min] countingWriter 是一个只会记录调用其 Write 方法写入的字节总数的 writer，没有实际写操作
type countingWriter int64

func (w *countingWriter) Write(p []byte) (n int, err error) {
	*w += countingWriter(len(p))
	return len(p), nil
}

// rangesMIMESize returns the number of bytes it takes to encode the
// provided ranges as a multipart response.
// [Min] 返回整个 multipart 实体的长度
func rangesMIMESize(ranges []httpRange, contentType string, contentSize int64) (encSize int64) {
	var w countingWriter
	// [Min] 返回一个随机边界分隔符号的多段 writer，因为 w 仅仅是计数 writer，
	// [Min] 所以 CreatePart 后，w 中记录的是所有 part 的总长
	mw := multipart.NewWriter(&w)
	for _, ra := range ranges {
		// [Min] CreatePart 会调用 io.Copy(w.w, &b)，即会把每一段中除了实际内容的其他部分（header + 边界 + 实际内容前的空行 \r\n）的长度累加起来，存在 w 中
		mw.CreatePart(ra.mimeHeader(contentType, contentSize))
		encSize += ra.length
	}
	mw.Close()
	// [Min] 整个 multipart 实体的长度
	encSize += int64(w)
	return
}

// [Min] 返回所有 range 段的长度和
func sumRangesSize(ranges []httpRange) (size int64) {
	for _, ra := range ranges {
		size += ra.length
	}
	return
}
