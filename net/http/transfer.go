// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http/internal"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang_org/x/net/lex/httplex"
)

// ErrLineTooLong is returned when reading request or response bodies
// with malformed chunked encoding.
var ErrLineTooLong = internal.ErrLineTooLong

type errorReader struct {
	err error
}

func (r errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

// [Min] 单字节 reader
type byteReader struct {
	b    byte
	done bool
}

func (br *byteReader) Read(p []byte) (n int, err error) {
	if br.done {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	br.done = true
	p[0] = br.b
	return 1, io.EOF
}

// transferBodyReader is an io.Reader that reads from tw.Body
// and records any non-EOF error in tw.bodyReadError.
// It is exactly 1 pointer wide to avoid allocations into interfaces.
// [Min] transferWriter 的指针结构体，从 transferWriter 的 Body 中读取数据
type transferBodyReader struct{ tw *transferWriter }

func (br transferBodyReader) Read(p []byte) (n int, err error) {
	n, err = br.tw.Body.Read(p)
	if err != nil && err != io.EOF {
		br.tw.bodyReadError = err
	}
	return
}

// transferWriter inspects the fields of a user-supplied Request or Response,
// sanitizes them without changing the user object and provides methods for
// writing the respective header, body and trailer in wire format.
// [Min] 既可对应 request 又可对应 response
type transferWriter struct {
	Method           string
	Body             io.Reader
	BodyCloser       io.Closer
	ResponseToHEAD   bool
	ContentLength    int64 // -1 means unknown, 0 means exactly none
	Close            bool
	TransferEncoding []string
	Header           Header
	Trailer          Header
	IsResponse       bool
	bodyReadError    error // any non-EOF error from reading Body

	FlushHeaders bool            // flush headers to network before body
	ByteReadCh   chan readResult // non-nil if probeRequestBody called
}

// [Min] 将 request 或 response 映射到 transferWriter
func newTransferWriter(r interface{}) (t *transferWriter, err error) {
	t = &transferWriter{}

	// Extract relevant fields
	atLeastHTTP11 := false
	switch rr := r.(type) {
	// [Min] Request 的处理
	case *Request:
		// [Min] contentlength 不为0，但 body 为 nil，报错
		if rr.ContentLength != 0 && rr.Body == nil {
			return nil, fmt.Errorf("http: Request.ContentLength=%d with nil Body", rr.ContentLength)
		}
		t.Method = valueOrDefault(rr.Method, "GET")
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Header = rr.Header
		t.Trailer = rr.Trailer
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = rr.outgoingLength()
		if t.ContentLength < 0 && len(t.TransferEncoding) == 0 && t.shouldSendChunkedRequestBody() {
			t.TransferEncoding = []string{"chunked"}
		}
		atLeastHTTP11 = true // Transport requests are always 1.1 or 2.0
	// [Min] Response 的处理
	case *Response:
		t.IsResponse = true
		if rr.Request != nil {
			t.Method = rr.Request.Method
		}
		t.Body = rr.Body
		t.BodyCloser = rr.Body
		t.ContentLength = rr.ContentLength
		t.Close = rr.Close
		t.TransferEncoding = rr.TransferEncoding
		t.Header = rr.Header
		t.Trailer = rr.Trailer
		atLeastHTTP11 = rr.ProtoAtLeast(1, 1)
		t.ResponseToHEAD = noResponseBodyExpected(t.Method)
	}

	// Sanitize Body,ContentLength,TransferEncoding
	if t.ResponseToHEAD {
		// [Min] 如果 method 为 HEAD，body 为 nil
		t.Body = nil
		// [Min] 如果 TransferEncoding 为 chunked，则 contentlength 为-1
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		}
	} else {
		if !atLeastHTTP11 || t.Body == nil {
			t.TransferEncoding = nil
		}
		if chunked(t.TransferEncoding) {
			t.ContentLength = -1
		} else if t.Body == nil { // no chunking, no body
			t.ContentLength = 0
		}
	}

	// Sanitize Trailer
	if !chunked(t.TransferEncoding) {
		t.Trailer = nil
	}

	return t, nil
}

// shouldSendChunkedRequestBody reports whether we should try to send a
// chunked request body to the server. In particular, the case we really
// want to prevent is sending a GET or other typically-bodyless request to a
// server with a chunked body when the body has zero bytes, since GETs with
// bodies (while acceptable according to specs), even zero-byte chunked
// bodies, are approximately never seen in the wild and confuse most
// servers. See Issue 18257, as one example.
//
// The only reason we'd send such a request is if the user set the Body to a
// non-nil value (say, ioutil.NopCloser(bytes.NewReader(nil))) and didn't
// set ContentLength, or NewRequest set it to -1 (unknown), so then we assume
// there's bytes to send.
//
// This code tries to read a byte from the Request.Body in such cases to see
// whether the body actually has content (super rare) or is actually just
// a non-nil content-less ReadCloser (the more common case). In that more
// common case, we act as if their Body were nil instead, and don't send
// a body.
// [Min] 判断 request body 是否为 chunked
// [Min] 一篇关于TransferEncoding的文章，清楚地解释了 chunked 的用法：
// [Min] https://imququ.com/post/transfer-encoding-header-in-http.html
func (t *transferWriter) shouldSendChunkedRequestBody() bool {
	// Note that t.ContentLength is the corrected content length
	// from rr.outgoingLength, so 0 actually means zero, not unknown.
	if t.ContentLength >= 0 || t.Body == nil { // redundant checks; caller did them
		return false
	}
	if requestMethodUsuallyLacksBody(t.Method) {
		// Only probe the Request.Body for GET/HEAD/DELETE/etc
		// requests, because it's only those types of requests
		// that confuse servers.
		// [Min] 修正t.Body, t.ContentLength
		t.probeRequestBody() // adjusts t.Body, t.ContentLength
		return t.Body != nil
	}
	// For all other request types (PUT, POST, PATCH, or anything
	// made-up we've never heard of), assume it's normal and the server
	// can deal with a chunked request body. Maybe we'll adjust this
	// later.
	return true
}

// probeRequestBody reads a byte from t.Body to see whether it's empty
// (returns io.EOF right away).
//
// But because we've had problems with this blocking users in the past
// (issue 17480) when the body is a pipe (perhaps waiting on the response
// headers before the pipe is fed data), we need to be careful and bound how
// long we wait for it. This delay will only affect users if all the following
// are true:
//   * the request body blocks
//   * the content length is not set (or set to -1)
//   * the method doesn't usually have a body (GET, HEAD, DELETE, ...)
//   * there is no transfer-encoding=chunked already set.
// In other words, this delay will not normally affect anybody, and there
// are workarounds if it does.
// [Min] 通过 goroutine 从 transferWriter 中读取一个字节来判断 body 是否为空，从而更新 t.Body,t.ContentLength等
// [Min] 如果超过了200 ms还没完成 goroutine 的读取，则默认为 chunked
func (t *transferWriter) probeRequestBody() {
	t.ByteReadCh = make(chan readResult, 1)
	go func(body io.Reader) {
		var buf [1]byte
		var rres readResult
		rres.n, rres.err = body.Read(buf[:])
		if rres.n == 1 {
			rres.b = buf[0]
		}
		t.ByteReadCh <- rres
	}(t.Body)
	timer := time.NewTimer(200 * time.Millisecond)
	select {
	case rres := <-t.ByteReadCh:
		timer.Stop()
		if rres.n == 0 && rres.err == io.EOF {
			// It was empty.
			// [Min] 空的话设置 body 为 nil，后续会根据 body 为 nil 来判断为 chunked
			t.Body = nil
			t.ContentLength = 0
		} else if rres.n == 1 {
			if rres.err != nil {
				t.Body = io.MultiReader(&byteReader{b: rres.b}, errorReader{rres.err})
			} else {
				t.Body = io.MultiReader(&byteReader{b: rres.b}, t.Body)
			}
		} else if rres.err != nil {
			t.Body = errorReader{rres.err}
		}
	case <-timer.C:
		// Too slow. Don't wait. Read it later, and keep
		// assuming that this is ContentLength == -1
		// (unknown), which means we'll send a
		// "Transfer-Encoding: chunked" header.
		t.Body = io.MultiReader(finishAsyncByteRead{t}, t.Body)
		// Request that Request.Write flush the headers to the
		// network before writing the body, since our body may not
		// become readable until it's seen the response headers.
		t.FlushHeaders = true
	}
}

// [Min]  是否不应该有 ResponseBody
func noResponseBodyExpected(requestMethod string) bool {
	return requestMethod == "HEAD"
}

// [Min] 是否应该发送ContentLength
// [Min] 首先根据TransferEncoding是否为 chunked来判断
// [Min] 如果 ContentLength大于0,返回 true，小于0，返回 false
// [Min] 对 POST 和 PUT 返回 true
// [Min] 如果等于0，
func (t *transferWriter) shouldSendContentLength() bool {
	if chunked(t.TransferEncoding) {
		return false
	}
	if t.ContentLength > 0 {
		return true
	}
	if t.ContentLength < 0 {
		return false
	}
	// Many servers expect a Content-Length for these methods
	if t.Method == "POST" || t.Method == "PUT" {
		return true
	}
	if t.ContentLength == 0 && isIdentity(t.TransferEncoding) {
		if t.Method == "GET" || t.Method == "HEAD" {
			return false
		}
		return true
	}

	return false
}

func (t *transferWriter) WriteHeader(w io.Writer) error {
	// [Min] 写入Connection: close
	if t.Close && !hasToken(t.Header.get("Connection"), "close") {
		if _, err := io.WriteString(w, "Connection: close\r\n"); err != nil {
			return err
		}
	}

	// Write Content-Length and/or Transfer-Encoding whose values are a
	// function of the sanitized field triple (Body, ContentLength,
	// TransferEncoding)
	// [Min] 根据实际情况写入Transfer-Encoding和Content-Length
	if t.shouldSendContentLength() {
		if _, err := io.WriteString(w, "Content-Length: "); err != nil {
			return err
		}
		if _, err := io.WriteString(w, strconv.FormatInt(t.ContentLength, 10)+"\r\n"); err != nil {
			return err
		}
	} else if chunked(t.TransferEncoding) {
		if _, err := io.WriteString(w, "Transfer-Encoding: chunked\r\n"); err != nil {
			return err
		}
	}

	// Write Trailer header
	// [Min] 写入 Trailer
	if t.Trailer != nil {
		keys := make([]string, 0, len(t.Trailer))
		for k := range t.Trailer {
			k = CanonicalHeaderKey(k)
			switch k {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				return &badStringError{"invalid Trailer key", k}
			}
			keys = append(keys, k)
		}
		if len(keys) > 0 {
			sort.Strings(keys)
			// TODO: could do better allocation-wise here, but trailers are rare,
			// so being lazy for now.
			if _, err := io.WriteString(w, "Trailer: "+strings.Join(keys, ",")+"\r\n"); err != nil {
				return err
			}
		}
	}

	return nil
}

// [Min] 将t 中的body写入 w
func (t *transferWriter) WriteBody(w io.Writer) error {
	var err error
	var ncopy int64

	// Write body
	if t.Body != nil {
		var body = transferBodyReader{t}
		if chunked(t.TransferEncoding) {
			if bw, ok := w.(*bufio.Writer); ok && !t.IsResponse {
				// [Min] FlushAfterChunkWriter在每次 Write 最后都会 Flush
				w = &internal.FlushAfterChunkWriter{Writer: bw}
			}
			cw := internal.NewChunkedWriter(w)
			_, err = io.Copy(cw, body)
			if err == nil {
				err = cw.Close() // [Min] 最后写入表示结束的0\r\n
			}
		} else if t.ContentLength == -1 {
			ncopy, err = io.Copy(w, body)
		} else {
			// [Min] 根据实际长度写入 w，多余的部分忽略
			ncopy, err = io.Copy(w, io.LimitReader(body, t.ContentLength))
			if err != nil {
				return err
			}
			var nextra int64
			nextra, err = io.Copy(ioutil.Discard, body)
			ncopy += nextra
		}
		if err != nil {
			return err
		}
	}
	if t.BodyCloser != nil {
		if err := t.BodyCloser.Close(); err != nil {
			return err
		}
	}

	if !t.ResponseToHEAD && t.ContentLength != -1 && t.ContentLength != ncopy {
		return fmt.Errorf("http: ContentLength=%d with Body length %d",
			t.ContentLength, ncopy)
	}

	if chunked(t.TransferEncoding) {
		// Write Trailer header
		if t.Trailer != nil {
			if err := t.Trailer.Write(w); err != nil {
				return err
			}
		}
		// Last chunk, empty trailer
		_, err = io.WriteString(w, "\r\n") // [Min] 写入 chunk 的 trailer \r\n
	}
	return err
}

type transferReader struct {
	// Input
	Header        Header
	StatusCode    int
	RequestMethod string
	ProtoMajor    int
	ProtoMinor    int
	// Output
	Body             io.ReadCloser
	ContentLength    int64
	TransferEncoding []string
	Close            bool
	Trailer          Header
}

// [Min] 检查最小版本
func (t *transferReader) protoAtLeast(m, n int) bool {
	return t.ProtoMajor > m || (t.ProtoMajor == m && t.ProtoMinor >= n)
}

// bodyAllowedForStatus reports whether a given response status code
// permits a body. See RFC 2616, section 4.4.
// [Min] 对于 status 是否允许 body 的存在
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199:
		return false
	case status == 204:
		return false
	case status == 304:
		return false
	}
	return true
}

var (
	suppressedHeaders304    = []string{"Content-Type", "Content-Length", "Transfer-Encoding"}
	suppressedHeadersNoBody = []string{"Content-Length", "Transfer-Encoding"}
)

// [Min] 对于 status 不允许存在的 header
func suppressedHeaders(status int) []string {
	switch {
	case status == 304:
		// RFC 2616 section 10.3.5: "the response MUST NOT include other entity-headers"
		return suppressedHeaders304
	case !bodyAllowedForStatus(status):
		return suppressedHeadersNoBody
	}
	return nil
}

// msg is *Request or *Response.
// [Min] 将 msg 中的数据（不含 Body）先存入transferReader，
// [Min] 再对 t.ContentLength,t.TransferEncoding,t.Close,t.Trailer 进行修正
// [Min] 再以 r 中的数据通过 body 填入 t.Body
// [Min] 最后将 t 中数据全部返还给 msg
func readTransfer(msg interface{}, r *bufio.Reader) (err error) {
	t := &transferReader{RequestMethod: "GET"}

	// Unify input
	isResponse := false
	switch rr := msg.(type) {
	case *Response:
		t.Header = rr.Header
		t.StatusCode = rr.StatusCode
		t.ProtoMajor = rr.ProtoMajor
		t.ProtoMinor = rr.ProtoMinor
		t.Close = shouldClose(t.ProtoMajor, t.ProtoMinor, t.Header, true)
		isResponse = true
		if rr.Request != nil {
			t.RequestMethod = rr.Request.Method
		}
	case *Request:
		t.Header = rr.Header
		t.RequestMethod = rr.Method
		t.ProtoMajor = rr.ProtoMajor
		t.ProtoMinor = rr.ProtoMinor
		// Transfer semantics for Requests are exactly like those for
		// Responses with status code 200, responding to a GET method
		t.StatusCode = 200
		t.Close = rr.Close
	default:
		panic("unexpected type")
	}

	// Default to HTTP/1.1
	if t.ProtoMajor == 0 && t.ProtoMinor == 0 {
		t.ProtoMajor, t.ProtoMinor = 1, 1
	}

	// Transfer encoding, content length
	// [Min] 处理TransferEncoding
	err = t.fixTransferEncoding()
	if err != nil {
		return err
	}

	// [Min] 处理Content-Length
	realLength, err := fixLength(isResponse, t.StatusCode, t.RequestMethod, t.Header, t.TransferEncoding)
	if err != nil {
		return err
	}
	if isResponse && t.RequestMethod == "HEAD" {
		if n, err := parseContentLength(t.Header.get("Content-Length")); err != nil {
			return err
		} else {
			t.ContentLength = n
		}
	} else {
		t.ContentLength = realLength
	}

	// Trailer
	// [Min] 处理 Trailer
	t.Trailer, err = fixTrailer(t.Header, t.TransferEncoding)
	if err != nil {
		return err
	}

	// If there is no Content-Length or chunked Transfer-Encoding on a *Response
	// and the status is not 1xx, 204 or 304, then the body is unbounded.
	// See RFC 2616, section 4.4.
	switch msg.(type) {
	case *Response:
		if realLength == -1 &&
			!chunked(t.TransferEncoding) &&
			bodyAllowedForStatus(t.StatusCode) {
			// Unbounded body.
			t.Close = true
		}
	}

	// Prepare body reader. ContentLength < 0 means chunked encoding
	// or close connection when finished, since multipart is not supported yet
	// [Min] 将 r 中数据通过 body 来构造 t.Body
	switch {
	case chunked(t.TransferEncoding):
		if noResponseBodyExpected(t.RequestMethod) || !bodyAllowedForStatus(t.StatusCode) {
			t.Body = NoBody
		} else {
			t.Body = &body{src: internal.NewChunkedReader(r), hdr: msg, r: r, closing: t.Close}
		}
	case realLength == 0:
		t.Body = NoBody
	case realLength > 0:
		t.Body = &body{src: io.LimitReader(r, realLength), closing: t.Close}
	default:
		// realLength < 0, i.e. "Content-Length" not mentioned in header
		if t.Close {
			// Close semantics (i.e. HTTP/1.0)
			t.Body = &body{src: r, closing: t.Close}
		} else {
			// Persistent connection (i.e. HTTP/1.1)
			t.Body = NoBody
		}
	}

	// Unify output
	switch rr := msg.(type) {
	case *Request:
		rr.Body = t.Body
		rr.ContentLength = t.ContentLength
		rr.TransferEncoding = t.TransferEncoding
		rr.Close = t.Close
		rr.Trailer = t.Trailer
	case *Response:
		rr.Body = t.Body
		rr.ContentLength = t.ContentLength
		rr.TransferEncoding = t.TransferEncoding
		rr.Close = t.Close
		rr.Trailer = t.Trailer
	}

	return nil
}

// Checks whether chunked is part of the encodings stack
// [Min] 判断TransferEncoding是否为chunked
func chunked(te []string) bool { return len(te) > 0 && te[0] == "chunked" }

// Checks whether the encoding is explicitly "identity".
// [Min] 判断TransferEncoding是否为identity
func isIdentity(te []string) bool { return len(te) == 1 && te[0] == "identity" }

// fixTransferEncoding sanitizes t.TransferEncoding, if needed.
// [Min] 处理TransferEncoding
func (t *transferReader) fixTransferEncoding() error {
	raw, present := t.Header["Transfer-Encoding"]
	if !present {
		return nil
	}
	delete(t.Header, "Transfer-Encoding")

	// Issue 12785; ignore Transfer-Encoding on HTTP/1.0 requests.
	if !t.protoAtLeast(1, 1) {
		return nil
	}

	encodings := strings.Split(raw[0], ",")
	te := make([]string, 0, len(encodings))
	// TODO: Even though we only support "identity" and "chunked"
	// encodings, the loop below is designed with foresight. One
	// invariant that must be maintained is that, if present,
	// chunked encoding must always come first.
	for _, encoding := range encodings {
		encoding = strings.ToLower(strings.TrimSpace(encoding))
		// "identity" encoding is not recorded
		if encoding == "identity" {
			break
		}
		if encoding != "chunked" {
			return &badStringError{"unsupported transfer encoding", encoding}
		}
		te = te[0 : len(te)+1]
		te[len(te)-1] = encoding
	}
	if len(te) > 1 {
		return &badStringError{"too many transfer encodings", strings.Join(te, ",")}
	}
	if len(te) > 0 {
		// RFC 7230 3.3.2 says "A sender MUST NOT send a
		// Content-Length header field in any message that
		// contains a Transfer-Encoding header field."
		//
		// but also:
		// "If a message is received with both a
		// Transfer-Encoding and a Content-Length header
		// field, the Transfer-Encoding overrides the
		// Content-Length. Such a message might indicate an
		// attempt to perform request smuggling (Section 9.5)
		// or response splitting (Section 9.4) and ought to be
		// handled as an error. A sender MUST remove the
		// received Content-Length field prior to forwarding
		// such a message downstream."
		//
		// Reportedly, these appear in the wild.
		delete(t.Header, "Content-Length")
		t.TransferEncoding = te
		return nil
	}

	return nil
}

// Determine the expected body length, using RFC 2616 Section 4.4. This
// function is not a method, because ultimately it should be shared by
// ReadResponse and ReadRequest.
// [Min] 处理Content-Length
func fixLength(isResponse bool, status int, requestMethod string, header Header, te []string) (int64, error) {
	isRequest := !isResponse
	contentLens := header["Content-Length"]

	// Hardening against HTTP request smuggling
	if len(contentLens) > 1 {
		// Per RFC 7230 Section 3.3.2, prevent multiple
		// Content-Length headers if they differ in value.
		// If there are dups of the value, remove the dups.
		// See Issue 16490.
		first := strings.TrimSpace(contentLens[0])
		for _, ct := range contentLens[1:] {
			if first != strings.TrimSpace(ct) {
				return 0, fmt.Errorf("http: message cannot contain multiple Content-Length headers; got %q", contentLens)
			}
		}

		// deduplicate Content-Length
		header.Del("Content-Length")
		header.Add("Content-Length", first)

		contentLens = header["Content-Length"]
	}

	// Logic based on response type or status
	if noResponseBodyExpected(requestMethod) {
		// For HTTP requests, as part of hardening against request
		// smuggling (RFC 7230), don't allow a Content-Length header for
		// methods which don't permit bodies. As an exception, allow
		// exactly one Content-Length header if its value is "0".
		if isRequest && len(contentLens) > 0 && !(len(contentLens) == 1 && contentLens[0] == "0") {
			return 0, fmt.Errorf("http: method cannot contain a Content-Length; got %q", contentLens)
		}
		return 0, nil
	}
	if status/100 == 1 {
		return 0, nil
	}
	switch status {
	case 204, 304:
		return 0, nil
	}

	// Logic based on Transfer-Encoding
	if chunked(te) {
		return -1, nil
	}

	// Logic based on Content-Length
	var cl string
	if len(contentLens) == 1 {
		cl = strings.TrimSpace(contentLens[0])
	}
	if cl != "" {
		n, err := parseContentLength(cl)
		if err != nil {
			return -1, err
		}
		return n, nil
	}
	header.Del("Content-Length")

	if isRequest {
		// RFC 2616 neither explicitly permits nor forbids an
		// entity-body on a GET request so we permit one if
		// declared, but we default to 0 here (not -1 below)
		// if there's no mention of a body.
		// Likewise, all other request methods are assumed to have
		// no body if neither Transfer-Encoding chunked nor a
		// Content-Length are set.
		return 0, nil
	}

	// Body-EOF logic based on other methods (like closing, or chunked coding)
	return -1, nil
}

// Determine whether to hang up after sending a request and body, or
// receiving a response and body
// 'header' is the request headers
// [Min] 是否应该标记为 close
func shouldClose(major, minor int, header Header, removeCloseHeader bool) bool {
	// [Min] 小于1.0的版本，都要 close
	if major < 1 {
		return true
	}

	conv := header["Connection"]
	hasClose := httplex.HeaderValuesContainsToken(conv, "close")
	// [Min] 如果版本为1.0，则判断 header 中的 connection是否有close，有则返回 true，
	// [Min] 如果没有，再判断是否没有 keep-alive
	if major == 1 && minor == 0 {
		return hasClose || !httplex.HeaderValuesContainsToken(conv, "keep-alive")
	}

	// [Min] 根据标记，是否删除 header 中的 Connection: close
	if hasClose && removeCloseHeader {
		header.Del("Connection")
	}

	// [Min] 其他版本直接返回是否有 close
	return hasClose
}

// Parse the trailer header
// [Min] 从原 Header 中删除 Trailer，并逐个检查原 header 中的 key 是否有效，
// [Min] 有效则保留此 key 并置为 nil，添加到新的 trailer 中
// [Min] 无效则返回空的 header 并报错
// [Min] 如果上述新的 trailer 为空，则返回 nil，nil
// [Min] 如果不为空，且不是 chunked，则报错，否则返回该新的 trailer
func fixTrailer(header Header, te []string) (Header, error) {
	vv, ok := header["Trailer"]
	if !ok {
		return nil, nil
	}
	header.Del("Trailer")

	trailer := make(Header)
	var err error
	for _, v := range vv {
		foreachHeaderElement(v, func(key string) {
			key = CanonicalHeaderKey(key)
			switch key {
			case "Transfer-Encoding", "Trailer", "Content-Length":
				if err == nil {
					err = &badStringError{"bad trailer key", key}
					return
				}
			}
			trailer[key] = nil
		})
	}
	if err != nil {
		return nil, err
	}
	if len(trailer) == 0 {
		return nil, nil
	}
	if !chunked(te) {
		// Trailer and no chunking
		return nil, ErrUnexpectedTrailer
	}
	return trailer, nil
}

// body turns a Reader into a ReadCloser.
// Close ensures that the body has been fully read
// and then reads the trailer if necessary.
// [Min] transferWrtier中 Body 的实体对象
type body struct {
	// [Min] src 实际上与 r 同根，要么就是 r，要么是以 r 为基础包裹的新的结构，
	// [Min] 只不过 src 对应于 body 的实体内容，而 r 对应于剩下的 trailer 部分
	src io.Reader
	// [Min] hdr 为  readtransfer 中的msg，即*Request/*Response
	hdr interface{} // non-nil (Response or Request) value means read trailer
	// [Min] r 与 src 实际上同根，当完成 src 的读取后，r 中的读取偏移量自然也就指向了剩下的部分
	r            *bufio.Reader // underlying wire-format reader for the trailer
	closing      bool          // is the connection to be closed after reading body?
	doEarlyClose bool          // whether Close should stop early

	mu         sync.Mutex // guards following, and calls to Read and Close
	sawEOF     bool
	closed     bool
	earlyClose bool   // Close called and we didn't read to the end of src
	onHitEOF   func() // if non-nil, func to call when EOF is Read
}

// ErrBodyReadAfterClose is returned when reading a Request or Response
// Body after the body has been closed. This typically happens when the body is
// read after an HTTP Handler calls WriteHeader or Write on its
// ResponseWriter.
var ErrBodyReadAfterClose = errors.New("http: invalid Read on closed Body")

// [Min] 从 body 中读取数据到 p，p 中数据即为Body实体内容，
// [Min] 但此方法不仅只是读取 Body，在读取 Body 完成后，也会读取 Trailer 并填入对应的*Request/*Response 字段中
func (b *body) Read(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return 0, ErrBodyReadAfterClose
	}
	return b.readLocked(p)
}

// Must hold b.mu.
func (b *body) readLocked(p []byte) (n int, err error) {
	// [Min] 如果之前就已经 EOF，则直接返回
	if b.sawEOF {
		return 0, io.EOF
	}
	n, err = b.src.Read(p)

	// [Min] 如果这次读取为 EOF，则设置 sawEOF 为 true
	// [Min] 如果 hdr 不为 nil，则从b.r 中读取为 trailer并写入 hdr 的 Trailer 字段中
	// [Min] 此处 hdr 为*Request/*Response
	if err == io.EOF {
		b.sawEOF = true
		// Chunked case. Read the trailer.
		if b.hdr != nil {
			if e := b.readTrailer(); e != nil {
				err = e
				// Something went wrong in the trailer, we must not allow any
				// further reads of any kind to succeed from body, nor any
				// subsequent requests on the server connection. See
				// golang.org/issue/12027
				b.sawEOF = false
				b.closed = true
			}
			// [Min] 修改完 hdr 指向的 Request/Response 后，将指针置为 nil
			b.hdr = nil
		} else {
			// If the server declared the Content-Length, our body is a LimitedReader
			// and we need to check whether this EOF arrived early.
			// [Min] 如果 src 为限制长度的 reader，且 src 并没有完全读取，则说明此时的 EOF有问题
			if lr, ok := b.src.(*io.LimitedReader); ok && lr.N > 0 {
				err = io.ErrUnexpectedEOF
			}
		}
	}

	// If we can return an EOF here along with the read data, do
	// so. This is optional per the io.Reader contract, but doing
	// so helps the HTTP transport code recycle its connection
	// earlier (since it will see this EOF itself), even if the
	// client doesn't do future reads or Close.
	// [Min] 如果读取顺利，且读取长度达到了限度，则标记sawEOF为 true
	if err == nil && n > 0 {
		if lr, ok := b.src.(*io.LimitedReader); ok && lr.N == 0 {
			err = io.EOF
			b.sawEOF = true
		}
	}

	// [Min] 调用预定义的 EOF 触发函数
	if b.sawEOF && b.onHitEOF != nil {
		b.onHitEOF()
	}

	return n, err
}

var (
	singleCRLF = []byte("\r\n")
	doubleCRLF = []byte("\r\n\r\n")
)

// [Min] r 中是否有两个连续的CRLF
func seeUpcomingDoubleCRLF(r *bufio.Reader) bool {
	for peekSize := 4; ; peekSize++ {
		// This loop stops when Peek returns an error,
		// which it does when r's buffer has been filled.
		buf, err := r.Peek(peekSize)
		if bytes.HasSuffix(buf, doubleCRLF) {
			return true
		}
		if err != nil {
			break
		}
	}
	return false
}

var errTrailerEOF = errors.New("http: unexpected EOF reading trailer")

// [Min]  从 r 中读取 Trailer 到 hdr 中
func (b *body) readTrailer() error {
	// The common case, since nobody uses trailers.
	// [Min]  r 中数据以\r\n 开头，跳过头两位
	buf, err := b.r.Peek(2)
	if bytes.Equal(buf, singleCRLF) {
		b.r.Discard(2)
		return nil
	}
	// [Min] 如果 r 中数据不满2个字节，报错
	if len(buf) < 2 {
		return errTrailerEOF
	}
	if err != nil {
		return err
	}

	// Make sure there's a header terminator coming up, to prevent
	// a DoS with an unbounded size Trailer. It's not easy to
	// slip in a LimitReader here, as textproto.NewReader requires
	// a concrete *bufio.Reader. Also, we can't get all the way
	// back up to our conn's LimitedReader that *might* be backing
	// this bufio.Reader. Instead, a hack: we iteratively Peek up
	// to the bufio.Reader's max size, looking for a double CRLF.
	// This limits the trailer to the underlying buffer size, typically 4kB.
	// [Min] 如果 r 中没有连续的两个CRLF，报错
	if !seeUpcomingDoubleCRLF(b.r) {
		return errors.New("http: suspiciously long trailer after chunked body")
	}

	// [Min] 尝试读取 trailer
	hdr, err := textproto.NewReader(b.r).ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			return errTrailerEOF
		}
		return err
	}
	// [Min] 将读取的 trailer 设置到 b.hdr(*Request/*Response) 对应的字段中
	switch rr := b.hdr.(type) {
	case *Request:
		mergeSetHeader(&rr.Trailer, Header(hdr))
	case *Response:
		mergeSetHeader(&rr.Trailer, Header(hdr))
	}
	return nil
}

// [Min] 如果 dst 的值为 nil，直接用 src覆盖，否则，根据 src 的 key 一一进行覆盖
func mergeSetHeader(dst *Header, src Header) {
	if *dst == nil {
		*dst = src
		return
	}
	for k, vv := range src {
		(*dst)[k] = vv
	}
}

// unreadDataSizeLocked returns the number of bytes of unread input.
// It returns -1 if unknown.
// b.mu must be held.
// [Min] body的 src 中还剩多少达到最大限制读取长度，前提是 b.src 为LimitedReader
func (b *body) unreadDataSizeLocked() int64 {
	if lr, ok := b.src.(*io.LimitedReader); ok {
		return lr.N
	}
	return -1
}

func (b *body) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	var err error
	switch {
	case b.sawEOF:
		// Already saw EOF, so no need going to look for it.
	case b.hdr == nil && b.closing:
		// no trailer and closing the connection next.
		// no point in reading to EOF.
	case b.doEarlyClose:
		// Read up to maxPostHandlerReadBytes bytes of the body, looking for
		// for EOF (and trailers), so we can re-use this connection.
		if lr, ok := b.src.(*io.LimitedReader); ok && lr.N > maxPostHandlerReadBytes {
			// There was a declared Content-Length, and we have more bytes remaining
			// than our maxPostHandlerReadBytes tolerance. So, give up.
			b.earlyClose = true
		} else {
			var n int64
			// Consume the body, or, which will also lead to us reading
			// the trailer headers after the body, if present.
			n, err = io.CopyN(ioutil.Discard, bodyLocked{b}, maxPostHandlerReadBytes)
			if err == io.EOF {
				err = nil
			}
			if n == maxPostHandlerReadBytes {
				b.earlyClose = true
			}
		}
	default:
		// Fully consume the body, which will also lead to us reading
		// the trailer headers after the body, if present.
		_, err = io.Copy(ioutil.Discard, bodyLocked{b})
	}
	b.closed = true
	return err
}

// [Min] 判断是否已经为earlyClose
func (b *body) didEarlyClose() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.earlyClose
}

// bodyRemains reports whether future Read calls might
// yield data.
// [Min] 判断 body 是否还没读完
func (b *body) bodyRemains() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.sawEOF
}

// [Min] 注册 EOF 触发函数
func (b *body) registerOnHitEOF(fn func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.onHitEOF = fn
}

// bodyLocked is a io.Reader reading from a *body when its mutex is
// already held.
type bodyLocked struct {
	b *body
}

func (bl bodyLocked) Read(p []byte) (n int, err error) {
	if bl.b.closed {
		return 0, ErrBodyReadAfterClose
	}
	return bl.b.readLocked(p)
}

// parseContentLength trims whitespace from s and returns -1 if no value
// is set, or the value if it's >= 0.
// [Min] 解析长度为十进制数值
func parseContentLength(cl string) (int64, error) {
	cl = strings.TrimSpace(cl)
	if cl == "" {
		return -1, nil
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 {
		return 0, &badStringError{"bad Content-Length", cl}
	}
	return n, nil

}

// finishAsyncByteRead finishes reading the 1-byte sniff
// from the ContentLength==0, Body!=nil case.
type finishAsyncByteRead struct {
	tw *transferWriter
}

func (fr finishAsyncByteRead) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	rres := <-fr.tw.ByteReadCh
	n, err = rres.n, rres.err
	if n == 1 {
		p[0] = rres.b
	}
	return
}
