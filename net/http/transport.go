// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// HTTP client implementation. See RFC 2616.
//
// This is the low-level Transport implementation of RoundTripper.
// The high-level interface is in client.go.

package http

import (
	"bufio"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/httptrace"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang_org/x/net/lex/httplex"
	"golang_org/x/net/proxy"
)

// DefaultTransport is the default implementation of Transport and is
// used by DefaultClient. It establishes network connections as needed
// and caches them for reuse by subsequent calls. It uses HTTP proxies
// as directed by the $HTTP_PROXY and $NO_PROXY (or $http_proxy and
// $no_proxy) environment variables.
var DefaultTransport RoundTripper = &Transport{
	Proxy: ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}).DialContext,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

// DefaultMaxIdleConnsPerHost is the default value of Transport's
// MaxIdleConnsPerHost.
const DefaultMaxIdleConnsPerHost = 2

// Transport is an implementation of RoundTripper that supports HTTP,
// HTTPS, and HTTP proxies (for either HTTP or HTTPS with CONNECT).
//
// By default, Transport caches connections for future re-use.
// This may leave many open connections when accessing many hosts.
// This behavior can be managed using Transport's CloseIdleConnections method
// and the MaxIdleConnsPerHost and DisableKeepAlives fields.
//
// Transports should be reused instead of created as needed.
// Transports are safe for concurrent use by multiple goroutines.
//
// A Transport is a low-level primitive for making HTTP and HTTPS requests.
// For high-level functionality, such as cookies and redirects, see Client.
//
// Transport uses HTTP/1.1 for HTTP URLs and either HTTP/1.1 or HTTP/2
// for HTTPS URLs, depending on whether the server supports HTTP/2,
// and how the Transport is configured. The DefaultTransport supports HTTP/2.
// To explicitly enable HTTP/2 on a transport, use golang.org/x/net/http2
// and call ConfigureTransport. See the package docs for more about HTTP/2.
//
// The Transport will send CONNECT requests to a proxy for its own use
// when processing HTTPS requests, but Transport should generally not
// be used to send a CONNECT request. That is, the Request passed to
// the RoundTrip method should not have a Method of "CONNECT", as Go's
// HTTP/1.x implementation does not support full-duplex request bodies
// being written while the response body is streamed. Go's HTTP/2
// implementation does support full duplex, but many CONNECT proxies speak
// HTTP/1.x.
type Transport struct {
	idleMu     sync.Mutex
	wantIdle   bool                                // user has requested to close all idle conns
	idleConn   map[connectMethodKey][]*persistConn // most recently used at end
	idleConnCh map[connectMethodKey]chan *persistConn
	idleLRU    connLRU

	reqMu       sync.Mutex
	reqCanceler map[*Request]func(error)

	altMu    sync.Mutex   // guards changing altProto only
	altProto atomic.Value // of nil or map[string]RoundTripper, key is URI scheme

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	//
	// The proxy type is determined by the URL scheme. "http"
	// and "socks5" are supported. If the scheme is empty,
	// "http" is assumed.
	//
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*Request) (*url.URL, error)

	// DialContext specifies the dial function for creating unencrypted TCP connections.
	// If DialContext is nil (and the deprecated Dial below is also nil),
	// then the transport dials using package net.
	// [Min] Dial with Context，可以马上 cancel 本次dial
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Dial specifies the dial function for creating unencrypted TCP connections.
	//
	// Deprecated: Use DialContext instead, which allows the transport
	// to cancel dials as soon as they are no longer needed.
	// If both are set, DialContext takes priority.
	// [Min] 已经弃用
	Dial func(network, addr string) (net.Conn, error)

	// DialTLS specifies an optional dial function for creating
	// TLS connections for non-proxied HTTPS requests.
	//
	// If DialTLS is nil, Dial and TLSClientConfig are used.
	//
	// If DialTLS is set, the Dial hook is not used for HTTPS
	// requests and the TLSClientConfig and TLSHandshakeTimeout
	// are ignored. The returned net.Conn is assumed to already be
	// past the TLS handshake.
	DialTLS func(network, addr string) (net.Conn, error)

	// TLSClientConfig specifies the TLS configuration to use with
	// tls.Client.
	// If nil, the default configuration is used.
	// If non-nil, HTTP/2 support may not be enabled by default.
	TLSClientConfig *tls.Config

	// TLSHandshakeTimeout specifies the maximum amount of time waiting to
	// wait for a TLS handshake. Zero means no timeout.
	TLSHandshakeTimeout time.Duration

	// DisableKeepAlives, if true, prevents re-use of TCP connections
	// between different HTTP requests.
	// [Min] 非 keepalive，TCP 连接不可在不同的 request 中重复使用
	DisableKeepAlives bool

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool

	// MaxIdleConns controls the maximum number of idle (keep-alive)
	// connections across all hosts. Zero means no limit.
	// [Min] 最大闲置连接数，0表示没有限制
	MaxIdleConns int

	// MaxIdleConnsPerHost, if non-zero, controls the maximum idle
	// (keep-alive) connections to keep per-host. If zero,
	// DefaultMaxIdleConnsPerHost is used.
	// [Min] 表示同一个 host 的最大闲置连接数，如果为0，使用默认值2，负数同 DisableKeepAlives=true 等价
	MaxIdleConnsPerHost int

	// IdleConnTimeout is the maximum amount of time an idle
	// (keep-alive) connection will remain idle before closing
	// itself.
	// Zero means no limit.
	// [Min] 连接闲置的最大时间，到达最大时间后会关闭该连接
	IdleConnTimeout time.Duration

	// ResponseHeaderTimeout, if non-zero, specifies the amount of
	// time to wait for a server's response headers after fully
	// writing the request (including its body, if any). This
	// time does not include the time to read the response body.
	ResponseHeaderTimeout time.Duration

	// ExpectContinueTimeout, if non-zero, specifies the amount of
	// time to wait for a server's first response headers after fully
	// writing the request headers if the request has an
	// "Expect: 100-continue" header. Zero means no timeout and
	// causes the body to be sent immediately, without
	// waiting for the server to approve.
	// This time does not include the time to send the request header.
	ExpectContinueTimeout time.Duration

	// TLSNextProto specifies how the Transport switches to an
	// alternate protocol (such as HTTP/2) after a TLS NPN/ALPN
	// protocol negotiation. If Transport dials an TLS connection
	// with a non-empty protocol name and TLSNextProto contains a
	// map entry for that key (such as "h2"), then the func is
	// called with the request's authority (such as "example.com"
	// or "example.com:1234") and the TLS connection. The function
	// must return a RoundTripper that then handles the request.
	// If TLSNextProto is not nil, HTTP/2 support is not enabled
	// automatically.
	TLSNextProto map[string]func(authority string, c *tls.Conn) RoundTripper

	// ProxyConnectHeader optionally specifies headers to send to
	// proxies during CONNECT requests.
	ProxyConnectHeader Header

	// MaxResponseHeaderBytes specifies a limit on how many
	// response bytes are allowed in the server's response
	// header.
	//
	// Zero means to use a default limit.
	MaxResponseHeaderBytes int64

	// nextProtoOnce guards initialization of TLSNextProto and
	// h2transport (via onceSetNextProtoDefaults)
	nextProtoOnce sync.Once
	h2transport   *http2Transport // non-nil if http2 wired up

	// TODO: tunable on max per-host TCP dials in flight (Issue 13957)
}

// onceSetNextProtoDefaults initializes TLSNextProto.
// It must be called via t.nextProtoOnce.Do.
func (t *Transport) onceSetNextProtoDefaults() {
	if strings.Contains(os.Getenv("GODEBUG"), "http2client=0") {
		return
	}
	if t.TLSNextProto != nil {
		// This is the documented way to disable http2 on a
		// Transport.
		return
	}
	if t.TLSClientConfig != nil || t.Dial != nil || t.DialTLS != nil {
		// Be conservative and don't automatically enable
		// http2 if they've specified a custom TLS config or
		// custom dialers. Let them opt-in themselves via
		// http2.ConfigureTransport so we don't surprise them
		// by modifying their tls.Config. Issue 14275.
		return
	}
	t2, err := http2configureTransport(t)
	if err != nil {
		log.Printf("Error enabling Transport HTTP/2 support: %v", err)
		return
	}
	t.h2transport = t2

	// Auto-configure the http2.Transport's MaxHeaderListSize from
	// the http.Transport's MaxResponseHeaderBytes. They don't
	// exactly mean the same thing, but they're close.
	//
	// TODO: also add this to x/net/http2.Configure Transport, behind
	// a +build go1.7 build tag:
	if limit1 := t.MaxResponseHeaderBytes; limit1 != 0 && t2.MaxHeaderListSize == 0 {
		const h2max = 1<<32 - 1
		if limit1 >= h2max {
			t2.MaxHeaderListSize = h2max
		} else {
			t2.MaxHeaderListSize = uint32(limit1)
		}
	}
}

// ProxyFromEnvironment returns the URL of the proxy to use for a
// given request, as indicated by the environment variables
// HTTP_PROXY, HTTPS_PROXY and NO_PROXY (or the lowercase versions
// thereof). HTTPS_PROXY takes precedence over HTTP_PROXY for https
// requests.
//
// The environment values may be either a complete URL or a
// "host[:port]", in which case the "http" scheme is assumed.
// An error is returned if the value is a different form.
//
// A nil URL and nil error are returned if no proxy is defined in the
// environment, or a proxy should not be used for the given request,
// as defined by NO_PROXY.
//
// As a special case, if req.URL.Host is "localhost" (with or without
// a port number), then a nil URL and nil error will be returned.
// [Min] 根据 req 的地址和环境变量中的代理地址，返回对于该 req 地址的可用代理地址
func ProxyFromEnvironment(req *Request) (*url.URL, error) {
	var proxy string
	// [Min] 如果为 https，调用httpsProxyEnv.Get()，获取 proxy
	if req.URL.Scheme == "https" {
		proxy = httpsProxyEnv.Get()
	}
	if proxy == "" {
		proxy = httpProxyEnv.Get() // [Min] 获取 http proxy
		if proxy != "" && os.Getenv("REQUEST_METHOD") != "" {
			return nil, errors.New("net/http: refusing to use HTTP_PROXY value in CGI environment; see golang.org/s/cgihttpproxy")
		}
	}
	// [Min] proxy 为空，则直接返回 nil，nil
	if proxy == "" {
		return nil, nil
	}
	// [Min] 判断 url中的地址是否可以使用代理
	if !useProxy(canonicalAddr(req.URL)) {
		return nil, nil
	}
	// [Min] 将代理地址解析为 proxyURL
	proxyURL, err := url.Parse(proxy)
	if err != nil ||
		(proxyURL.Scheme != "http" &&
			proxyURL.Scheme != "https" &&
			proxyURL.Scheme != "socks5") {
		// proxy was bogus. Try prepending "http://" to it and
		// see if that parses correctly. If not, we fall
		// through and complain about the original one.
		if proxyURL, err := url.Parse("http://" + proxy); err == nil {
			return proxyURL, nil
		}

	}
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address %q: %v", proxy, err)
	}
	return proxyURL, nil
}

// ProxyURL returns a proxy function (for use in a Transport)
// that always returns the same URL.
// [Min] 返回一个函数，该函数用于对任何一个 Request 返回一个给定的 URL
func ProxyURL(fixedURL *url.URL) func(*Request) (*url.URL, error) {
	return func(*Request) (*url.URL, error) {
		return fixedURL, nil
	}
}

// transportRequest is a wrapper around a *Request that adds
// optional extra headers to write and stores any error to return
// from roundTrip.
// [Min] transportRequest包裹了 Request,变添加了额外的 header 和 trace 等信息
type transportRequest struct {
	*Request                        // original request, not to be mutated
	extra    Header                 // extra headers to write, or nil
	trace    *httptrace.ClientTrace // optional

	mu  sync.Mutex // guards err
	err error      // first setError value for mapRoundTripError to consider
}

// [Min] 如果 extra 不为 nil，直接返回 extra，否则返回空 header
func (tr *transportRequest) extraHeaders() Header {
	if tr.extra == nil {
		tr.extra = make(Header)
	}
	return tr.extra
}

// [Min] 设置 tr.err，只会修改第一个 error
func (tr *transportRequest) setError(err error) {
	tr.mu.Lock()
	if tr.err == nil {
		tr.err = err
	}
	tr.mu.Unlock()
}

// RoundTrip implements the RoundTripper interface.
//
// For higher-level HTTP client support (such as handling of cookies
// and redirects), see Get, Post, and the Client type.
// [Min] 实现了RoundTripper接口，发起Request，得到 Response
func (t *Transport) RoundTrip(req *Request) (*Response, error) {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	ctx := req.Context()
	trace := httptrace.ContextClientTrace(ctx)

	// [Min] Request URL,Header为 nil，报错
	if req.URL == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		req.closeBody()
		return nil, errors.New("http: nil Request.Header")
	}
	scheme := req.URL.Scheme
	isHTTP := scheme == "http" || scheme == "https"
	// [Min] 如果是 http/https，检查 header 中的 key-value 对是否有效
	if isHTTP {
		for k, vv := range req.Header {
			if !httplex.ValidHeaderFieldName(k) {
				return nil, fmt.Errorf("net/http: invalid header field name %q", k)
			}
			for _, v := range vv {
				if !httplex.ValidHeaderFieldValue(v) {
					return nil, fmt.Errorf("net/http: invalid header field value %q for key %v", v, k)
				}
			}
		}
	}

	// [Min] 从下面的"unsupported protocol scheme" error大致可以猜测
	// [Min] t.altProto中应该主要保存了用于处理非 http/https scheme 的 RoundTripper
	altProto, _ := t.altProto.Load().(map[string]RoundTripper)
	// [Min] 判断该 request 的 scheme 是否在预定义的 RoundTripper map 中，
	// [Min] 如果是，则使用该RoundTripper执行 request，如果返回的不是ErrSkipAltProtocol错误，则按此 response 返回
	if altRT := altProto[scheme]; altRT != nil {
		if resp, err := altRT.RoundTrip(req); err != ErrSkipAltProtocol {
			return resp, err
		}
	}
	// [Min] 如果不是 http/https，理应由上述 altProto处理了（如果有的话），否则报错
	if !isHTTP {
		req.closeBody()
		return nil, &badStringError{"unsupported protocol scheme", scheme}
	}
	// [Min] 判断Method是否合法，不合法报错
	if req.Method != "" && !validMethod(req.Method) {
		return nil, fmt.Errorf("net/http: invalid method %q", req.Method)
	}
	// [Min] Host 不能为空，否则报错
	if req.URL.Host == "" {
		req.closeBody()
		return nil, errors.New("http: no Host in request URL")
	}

	// [Min] for 循环用来重新发起那些 roundTrip返回 error 后可以重新发起的 request
	for {
		// treq gets modified by roundTrip, so we need to recreate for each retry.
		treq := &transportRequest{Request: req, trace: trace}
		// [Min] 由transportRequest构造connectMethod
		cm, err := t.connectMethodForRequest(treq)
		if err != nil {
			req.closeBody()
			return nil, err
		}

		// Get the cached or newly-created connection to either the
		// host (for http or https), the http proxy, or the http proxy
		// pre-CONNECTed to https server. In any case, we'll be ready
		// to send it requests.
		// [Min] 获取可用于发送 request 的连接
		pconn, err := t.getConn(treq, cm)
		// [Min] 如果失败了，则将该 request 从 reqCanceler 中删去
		if err != nil {
			t.setReqCanceler(req, nil)
			req.closeBody()
			return nil, err
		}

		var resp *Response
		// [Min] 如果 pconn.alt不为 nil，则调用 alt 的RoundTrip来发起 request 获得 response
		// [Min] 否则调用pconn.roundTrip
		if pconn.alt != nil {
			// HTTP/2 path.
			t.setReqCanceler(req, nil) // not cancelable with CancelRequest
			resp, err = pconn.alt.RoundTrip(req)
		} else {
			resp, err = pconn.roundTrip(treq)
		}
		// [Min] 如果没有错误，直接返回 response
		if err == nil {
			return resp, nil
		}
		// [Min] 判断是否可以重新发起
		if !pconn.shouldRetryRequest(req, err) {
			// Issue 16465: return underlying net.Conn.Read error from peek,
			// as we've historically done.
			if e, ok := err.(transportReadFromServerError); ok {
				err = e.err
			}
			return nil, err
		}
		testHookRoundTripRetried()

		// Rewind the body if we're able to.  (HTTP/2 does this itself so we only
		// need to do it for HTTP/1.1 connections.)
		// [Min] 如果 req.GetBody 不为 nil（可以获取 request body 的拷贝）且不是 http2
		// [Min] 那么就拷贝当前这个 request，再将当初创建该 request 的原始body拷贝至这个新的request中
		// [Min] 再继续循环，并以这个新的 request 来重新发起
		if req.GetBody != nil && pconn.alt == nil {
			newReq := *req
			var err error
			newReq.Body, err = req.GetBody()
			if err != nil {
				return nil, err
			}
			req = &newReq
		}
	}
}

// shouldRetryRequest reports whether we should retry sending a failed
// HTTP request on a new connection. The non-nil input error is the
// error from roundTrip.
// [Min] 根据 request 和 roundTrip 返回的 error，判断是否应该重新发起 request
func (pc *persistConn) shouldRetryRequest(req *Request, err error) bool {
	if err == http2ErrNoCachedConn {
		// Issue 16582: if the user started a bunch of
		// requests at once, they can all pick the same conn
		// and violate the server's max concurrent streams.
		// Instead, match the HTTP/1 behavior for now and dial
		// again to get a new TCP connection, rather than failing
		// this request.
		return true
	}
	if err == errMissingHost {
		// User error.
		return false
	}
	if !pc.isReused() {
		// This was a fresh connection. There's no reason the server
		// should've hung up on us.
		//
		// Also, if we retried now, we could loop forever
		// creating new connections and retrying if the server
		// is just hanging up on us because it doesn't like
		// our request (as opposed to sending an error).
		return false
	}
	if _, ok := err.(nothingWrittenError); ok {
		// We never wrote anything, so it's safe to retry, if there's no body or we
		// can "rewind" the body with GetBody.
		return req.outgoingLength() == 0 || req.GetBody != nil
	}
	if !req.isReplayable() {
		// Don't retry non-idempotent requests.
		return false
	}
	if _, ok := err.(transportReadFromServerError); ok {
		// We got some non-EOF net.Conn.Read failure reading
		// the 1st response byte from the server.
		return true
	}
	if err == errServerClosedIdle {
		// The server replied with io.EOF while we were trying to
		// read the response. Probably an unfortunately keep-alive
		// timeout, just as the client was writing a request.
		return true
	}
	return false // conservatively
}

// ErrSkipAltProtocol is a sentinel error value defined by Transport.RegisterProtocol.
var ErrSkipAltProtocol = errors.New("net/http: skip alternate protocol")

// RegisterProtocol registers a new protocol with scheme.
// The Transport will pass requests using the given scheme to rt.
// It is rt's responsibility to simulate HTTP request semantics.
//
// RegisterProtocol can be used by other packages to provide
// implementations of protocol schemes like "ftp" or "file".
//
// If rt.RoundTrip returns ErrSkipAltProtocol, the Transport will
// handle the RoundTrip itself for that one request, as if the
// protocol were not registered.
// [Min] 以新的RoundTripper来注册altProto，其中 altProto 为 map，scheme 为 key，rt为value
func (t *Transport) RegisterProtocol(scheme string, rt RoundTripper) {
	t.altMu.Lock()
	defer t.altMu.Unlock()
	oldMap, _ := t.altProto.Load().(map[string]RoundTripper)
	if _, exists := oldMap[scheme]; exists {
		panic("protocol " + scheme + " already registered")
	}
	newMap := make(map[string]RoundTripper)
	for k, v := range oldMap {
		newMap[k] = v
	}
	newMap[scheme] = rt
	t.altProto.Store(newMap)
}

// CloseIdleConnections closes any connections which were previously
// connected from previous requests but are now sitting idle in
// a "keep-alive" state. It does not interrupt any connections currently
// in use.
// [Min] 关闭闲置的连接，不影响正在使用的
func (t *Transport) CloseIdleConnections() {
	t.nextProtoOnce.Do(t.onceSetNextProtoDefaults)
	// [Min] 将用于记录闲置连接的相关字段置为零值
	t.idleMu.Lock()
	m := t.idleConn
	t.idleConn = nil
	t.idleConnCh = nil
	t.wantIdle = true
	t.idleLRU = connLRU{}
	t.idleMu.Unlock()
	// [Min] 关闭每一个闲置连接
	for _, conns := range m {
		for _, pconn := range conns {
			pconn.close(errCloseIdleConns)
		}
	}
	if t2 := t.h2transport; t2 != nil {
		t2.CloseIdleConnections()
	}
}

// CancelRequest cancels an in-flight request by closing its connection.
// CancelRequest should only be called after RoundTrip has returned.
//
// Deprecated: Use Request.WithContext to create a request with a
// cancelable context instead. CancelRequest cannot cancel HTTP/2
// requests.
// [Min] 取消 request，已弃用
func (t *Transport) CancelRequest(req *Request) {
	t.cancelRequest(req, errRequestCanceled)
}

// Cancel an in-flight request, recording the error value.
// [Min] 通过触发 t.reqCanceler 中注册的函数，来向获取该 request 连接时注册的cancelc通道发送 error，
// [Min] 从而使得后续逻辑可以通过此通道取消 request，同时将此 request 从 reqCancler 中删除
func (t *Transport) cancelRequest(req *Request, err error) {
	t.reqMu.Lock()
	cancel := t.reqCanceler[req]
	delete(t.reqCanceler, req)
	t.reqMu.Unlock()
	if cancel != nil {
		cancel(err)
	}
}

//
// Private implementation past this point.
//

var (
	httpProxyEnv = &envOnce{
		names: []string{"HTTP_PROXY", "http_proxy"},
	}
	httpsProxyEnv = &envOnce{
		names: []string{"HTTPS_PROXY", "https_proxy"},
	}
	noProxyEnv = &envOnce{
		names: []string{"NO_PROXY", "no_proxy"},
	}
)

// envOnce looks up an environment variable (optionally by multiple
// names) once. It mitigates expensive lookups on some platforms
// (e.g. Windows).
type envOnce struct {
	names []string
	once  sync.Once
	val   string
}

// [Min] 只对 e 执行一次，以 e.names 中值为环境变量名，依次查找，返回第一个不为空的值
func (e *envOnce) Get() string {
	e.once.Do(e.init)
	return e.val
}

// [Min] 以 e.names 中值为环境变量名，依次查找，更新 e.val 为第一个不为空的值
func (e *envOnce) init() {
	for _, n := range e.names {
		e.val = os.Getenv(n)
		if e.val != "" {
			return
		}
	}
}

// reset is used by tests
// [Min] 重置 e 的执行Do的次数
func (e *envOnce) reset() {
	e.once = sync.Once{}
	e.val = ""
}

// [Min] 由transportRequest构造connectMethod，主要是获取proxyURL，设置目标 scheme 和 addr
func (t *Transport) connectMethodForRequest(treq *transportRequest) (cm connectMethod, err error) {
	// [Min] 判断 request 中 URL 的 port 是否有效
	if port := treq.URL.Port(); !validPort(port) {
		return cm, fmt.Errorf("invalid URL port %q", port)
	}
	// [Min] 将 request 中的 scheme 和URL 设为目标 scheme 和 addr
	cm.targetScheme = treq.URL.Scheme
	cm.targetAddr = canonicalAddr(treq.URL)
	if t.Proxy != nil {
		// [Min] 获得对于该 request 可用的proxyURL
		cm.proxyURL, err = t.Proxy(treq.Request)
		if err == nil && cm.proxyURL != nil {
			if port := cm.proxyURL.Port(); !validPort(port) {
				return cm, fmt.Errorf("invalid proxy URL port %q", port)
			}
		}
	}
	return cm, err
}

// proxyAuth returns the Proxy-Authorization header to set
// on requests, if applicable.
// [Min] 设置Proxy-Authorization的内容
func (cm *connectMethod) proxyAuth() string {
	if cm.proxyURL == nil {
		return ""
	}
	if u := cm.proxyURL.User; u != nil {
		username := u.Username()
		password, _ := u.Password()
		return "Basic " + basicAuth(username, password)
	}
	return ""
}

// error values for debugging and testing, not seen by users.
var (
	errKeepAlivesDisabled = errors.New("http: putIdleConn: keep alives disabled")
	errConnBroken         = errors.New("http: putIdleConn: connection is in bad state")
	errWantIdle           = errors.New("http: putIdleConn: CloseIdleConnections was called")
	errTooManyIdle        = errors.New("http: putIdleConn: too many idle connections")
	errTooManyIdleHost    = errors.New("http: putIdleConn: too many idle connections for host")
	errCloseIdleConns     = errors.New("http: CloseIdleConnections called")
	errReadLoopExiting    = errors.New("http: persistConn.readLoop exiting")
	errIdleConnTimeout    = errors.New("http: idle connection timeout")
	errNotCachingH2Conn   = errors.New("http: not caching alternate protocol's connections")

	// errServerClosedIdle is not seen by users for idempotent requests, but may be
	// seen by a user if the server shuts down an idle connection and sends its FIN
	// in flight with already-written POST body bytes from the client.
	// See https://github.com/golang/go/issues/19943#issuecomment-355607646
	errServerClosedIdle = errors.New("http: server closed idle connection")
)

// transportReadFromServerError is used by Transport.readLoop when the
// 1 byte peek read fails and we're actually anticipating a response.
// Usually this is just due to the inherent keep-alive shut down race,
// where the server closed the connection at the same time the client
// wrote. The underlying err field is usually io.EOF or some
// ECONNRESET sort of thing which varies by platform. But it might be
// the user's custom net.Conn.Read error too, so we carry it along for
// them to return from Transport.RoundTrip.
type transportReadFromServerError struct {
	err error
}

func (e transportReadFromServerError) Error() string {
	return fmt.Sprintf("net/http: Transport failed to read from server: %v", e.err)
}

// [Min] 尝试将连接加入闲置连接中，如果不行，则关闭该连接
func (t *Transport) putOrCloseIdleConn(pconn *persistConn) {
	if err := t.tryPutIdleConn(pconn); err != nil {
		pconn.close(err)
	}
}

// [Min] 返回MaxIdleConnsPerHost，如果为0，返回2
func (t *Transport) maxIdleConnsPerHost() int {
	if v := t.MaxIdleConnsPerHost; v != 0 {
		return v
	}
	return DefaultMaxIdleConnsPerHost
}

// tryPutIdleConn adds pconn to the list of idle persistent connections awaiting
// a new request.
// If pconn is no longer needed or not in a good state, tryPutIdleConn returns
// an error explaining why it wasn't registered.
// tryPutIdleConn does not close pconn. Use putOrCloseIdleConn instead for that.
// [Min] 尝试将连接注册为可以接收新请求的闲置连接，如果连接不可用，报错
func (t *Transport) tryPutIdleConn(pconn *persistConn) error {
	// [Min] 不可重复使用的情况
	if t.DisableKeepAlives || t.MaxIdleConnsPerHost < 0 {
		return errKeepAlivesDisabled
	}
	// [Min] 连接不可用
	if pconn.isBroken() {
		return errConnBroken
	}
	// [Min] alt不为 nil 报错
	if pconn.alt != nil {
		return errNotCachingH2Conn
	}
	pconn.markReused()
	key := pconn.cacheKey

	t.idleMu.Lock()
	defer t.idleMu.Unlock()

	waitingDialer := t.idleConnCh[key]
	select {
	// [Min] 如果有人在通过idleConnCh等待该 key 对应的闲置连接，则他会收到该连接
	case waitingDialer <- pconn:
		// We're done with this pconn and somebody else is
		// currently waiting for a conn of this type (they're
		// actively dialing, but this conn is ready
		// first). Chrome calls this socket late binding. See
		// https://insouciant.org/tech/connection-management-in-chromium/
		return nil
	default:
		// [Min] 如果没人在等待该 key 的连接，且该 key 对应的idleConnCh存在，则删除该通道
		if waitingDialer != nil {
			// They had populated this, but their dial won
			// first, so we can clean up this map entry.
			delete(t.idleConnCh, key)
		}
	}
	// [Min] 如果 wantIdle 为 true，则报错errWantIdle
	if t.wantIdle {
		return errWantIdle
	}
	if t.idleConn == nil {
		t.idleConn = make(map[connectMethodKey][]*persistConn)
	}
	idles := t.idleConn[key]
	// [Min] 如果该 key 对应的闲置连接已经达到单个 host 的最大数量，则报错，说明无法再添加进闲置连接
	if len(idles) >= t.maxIdleConnsPerHost() {
		return errTooManyIdleHost
	}
	// [Min] 如果已经存在，也报错
	for _, exist := range idles {
		if exist == pconn {
			log.Fatalf("dup idle pconn %p in freelist", pconn)
		}
	}
	// [Min] 将该连接加入闲置连接中
	t.idleConn[key] = append(idles, pconn)
	t.idleLRU.add(pconn)
	// [Min] 如果idleLRU中的连接数大于MaxIdleConns，那么
	if t.MaxIdleConns != 0 && t.idleLRU.len() > t.MaxIdleConns {
		oldest := t.idleLRU.removeOldest()
		oldest.close(errTooManyIdle)
		// [Min] 将此连接从idleConn和idleLRU中删除（idleLRU的删除动作又做了一遍）
		t.removeIdleConnLocked(oldest)
	}
	if t.IdleConnTimeout > 0 {
		if pconn.idleTimer != nil {
			// [Min] 如果IdleConnTimeout且idleTimer不为 nil（已经有AfterFunc 注册），则只需重置超时时间
			pconn.idleTimer.Reset(t.IdleConnTimeout)
		} else {
			// [Min] 如果如果IdleConnTimeout且idleTimer为 nil，
			// [Min] 则注册一个以IdleConnTimeout 为超时时间的 timer，并且在超时后会执行函数closeConnIfStillIdle
			pconn.idleTimer = time.AfterFunc(t.IdleConnTimeout, pconn.closeConnIfStillIdle)
		}
	}
	// [Min] 更新闲置起始时间
	pconn.idleAt = time.Now()
	return nil
}

// getIdleConnCh returns a channel to receive and return idle
// persistent connection for the given connectMethod.
// It may return nil, if persistent connections are not being used.
// [Min] 根据connectMethod来获取他对应的闲置连接通道，没有就新建一个
func (t *Transport) getIdleConnCh(cm connectMethod) chan *persistConn {
	if t.DisableKeepAlives {
		return nil
	}
	key := cm.key()
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	t.wantIdle = false
	if t.idleConnCh == nil {
		t.idleConnCh = make(map[connectMethodKey]chan *persistConn)
	}
	ch, ok := t.idleConnCh[key]
	if !ok {
		ch = make(chan *persistConn)
		t.idleConnCh[key] = ch
	}
	return ch
}

// [Min] 根据connectMethod来获取闲置的连接
func (t *Transport) getIdleConn(cm connectMethod) (pconn *persistConn, idleSince time.Time) {
	// [Min] 获取该connectMethod的 key
	key := cm.key()
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	for {
		pconns, ok := t.idleConn[key]
		// [Min] t.idleConn中没有，直接返回 nil
		if !ok {
			return nil, time.Time{}
		}
		// [Min] 如果只有一个闲置的连接，就使用该连接
		// [Min] 如果不只一个，则使用最后一个（刚使用完限制下来的）
		// [Min] 将决定使用的连接从闲置连接中删除
		if len(pconns) == 1 {
			pconn = pconns[0]
			delete(t.idleConn, key)
		} else {
			// 2 or more cached connections; use the most
			// recently used one at the end.
			pconn = pconns[len(pconns)-1]
			t.idleConn[key] = pconns[:len(pconns)-1]
		}
		// [Min] 从idleLRU中删除该连接
		t.idleLRU.remove(pconn)
		// [Min] 如果该连接不可用，则继续循环找下一个可用的闲置连接
		if pconn.isBroken() {
			// There is a tiny window where this is
			// possible, between the connecting dying and
			// the persistConn readLoop calling
			// Transport.removeIdleConn. Just skip it and
			// carry on.
			continue
		}
		// [Min] 如果该连接已经闲置超时（无法停止该idleTimer，说明已经关闭或超时），
		// [Min] 则继续循环寻找下一个闲置连接
		if pconn.idleTimer != nil && !pconn.idleTimer.Stop() {
			// We picked this conn at the ~same time it
			// was expiring and it's trying to close
			// itself in another goroutine. Don't use it.
			continue
		}
		// [Min] 返回该连接和闲置的起始时间
		return pconn, pconn.idleAt
	}
}

// removeIdleConn marks pconn as dead.
// [Min] 删除闲置连接
func (t *Transport) removeIdleConn(pconn *persistConn) {
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	t.removeIdleConnLocked(pconn)
}

// t.idleMu must be held.
// [Min] 从idleLRU和 idleConn 中删除连接
func (t *Transport) removeIdleConnLocked(pconn *persistConn) {
	if pconn.idleTimer != nil {
		pconn.idleTimer.Stop()
	}
	t.idleLRU.remove(pconn)
	key := pconn.cacheKey
	pconns := t.idleConn[key]
	switch len(pconns) {
	case 0:
		// Nothing
	case 1:
		if pconns[0] == pconn {
			delete(t.idleConn, key)
		}
	default:
		for i, v := range pconns {
			if v != pconn {
				continue
			}
			// Slide down, keeping most recently-used
			// conns at the end.
			// [Min] 保持相对位置不变
			copy(pconns[i:], pconns[i+1:])
			t.idleConn[key] = pconns[:len(pconns)-1]
			break
		}
	}
}

// [Min] 如果 fn 不为 nil，从t.reqCanceler中设置该 request 对应的函数为 fn
// [Min] 如果 fn 为 nil，则从t.reqCanceler中删除该 request
func (t *Transport) setReqCanceler(r *Request, fn func(error)) {
	t.reqMu.Lock()
	defer t.reqMu.Unlock()
	if t.reqCanceler == nil {
		t.reqCanceler = make(map[*Request]func(error))
	}
	if fn != nil {
		t.reqCanceler[r] = fn
	} else {
		delete(t.reqCanceler, r)
	}
}

// replaceReqCanceler replaces an existing cancel function. If there is no cancel function
// for the request, we don't set the function and return false.
// Since CancelRequest will clear the canceler, we can use the return value to detect if
// the request was canceled since the last setReqCancel call.
// [Min] 如果返回的是 false，则说明该 request 已经被取消，因为如果不是被取消掉的，t.reqCanceler[r]至少是一个空函数func(error){}
func (t *Transport) replaceReqCanceler(r *Request, fn func(error)) bool {
	t.reqMu.Lock()
	defer t.reqMu.Unlock()
	_, ok := t.reqCanceler[r]
	if !ok {
		return false
	}
	if fn != nil {
		t.reqCanceler[r] = fn
	} else {
		delete(t.reqCanceler, r)
	}
	return true
}

var zeroDialer net.Dialer

// [Min] 非 https 获取 Conn
func (t *Transport) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	// [Min] 如果DialContext不为 nil，则直接调用该方法获取 Conn
	// [Min] 默认的 Transport 定义了一个默认的 Dialer，此 Dialer 的DialContext方法即为默认的DialContext
	if t.DialContext != nil {
		return t.DialContext(ctx, network, addr)
	}
	// [Min] 如果DialContext为 nil，Dial 不为 nil（弃用为妙，不含 context，无法优雅的 cancel）
	// [Min] 则调用 Dial 来获取 Conn
	if t.Dial != nil {
		c, err := t.Dial(network, addr)
		if c == nil && err == nil {
			err = errors.New("net/http: Transport.Dial hook returned (nil, nil)")
		}
		return c, err
	}
	// [Min] 如果 Dial 和 DialContext 均为 nil，则以零值 Dialer 的 DialContext 来获取 Conn
	return zeroDialer.DialContext(ctx, network, addr)
}

// getConn dials and creates a new persistConn to the target as
// specified in the connectMethod. This includes doing a proxy CONNECT
// and/or setting up TLS.  If this doesn't return an error, the persistConn
// is ready to write requests to.
// [Min] 获得一个持久的可以用于写入 request 的连接
func (t *Transport) getConn(treq *transportRequest, cm connectMethod) (*persistConn, error) {
	req := treq.Request
	trace := treq.trace
	ctx := req.Context()
	if trace != nil && trace.GetConn != nil {
		trace.GetConn(cm.addr())
	}
	// [Min] 获取闲置连接 pc，如果有则返回该连接
	if pc, idleSince := t.getIdleConn(cm); pc != nil {
		if trace != nil && trace.GotConn != nil {
			trace.GotConn(pc.gotIdleConnTrace(idleSince))
		}
		// set request canceler to some non-nil function so we
		// can detect whether it was cleared between now and when
		// we enter roundTrip
		// [Min] 在t.reqCanceler中设置该 request 对应的值为非 nil函数（nil表示删除该 request）
		t.setReqCanceler(req, func(error) {})
		return pc, nil
	}

	type dialRes struct {
		pc  *persistConn
		err error
	}
	// [Min] 注册 dialc 用于接收 dialConn 获取的连接
	dialc := make(chan dialRes)

	// Copy these hooks so we don't race on the postPendingDial in
	// the goroutine we launch. Issue 11136.
	testHookPrePendingDial := testHookPrePendingDial
	testHookPostPendingDial := testHookPostPendingDial

	// [Min] 在 dailConn 不够快（后续 select 执行了其他 case）还没来的及处理的情况下，处理自己发起的 dialConn 的返回的函数
	// [Min] 执行时会通过开启一个 goroutine 来处理，待执行
	handlePendingDial := func() {
		testHookPrePendingDial()
		go func() {
			if v := <-dialc; v.err == nil {
				// [Min] 尝试将 dial 返回的连接加入闲置连接中，失败的化就关闭该连接
				t.putOrCloseIdleConn(v.pc)
			}
			testHookPostPendingDial()
		}()
	}

	// [Min] 申请一个非阻塞的长度为1的 error通道，
	// [Min] 并注册该 request 的reqCanceler 为一个向该通道发送 err 的函数
	cancelc := make(chan error, 1)
	t.setReqCanceler(req, func(err error) { cancelc <- err })

	// [Min] goroutine 发起 dialConn，获取连接，并通过dialc等待对该连接的接收处理
	go func() {
		pc, err := t.dialConn(ctx, cm)
		dialc <- dialRes{pc, err}
	}()

	// [Min] 获取闲置连接通道
	idleConnCh := t.getIdleConnCh(cm)
	select {
	// [Min] 从 dialConn 中直接返回了数据（比较快的情况）
	case v := <-dialc:
		// Our dial finished.
		// [Min] 如果连接不为 nil，直接返回该连接
		if v.pc != nil {
			if trace != nil && trace.GotConn != nil && v.pc.alt == nil {
				trace.GotConn(httptrace.GotConnInfo{Conn: v.pc.conn})
			}
			return v.pc, nil
		}
		// Our dial failed. See why to return a nicer error
		// value.
		// [Min] 如果返回的连接为 nil，返回不同的 error
		select {
		// [Min] 由于 request cancel 掉了
		case <-req.Cancel:
			// It was an error due to cancelation, so prioritize that
			// error value. (Issue 16049)
			return nil, errRequestCanceledConn
		// [Min] request 超时了
		case <-req.Context().Done():
			return nil, req.Context().Err()
		// [Min] 触发了 reqCanceler 的函数
		case err := <-cancelc:
			if err == errRequestCanceled {
				err = errRequestCanceledConn
			}
			return nil, err
		default:
			// It wasn't an error due to cancelation, so
			// return the original error message:
			// [Min] 非取消 request 的错误，返回原始错误
			return nil, v.err
		}
	case pc := <-idleConnCh:
		// Another request finished first and its net.Conn
		// became available before our dial. Or somebody
		// else's dial that they didn't use.
		// But our dial is still going, so give it away
		// when it finishes:
		// [Min] 如果有一个连接在我们完成自己的 dialConn 之前闲置下来（对此连接在 readLoop 中调用了 tryPutIdleConn 通过idleConnCh发送过来）
		// [Min] 我们就直接使用该该连接，执行handlePendingDial，发起 goroutine，
		// [Min] 如果我们的 dial 顺利返回连接，则尝试保存该连接为闲置连接，
		// [Min] 而我们则继续使用从别处的来的连接
		handlePendingDial()
		if trace != nil && trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{Conn: pc.conn, Reused: pc.isReused()})
		}
		return pc, nil
	case <-req.Cancel:
		// [Min] request 已经 cancel，dialConn 还没结束，需要处理 dialConn 的返回
		handlePendingDial()
		return nil, errRequestCanceledConn
	case <-req.Context().Done():
		// [Min] request 已经超时， dialConn 还没结束，需要处理 dialConn 的返回
		handlePendingDial()
		return nil, req.Context().Err()
	case err := <-cancelc:
		// [Min] request 已经触发了 reqCanceler 的函数，dialConn 还没结束，需要处理 dialConn 的返回
		handlePendingDial()
		if err == errRequestCanceled {
			err = errRequestCanceledConn
		}
		return nil, err
	}
}

type oneConnDialer <-chan net.Conn

func newOneConnDialer(c net.Conn) proxy.Dialer {
	ch := make(chan net.Conn, 1)
	ch <- c
	return oneConnDialer(ch)
}

func (d oneConnDialer) Dial(network, addr string) (net.Conn, error) {
	select {
	case c := <-d:
		return c, nil
	default:
		return nil, io.EOF
	}
}

// The connect method and the transport can both specify a TLS
// Host name.  The transport's name takes precedence if present.
func chooseTLSHost(cm connectMethod, t *Transport) string {
	tlsHost := ""
	if t.TLSClientConfig != nil {
		tlsHost = t.TLSClientConfig.ServerName
	}
	if tlsHost == "" {
		tlsHost = cm.tlsHost()
	}
	return tlsHost
}

// Add TLS to a persistent connection, i.e. negotiate a TLS session. If pconn is already a TLS
// tunnel, this function establishes a nested TLS session inside the encrypted channel.
// The remote endpoint's name may be overridden by TLSClientConfig.ServerName.
func (pconn *persistConn) addTLS(name string, trace *httptrace.ClientTrace) error {
	// Initiate TLS and check remote host name against certificate.
	cfg := cloneTLSConfig(pconn.t.TLSClientConfig)
	if cfg.ServerName == "" {
		cfg.ServerName = name
	}
	plainConn := pconn.conn
	tlsConn := tls.Client(plainConn, cfg)
	errc := make(chan error, 2)
	var timer *time.Timer // for canceling TLS handshake
	if d := pconn.t.TLSHandshakeTimeout; d != 0 {
		timer = time.AfterFunc(d, func() {
			errc <- tlsHandshakeTimeoutError{}
		})
	}
	go func() {
		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		err := tlsConn.Handshake()
		if timer != nil {
			timer.Stop()
		}
		errc <- err
	}()
	if err := <-errc; err != nil {
		plainConn.Close()
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tls.ConnectionState{}, err)
		}
		return err
	}
	if !cfg.InsecureSkipVerify {
		if err := tlsConn.VerifyHostname(cfg.ServerName); err != nil {
			plainConn.Close()
			return err
		}
	}
	cs := tlsConn.ConnectionState()
	if trace != nil && trace.TLSHandshakeDone != nil {
		trace.TLSHandshakeDone(cs, nil)
	}
	pconn.tlsState = &cs
	pconn.conn = tlsConn
	return nil
}

func (t *Transport) dialConn(ctx context.Context, cm connectMethod) (*persistConn, error) {
	pconn := &persistConn{
		t:             t,
		cacheKey:      cm.key(),
		reqch:         make(chan requestAndChan, 1),
		writech:       make(chan writeRequest, 1),
		closech:       make(chan struct{}),
		writeErrCh:    make(chan error, 1),
		writeLoopDone: make(chan struct{}),
	}
	trace := httptrace.ContextClientTrace(ctx)
	wrapErr := func(err error) error {
		if cm.proxyURL != nil {
			// Return a typed error, per Issue 16997
			return &net.OpError{Op: "proxyconnect", Net: "tcp", Err: err}
		}
		return err
	}
	// [Min] 如果为 https，且给定了 DialTLS 的函数，则按 https 处理，否则以 http 处理
	if cm.scheme() == "https" && t.DialTLS != nil {
		var err error
		pconn.conn, err = t.DialTLS("tcp", cm.addr())
		if err != nil {
			return nil, wrapErr(err)
		}
		if pconn.conn == nil {
			return nil, wrapErr(errors.New("net/http: Transport.DialTLS returned (nil, nil)"))
		}
		if tc, ok := pconn.conn.(*tls.Conn); ok {
			// Handshake here, in case DialTLS didn't. TLSNextProto below
			// depends on it for knowing the connection state.
			if trace != nil && trace.TLSHandshakeStart != nil {
				trace.TLSHandshakeStart()
			}
			if err := tc.Handshake(); err != nil {
				go pconn.conn.Close()
				if trace != nil && trace.TLSHandshakeDone != nil {
					trace.TLSHandshakeDone(tls.ConnectionState{}, err)
				}
				return nil, err
			}
			cs := tc.ConnectionState()
			if trace != nil && trace.TLSHandshakeDone != nil {
				trace.TLSHandshakeDone(cs, nil)
			}
			pconn.tlsState = &cs
		}
	} else {
		// [Min] 非 https 获取 Conn
		conn, err := t.dial(ctx, "tcp", cm.addr())
		if err != nil {
			return nil, wrapErr(err)
		}
		pconn.conn = conn
		// [Min] 如果是因为t.DialTLS没有预先定义而导致采用了非 https 的方式获取 Conn，
		// [Min] 再调用addTLS来加密
		if cm.scheme() == "https" {
			var firstTLSHost string
			if firstTLSHost, _, err = net.SplitHostPort(cm.addr()); err != nil {
				return nil, wrapErr(err)
			}
			if err = pconn.addTLS(firstTLSHost, trace); err != nil {
				return nil, wrapErr(err)
			}
		}
	}

	// Proxy setup.
	// [Min] 再设置代理
	switch {
	case cm.proxyURL == nil:
		// Do nothing. Not using a proxy.
	case cm.proxyURL.Scheme == "socks5":
		conn := pconn.conn
		var auth *proxy.Auth
		if u := cm.proxyURL.User; u != nil {
			auth = &proxy.Auth{}
			auth.User = u.Username()
			auth.Password, _ = u.Password()
		}
		// [Min] newOneConnDialer(conn) 返回一个proxy.Dialer forward，
		// [Min] 当调用forward.Dial 的时候，会返回conn，也就是说newOneConnDialer相当于缓存了一个 conn
		// [Min] proxy.SOCKS5返回一个 proxy.Dialer p，其中p.ProxyDial 为是一个函数，用来执行forward.Dial
		// [Min] 当调用 p.Dial 的时候，如果p.ProxyDial不为 nil，则会先对代理地址（即cm.addr()）调用p.ProxyDial 连接代理服务器（此就是直接返回 conn，因为 conn 就是通过代理地址获取的）
		// [Min] 然后再调用 p.DialWithConn，来连接目标地址cm.targetAddr
		p, err := proxy.SOCKS5("", cm.addr(), auth, newOneConnDialer(conn))
		if err != nil {
			conn.Close()
			return nil, err
		}
		if _, err := p.Dial("tcp", cm.targetAddr); err != nil {
			conn.Close()
			return nil, err
		}
	case cm.targetScheme == "http":
		pconn.isProxy = true
		// [Min] 设置修改 header 中Proxy-Authorization为 pa 的函数
		if pa := cm.proxyAuth(); pa != "" {
			pconn.mutateHeaderFunc = func(h Header) {
				h.Set("Proxy-Authorization", pa)
			}
		}
	case cm.targetScheme == "https":
		conn := pconn.conn
		hdr := t.ProxyConnectHeader
		if hdr == nil {
			hdr = make(Header)
		}
		connectReq := &Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: cm.targetAddr},
			Host:   cm.targetAddr,
			Header: hdr,
		}
		if pa := cm.proxyAuth(); pa != "" {
			connectReq.Header.Set("Proxy-Authorization", pa)
		}
		connectReq.Write(conn)

		// Read response.
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(conn)
		resp, err := ReadResponse(br, connectReq)
		if err != nil {
			conn.Close()
			return nil, err
		}
		if resp.StatusCode != 200 {
			f := strings.SplitN(resp.Status, " ", 2)
			conn.Close()
			if len(f) < 2 {
				return nil, errors.New("unknown status code")
			}
			return nil, errors.New(f[1])
		}
	}

	if cm.proxyURL != nil && cm.targetScheme == "https" {
		if err := pconn.addTLS(cm.tlsHost(), trace); err != nil {
			return nil, err
		}
	}

	if s := pconn.tlsState; s != nil && s.NegotiatedProtocolIsMutual && s.NegotiatedProtocol != "" {
		if next, ok := t.TLSNextProto[s.NegotiatedProtocol]; ok {
			return &persistConn{alt: next(cm.targetAddr, pconn.conn.(*tls.Conn))}, nil
		}
	}

	pconn.br = bufio.NewReader(pconn)
	pconn.bw = bufio.NewWriter(persistConnWriter{pconn})
	go pconn.readLoop()
	go pconn.writeLoop()
	return pconn, nil
}

// persistConnWriter is the io.Writer written to by pc.bw.
// It accumulates the number of bytes written to the underlying conn,
// so the retry logic can determine whether any bytes made it across
// the wire.
// This is exactly 1 pointer field wide so it can go into an interface
// without allocation.
type persistConnWriter struct {
	pc *persistConn
}

// [Min] 将 p 写入 w.pc.conn
func (w persistConnWriter) Write(p []byte) (n int, err error) {
	n, err = w.pc.conn.Write(p)
	w.pc.nwrite += int64(n)
	return
}

// useProxy reports whether requests to addr should use a proxy,
// according to the NO_PROXY or no_proxy environment variable.
// addr is always a canonicalAddr with a host and port.
// [Min] 根据 NO_PROXY 来判断 addr 是否可以用代理
func useProxy(addr string) bool {
	if len(addr) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	// [Min] localhost, 127.x.x.x/ipv6 loopback 返回 false
	if host == "localhost" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return false
		}
	}

	// [Min] 如果 noProxyEnv 表明所有地址都不要代理，则返回 false
	noProxy := noProxyEnv.Get()
	if noProxy == "*" {
		return false
	}

	addr = strings.ToLower(strings.TrimSpace(addr))
	if hasPort(addr) {
		addr = addr[:strings.LastIndex(addr, ":")]
	}

	// [Min] 如果给定的 addr 在 noProxy 表示的范围内，则返回 false
	for _, p := range strings.Split(noProxy, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) == 0 {
			continue
		}
		if hasPort(p) {
			p = p[:strings.LastIndex(p, ":")]
		}
		if addr == p {
			return false
		}
		if len(p) == 0 {
			// There is no host part, likely the entry is malformed; ignore.
			continue
		}
		if p[0] == '.' && (strings.HasSuffix(addr, p) || addr == p[1:]) {
			// no_proxy ".foo.com" matches "bar.foo.com" or "foo.com"
			return false
		}
		if p[0] != '.' && strings.HasSuffix(addr, p) && addr[len(addr)-len(p)-1] == '.' {
			// no_proxy "foo.com" matches "bar.foo.com"
			return false
		}
	}
	return true
}

// connectMethod is the map key (in its String form) for keeping persistent
// TCP connections alive for subsequent HTTP requests.
//
// A connect method may be of the following types:
//
//	Cache key form                    Description
//	-----------------                 -------------------------
//	|http|foo.com                     http directly to server, no proxy
//	|https|foo.com                    https directly to server, no proxy
//	http://proxy.com|https|foo.com    http to proxy, then CONNECT to foo.com
//	http://proxy.com|http             http to proxy, http to anywhere after that
//	socks5://proxy.com|http|foo.com   socks5 to proxy, then http to foo.com
//	socks5://proxy.com|https|foo.com  socks5 to proxy, then https to foo.com
//	https://proxy.com|https|foo.com   https to proxy, then CONNECT to foo.com
//	https://proxy.com|http            https to proxy, http to anywhere after that
//
type connectMethod struct {
	proxyURL     *url.URL // nil for no proxy, else full proxy URL
	targetScheme string   // "http" or "https"
	// If proxyURL specifies an http or https proxy, and targetScheme is http (not https),
	// then targetAddr is not included in the connect method key, because the socket can
	// be reused for different targetAddr values.
	// [Min] 如果代理地址的 scheme 为 http/https，且目标地址的 scheme 为 http，
	// [Min] 那么targetAddr在connectMethodKey 中会被空取代，这样该 socket 就可以被不同的 targetAddr 共用
	targetAddr string
}

// [Min] 获取该connectMethod 的 key
func (cm *connectMethod) key() connectMethodKey {
	proxyStr := ""
	targetAddr := cm.targetAddr
	if cm.proxyURL != nil {
		proxyStr = cm.proxyURL.String()
		// [Min] 见targetAddr说明
		if (cm.proxyURL.Scheme == "http" || cm.proxyURL.Scheme == "https") && cm.targetScheme == "http" {
			targetAddr = ""
		}
	}
	return connectMethodKey{
		proxy:  proxyStr,
		scheme: cm.targetScheme,
		addr:   targetAddr,
	}
}

// scheme returns the first hop scheme: http, https, or socks5
// [Min] 优先返回代理地址的 scheme，其次目标 scheme
func (cm *connectMethod) scheme() string {
	if cm.proxyURL != nil {
		return cm.proxyURL.Scheme
	}
	return cm.targetScheme
}

// addr returns the first hop "host:port" to which we need to TCP connect.
// [Min] 优先返回代理地址，其次目标地址
func (cm *connectMethod) addr() string {
	if cm.proxyURL != nil {
		return canonicalAddr(cm.proxyURL)
	}
	return cm.targetAddr
}

// tlsHost returns the host name to match against the peer's
// TLS certificate.
// [Min] 返回目标地址去掉 port 后的字符串
func (cm *connectMethod) tlsHost() string {
	h := cm.targetAddr
	if hasPort(h) {
		h = h[:strings.LastIndex(h, ":")]
	}
	return h
}

// connectMethodKey is the map key version of connectMethod, with a
// stringified proxy URL (or the empty string) instead of a pointer to
// a URL.
// [Min] connectMethod map的 key，就是将connectMethod中三要素进行了一定的字符串化
type connectMethodKey struct {
	proxy, scheme, addr string
}

func (k connectMethodKey) String() string {
	// Only used by tests.
	return fmt.Sprintf("%s|%s|%s", k.proxy, k.scheme, k.addr)
}

// persistConn wraps a connection, usually a persistent one
// (but may be used for non-keep-alive requests as well)
type persistConn struct {
	// alt optionally specifies the TLS NextProto RoundTripper.
	// This is used for HTTP/2 today and future protocols later.
	// If it's non-nil, the rest of the fields are unused.
	alt RoundTripper

	t         *Transport
	cacheKey  connectMethodKey
	conn      net.Conn
	tlsState  *tls.ConnectionState
	br        *bufio.Reader       // from conn
	bw        *bufio.Writer       // to conn
	nwrite    int64               // bytes written
	reqch     chan requestAndChan // written by roundTrip; read by readLoop
	writech   chan writeRequest   // written by roundTrip; read by writeLoop
	closech   chan struct{}       // closed when conn closed
	isProxy   bool
	sawEOF    bool  // whether we've seen EOF from conn; owned by readLoop
	readLimit int64 // bytes allowed to be read; owned by readLoop
	// writeErrCh passes the request write error (usually nil)
	// from the writeLoop goroutine to the readLoop which passes
	// it off to the res.Body reader, which then uses it to decide
	// whether or not a connection can be reused. Issue 7569.
	writeErrCh chan error

	writeLoopDone chan struct{} // closed when write loop ends

	// Both guarded by Transport.idleMu:
	// [Min] 上一次变为闲置的时间
	idleAt time.Time // time it last become idle
	// [Min] 由AfterFunc构造，当连接闲置一定时间后，会关闭该连接
	idleTimer *time.Timer // holding an AfterFunc to close it

	mu                   sync.Mutex // guards following fields
	numExpectedResponses int
	closed               error // set non-nil when conn is closed, before closech is closed
	canceledErr          error // set non-nil if conn is canceled
	broken               bool  // an error has happened on this connection; marked broken so it's not reused.
	reused               bool  // whether conn has had successful request/response and is being reused.
	// mutateHeaderFunc is an optional func to modify extra
	// headers on each outbound request before it's written. (the
	// original Request given to RoundTrip is not modified)
	mutateHeaderFunc func(Header)
}

// [Min] 用于再 readLoop 中设置pc.readLimit
func (pc *persistConn) maxHeaderResponseSize() int64 {
	if v := pc.t.MaxResponseHeaderBytes; v != 0 {
		return v
	}
	return 10 << 20 // conservative default; same as http2
}

// [Min] 根据readLimit 读取 conn 中的数据到 p
func (pc *persistConn) Read(p []byte) (n int, err error) {
	if pc.readLimit <= 0 {
		return 0, fmt.Errorf("read limit of %d bytes exhausted", pc.maxHeaderResponseSize())
	}
	if int64(len(p)) > pc.readLimit {
		p = p[:pc.readLimit]
	}
	n, err = pc.conn.Read(p)
	if err == io.EOF {
		pc.sawEOF = true
	}
	pc.readLimit -= int64(n)
	return
}

// isBroken reports whether this connection is in a known broken state.
// [Min] 判断persistConn是否不可用
func (pc *persistConn) isBroken() bool {
	pc.mu.Lock()
	b := pc.closed != nil
	pc.mu.Unlock()
	return b
}

// canceled returns non-nil if the connection was closed due to
// CancelRequest or due to context cancelation.
// [Min] 根据pc.canceledErr，返回是否是被 cancel 了
func (pc *persistConn) canceled() error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	return pc.canceledErr
}

// isReused reports whether this connection is in a known broken state.
// [Min] 根据pc.reused返回是否是重复使用
func (pc *persistConn) isReused() bool {
	pc.mu.Lock()
	r := pc.reused
	pc.mu.Unlock()
	return r
}

func (pc *persistConn) gotIdleConnTrace(idleAt time.Time) (t httptrace.GotConnInfo) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	t.Reused = pc.reused
	t.Conn = pc.conn
	t.WasIdle = true
	if !idleAt.IsZero() {
		t.IdleTime = time.Since(idleAt)
	}
	return
}

// [Min] 设置pc.canceledErr为 err，并以 errRequestCanceled 关闭该连接
func (pc *persistConn) cancelRequest(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.canceledErr = err
	pc.closeLocked(errRequestCanceled)
}

// closeConnIfStillIdle closes the connection if it's still sitting idle.
// This is what's called by the persistConn's idleTimer, and is run in its
// own goroutine.
// [Min] 当连接闲置超时后，会调用此函数来删除该闲置连接
func (pc *persistConn) closeConnIfStillIdle() {
	t := pc.t
	t.idleMu.Lock()
	defer t.idleMu.Unlock()
	if _, ok := t.idleLRU.m[pc]; !ok {
		// Not idle.
		return
	}
	t.removeIdleConnLocked(pc)
	pc.close(errIdleConnTimeout)
}

// mapRoundTripError returns the appropriate error value for
// persistConn.roundTrip.
//
// The provided err is the first error that (*persistConn).roundTrip
// happened to receive from its select statement.
//
// The startBytesWritten value should be the value of pc.nwrite before the roundTrip
// started writing the request.
func (pc *persistConn) mapRoundTripError(req *transportRequest, startBytesWritten int64, err error) error {
	if err == nil {
		return nil
	}

	// If the request was canceled, that's better than network
	// failures that were likely the result of tearing down the
	// connection.
	if cerr := pc.canceled(); cerr != nil {
		return cerr
	}

	// See if an error was set explicitly.
	req.mu.Lock()
	reqErr := req.err
	req.mu.Unlock()
	if reqErr != nil {
		return reqErr
	}

	if err == errServerClosedIdle {
		// Don't decorate
		return err
	}

	if _, ok := err.(transportReadFromServerError); ok {
		// Don't decorate
		return err
	}
	if pc.isBroken() {
		<-pc.writeLoopDone
		if pc.nwrite == startBytesWritten {
			return nothingWrittenError{err}
		}
		return fmt.Errorf("net/http: HTTP/1.x transport connection broken: %v", err)
	}
	return err
}

func (pc *persistConn) readLoop() {
	closeErr := errReadLoopExiting // default value, if not changed below
	// [Min] 结束 loop 的时候关闭连接，并将该连接从闲置连接中删除
	defer func() {
		pc.close(closeErr)
		pc.t.removeIdleConn(pc)
	}()

	// [Min] 用于执行pc.t.tryPutIdleConn(pc)，返回是否将连接置为闲置成功
	tryPutIdleConn := func(trace *httptrace.ClientTrace) bool {
		if err := pc.t.tryPutIdleConn(pc); err != nil {
			closeErr = err
			if trace != nil && trace.PutIdleConn != nil && err != errKeepAlivesDisabled {
				trace.PutIdleConn(err)
			}
			return false
		}
		if trace != nil && trace.PutIdleConn != nil {
			trace.PutIdleConn(nil)
		}
		return true
	}

	// eofc is used to block caller goroutines reading from Response.Body
	// at EOF until this goroutines has (potentially) added the connection
	// back to the idle pool.
	eofc := make(chan struct{})
	defer close(eofc) // unblock reader on errors

	// Read this once, before loop starts. (to avoid races in tests)
	testHookMu.Lock()
	testHookReadLoopBeforeNextRead := testHookReadLoopBeforeNextRead
	testHookMu.Unlock()

	alive := true
	for alive {
		pc.readLimit = pc.maxHeaderResponseSize()
		_, err := pc.br.Peek(1)

		pc.mu.Lock()
		if pc.numExpectedResponses == 0 {
			pc.readLoopPeekFailLocked(err)
			pc.mu.Unlock()
			return
		}
		pc.mu.Unlock()

		// [Min] 获得由 roundTrip 发起的 request
		rc := <-pc.reqch
		trace := httptrace.ContextClientTrace(rc.req.Context())

		var resp *Response
		if err == nil {
			resp, err = pc.readResponse(rc, trace)
		} else {
			err = transportReadFromServerError{err}
			closeErr = err
		}

		if err != nil {
			if pc.readLimit <= 0 {
				err = fmt.Errorf("net/http: server response headers exceeded %d bytes; aborted", pc.maxHeaderResponseSize())
			}

			select {
			case rc.ch <- responseAndError{err: err}:
			case <-rc.callerGone:
				return
			}
			return
		}
		pc.readLimit = maxInt64 // effictively no limit for response bodies

		pc.mu.Lock()
		pc.numExpectedResponses--
		pc.mu.Unlock()

		hasBody := rc.req.Method != "HEAD" && resp.ContentLength != 0

		if resp.Close || rc.req.Close || resp.StatusCode <= 199 {
			// Don't do keep-alive on error if either party requested a close
			// or we get an unexpected informational (1xx) response.
			// StatusCode 100 is already handled above.
			alive = false
		}

		if !hasBody {
			pc.t.setReqCanceler(rc.req, nil)

			// Put the idle conn back into the pool before we send the response
			// so if they process it quickly and make another request, they'll
			// get this same conn. But we use the unbuffered channel 'rc'
			// to guarantee that persistConn.roundTrip got out of its select
			// potentially waiting for this persistConn to close.
			// but after
			alive = alive &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(trace)

			select {
			case rc.ch <- responseAndError{res: resp}:
			case <-rc.callerGone:
				return
			}

			// Now that they've read from the unbuffered channel, they're safely
			// out of the select that also waits on this goroutine to die, so
			// we're allowed to exit now if needed (if alive is false)
			testHookReadLoopBeforeNextRead()
			continue
		}

		waitForBodyRead := make(chan bool, 2)
		body := &bodyEOFSignal{
			body: resp.Body,
			earlyCloseFn: func() error {
				waitForBodyRead <- false
				<-eofc // will be closed by deferred call at the end of the function
				return nil

			},
			fn: func(err error) error {
				isEOF := err == io.EOF
				waitForBodyRead <- isEOF
				if isEOF {
					<-eofc // see comment above eofc declaration
				} else if err != nil {
					if cerr := pc.canceled(); cerr != nil {
						return cerr
					}
				}
				return err
			},
		}

		resp.Body = body
		if rc.addedGzip && strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			resp.Body = &gzipReader{body: body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
			resp.Uncompressed = true
		}

		select {
		case rc.ch <- responseAndError{res: resp}:
		case <-rc.callerGone:
			return
		}

		// Before looping back to the top of this function and peeking on
		// the bufio.Reader, wait for the caller goroutine to finish
		// reading the response body. (or for cancelation or death)
		select {
		case bodyEOF := <-waitForBodyRead:
			pc.t.setReqCanceler(rc.req, nil) // before pc might return to idle pool
			alive = alive &&
				bodyEOF &&
				!pc.sawEOF &&
				pc.wroteRequest() &&
				tryPutIdleConn(trace)
			if bodyEOF {
				eofc <- struct{}{}
			}
		case <-rc.req.Cancel:
			alive = false
			pc.t.CancelRequest(rc.req)
		case <-rc.req.Context().Done():
			alive = false
			pc.t.cancelRequest(rc.req, rc.req.Context().Err())
		case <-pc.closech:
			alive = false
		}

		testHookReadLoopBeforeNextRead()
	}
}

func (pc *persistConn) readLoopPeekFailLocked(peekErr error) {
	if pc.closed != nil {
		return
	}
	if n := pc.br.Buffered(); n > 0 {
		buf, _ := pc.br.Peek(n)
		log.Printf("Unsolicited response received on idle HTTP channel starting with %q; err=%v", buf, peekErr)
	}
	if peekErr == io.EOF {
		// common case.
		pc.closeLocked(errServerClosedIdle)
	} else {
		pc.closeLocked(fmt.Errorf("readLoopPeekFailLocked: %v", peekErr))
	}
}

// readResponse reads an HTTP response (or two, in the case of "Expect:
// 100-continue") from the server. It returns the final non-100 one.
// trace is optional.
// [Min] 读取 Response, rc只是用于设置 Response 中的 Request 字段，主要都是从 pc.br 中获取 Response
func (pc *persistConn) readResponse(rc requestAndChan, trace *httptrace.ClientTrace) (resp *Response, err error) {
	if trace != nil && trace.GotFirstResponseByte != nil {
		if peek, err := pc.br.Peek(1); err == nil && len(peek) == 1 {
			trace.GotFirstResponseByte()
		}
	}
	// [Min] 从 pc.br中读取数据组成 Response
	resp, err = ReadResponse(pc.br, rc.req)
	if err != nil {
		return
	}
	if rc.continueCh != nil {
		if resp.StatusCode == 100 {
			if trace != nil && trace.Got100Continue != nil {
				trace.Got100Continue()
			}
			rc.continueCh <- struct{}{}
		} else {
			close(rc.continueCh)
		}
	}
	if resp.StatusCode == 100 {
		pc.readLimit = pc.maxHeaderResponseSize() // reset the limit
		resp, err = ReadResponse(pc.br, rc.req)
		if err != nil {
			return
		}
	}
	resp.TLS = pc.tlsState
	return
}

// waitForContinue returns the function to block until
// any response, timeout or connection close. After any of them,
// the function returns a bool which indicates if the body should be sent.
// [Min] 返回一个用于判断是否要继续（statuscode 100）的函数
func (pc *persistConn) waitForContinue(continueCh <-chan struct{}) func() bool {
	if continueCh == nil {
		return nil
	}
	return func() bool {
		timer := time.NewTimer(pc.t.ExpectContinueTimeout)
		defer timer.Stop()

		select {
		case _, ok := <-continueCh:
			return ok
		case <-timer.C:
			return true
		case <-pc.closech:
			return false
		}
	}
}

// nothingWrittenError wraps a write errors which ended up writing zero bytes.
type nothingWrittenError struct {
	error
}

func (pc *persistConn) writeLoop() {
	defer close(pc.writeLoopDone)
	for {
		select {
		case wr := <-pc.writech:
			startBytesWritten := pc.nwrite
			err := wr.req.Request.write(pc.bw, pc.isProxy, wr.req.extra, pc.waitForContinue(wr.continueCh))
			if bre, ok := err.(requestBodyReadError); ok {
				err = bre.error
				// Errors reading from the user's
				// Request.Body are high priority.
				// Set it here before sending on the
				// channels below or calling
				// pc.close() which tears town
				// connections and causes other
				// errors.
				wr.req.setError(err)
			}
			if err == nil {
				err = pc.bw.Flush()
			}
			if err != nil {
				wr.req.Request.closeBody()
				if pc.nwrite == startBytesWritten {
					err = nothingWrittenError{err}
				}
			}
			pc.writeErrCh <- err // to the body reader, which might recycle us
			wr.ch <- err         // to the roundTrip function
			if err != nil {
				pc.close(err)
				return
			}
		case <-pc.closech:
			return
		}
	}
}

// wroteRequest is a check before recycling a connection that the previous write
// (from writeLoop above) happened and was successful.
func (pc *persistConn) wroteRequest() bool {
	select {
	case err := <-pc.writeErrCh:
		// Common case: the write happened well before the response, so
		// avoid creating a timer.
		return err == nil
	default:
		// Rare case: the request was written in writeLoop above but
		// before it could send to pc.writeErrCh, the reader read it
		// all, processed it, and called us here. In this case, give the
		// write goroutine a bit of time to finish its send.
		//
		// Less rare case: We also get here in the legitimate case of
		// Issue 7569, where the writer is still writing (or stalled),
		// but the server has already replied. In this case, we don't
		// want to wait too long, and we want to return false so this
		// connection isn't re-used.
		select {
		case err := <-pc.writeErrCh:
			return err == nil
		case <-time.After(50 * time.Millisecond):
			return false
		}
	}
}

// responseAndError is how the goroutine reading from an HTTP/1 server
// communicates with the goroutine doing the RoundTrip.
type responseAndError struct {
	res *Response // else use this response (see res method)
	err error
}

type requestAndChan struct {
	req *Request
	ch  chan responseAndError // unbuffered; always send in select on callerGone

	// whether the Transport (as opposed to the user client code)
	// added the Accept-Encoding gzip header. If the Transport
	// set it, only then do we transparently decode the gzip.
	addedGzip bool

	// Optional blocking chan for Expect: 100-continue (for send).
	// If the request has an "Expect: 100-continue" header and
	// the server responds 100 Continue, readLoop send a value
	// to writeLoop via this chan.
	continueCh chan<- struct{}

	callerGone <-chan struct{} // closed when roundTrip caller has returned
}

// A writeRequest is sent by the readLoop's goroutine to the
// writeLoop's goroutine to write a request while the read loop
// concurrently waits on both the write response and the server's
// reply.
type writeRequest struct {
	req *transportRequest
	ch  chan<- error

	// Optional blocking chan for Expect: 100-continue (for receive).
	// If not nil, writeLoop blocks sending request body until
	// it receives from this chan.
	continueCh <-chan struct{}
}

type httpError struct {
	err     string
	timeout bool
}

func (e *httpError) Error() string   { return e.err }
func (e *httpError) Timeout() bool   { return e.timeout }
func (e *httpError) Temporary() bool { return true }

var errTimeout error = &httpError{err: "net/http: timeout awaiting response headers", timeout: true}
var errRequestCanceled = errors.New("net/http: request canceled")
var errRequestCanceledConn = errors.New("net/http: request canceled while waiting for connection") // TODO: unify?

func nop() {}

// testHooks. Always non-nil.
var (
	testHookEnterRoundTrip   = nop
	testHookWaitResLoop      = nop
	testHookRoundTripRetried = nop
	testHookPrePendingDial   = nop
	testHookPostPendingDial  = nop

	testHookMu                     sync.Locker = fakeLocker{} // guards following
	testHookReadLoopBeforeNextRead             = nop
)

// [Min] 发起 request
func (pc *persistConn) roundTrip(req *transportRequest) (resp *Response, err error) {
	testHookEnterRoundTrip()
	// [Min] 如果无法为 request 注册 canceler，则说明该 request 是被 cancel 掉的，直接返回 nil
	if !pc.t.replaceReqCanceler(req.Request, pc.cancelRequest) {
		pc.t.putOrCloseIdleConn(pc)
		return nil, errRequestCanceled
	}
	// [Min] 增加期待返回的数量，并设置修改 header 的函数
	pc.mu.Lock()
	pc.numExpectedResponses++
	headerFn := pc.mutateHeaderFunc
	pc.mu.Unlock()

	// [Min] 修改 extra header
	if headerFn != nil {
		headerFn(req.extraHeaders())
	}

	// Ask for a compressed version if the caller didn't set their
	// own value for Accept-Encoding. We only attempt to
	// uncompress the gzip stream if we were the layer that
	// requested it.
	requestedGzip := false
	// [Min] 按照 header 相关的属性，设置 extra header 的 Accept-Encoding 为 gzip
	if !pc.t.DisableCompression &&
		req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		req.Method != "HEAD" {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: http://www.gzip.org/zlib/zlib_faq.html#faq38
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   http://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		requestedGzip = true
		req.extraHeaders().Set("Accept-Encoding", "gzip")
	}

	var continueCh chan struct{}
	if req.ProtoAtLeast(1, 1) && req.Body != nil && req.expectsContinue() {
		continueCh = make(chan struct{}, 1)
	}

	if pc.t.DisableKeepAlives {
		req.extraHeaders().Set("Connection", "close")
	}

	gone := make(chan struct{})
	defer close(gone)

	defer func() {
		if err != nil {
			pc.t.setReqCanceler(req.Request, nil)
		}
	}()

	const debugRoundTrip = false

	// Write the request concurrently with waiting for a response,
	// in case the server decides to reply before reading our full
	// request body.
	startBytesWritten := pc.nwrite
	writeErrCh := make(chan error, 1)
	pc.writech <- writeRequest{req, writeErrCh, continueCh}

	resc := make(chan responseAndError)
	pc.reqch <- requestAndChan{
		req:        req.Request,
		ch:         resc,
		addedGzip:  requestedGzip,
		continueCh: continueCh,
		callerGone: gone,
	}

	var respHeaderTimer <-chan time.Time
	cancelChan := req.Request.Cancel
	ctxDoneChan := req.Context().Done()
	for {
		testHookWaitResLoop()
		select {
		case err := <-writeErrCh:
			if debugRoundTrip {
				req.logf("writeErrCh resv: %T/%#v", err, err)
			}
			if err != nil {
				pc.close(fmt.Errorf("write error: %v", err))
				return nil, pc.mapRoundTripError(req, startBytesWritten, err)
			}
			// [Min] 如果 err 为 nil，且ResponseHeaderTimeout > 0， 那么就设置计时器respHeaderTimer
			if d := pc.t.ResponseHeaderTimeout; d > 0 {
				if debugRoundTrip {
					req.logf("starting timer for %v", d)
				}
				timer := time.NewTimer(d)
				defer timer.Stop() // prevent leaks
				respHeaderTimer = timer.C
			}
		case <-pc.closech:
			// [Min] 连接已关闭
			if debugRoundTrip {
				req.logf("closech recv: %T %#v", pc.closed, pc.closed)
			}
			return nil, pc.mapRoundTripError(req, startBytesWritten, pc.closed)
		case <-respHeaderTimer:
			// [Min] respHeaderTimer超时，关闭连接
			if debugRoundTrip {
				req.logf("timeout waiting for response headers.")
			}
			pc.close(errTimeout)
			return nil, errTimeout
		case re := <-resc:
			// [Min] 至少有一个不为 nil
			if (re.res == nil) == (re.err == nil) {
				panic(fmt.Sprintf("internal error: exactly one of res or err should be set; nil=%v", re.res == nil))
			}
			if debugRoundTrip {
				req.logf("resc recv: %p, %T/%#v", re.res, re.err, re.err)
			}
			if re.err != nil {
				return nil, pc.mapRoundTripError(req, startBytesWritten, re.err)
			}
			// [Min] err 为 nil，正常返回 response
			return re.res, nil
		case <-cancelChan:
			// [Min] 通过 request.Cancel来取消 request
			pc.t.CancelRequest(req.Request)
			cancelChan = nil
		case <-ctxDoneChan:
			// [Min] 通过 context 来取消 request
			pc.t.cancelRequest(req.Request, req.Context().Err())
			cancelChan = nil
			ctxDoneChan = nil
		}
	}
}

// tLogKey is a context WithValue key for test debugging contexts containing
// a t.Logf func. See export_test.go's Request.WithT method.
type tLogKey struct{}

func (tr *transportRequest) logf(format string, args ...interface{}) {
	if logf, ok := tr.Request.Context().Value(tLogKey{}).(func(string, ...interface{})); ok {
		logf(time.Now().Format(time.RFC3339Nano)+": "+format, args...)
	}
}

// markReused marks this connection as having been successfully used for a
// request and response.
// [Min] 标记为 reused
func (pc *persistConn) markReused() {
	pc.mu.Lock()
	pc.reused = true
	pc.mu.Unlock()
}

// close closes the underlying TCP connection and closes
// the pc.closech channel.
//
// The provided err is only for testing and debugging; in normal
// circumstances it should never be seen by users.
// [Min] 以相应的 err 关闭该连接并关闭 closech
func (pc *persistConn) close(err error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.closeLocked(err)
}

// [Min] 在锁定的状态下，关闭连接
func (pc *persistConn) closeLocked(err error) {
	if err == nil {
		panic("nil error")
	}
	pc.broken = true
	if pc.closed == nil {
		pc.closed = err
		if pc.alt != nil {
			// Do nothing; can only get here via getConn's
			// handlePendingDial's putOrCloseIdleConn when
			// it turns out the abandoned connection in
			// flight ended up negotiating an alternate
			// protocol. We don't use the connection
			// freelist for http2. That's done by the
			// alternate protocol's RoundTripper.
		} else {
			pc.conn.Close()
			close(pc.closech)
		}
	}
	pc.mutateHeaderFunc = nil
}

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

// canonicalAddr returns url.Host but always with a ":port" suffix
// [Min] 返回 host:port 的字符串
func canonicalAddr(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme] // [Min] 如果没有 url 中咩有 port，则设置默认 port
	}
	return net.JoinHostPort(addr, port)
}

// bodyEOFSignal is used by the HTTP/1 transport when reading response
// bodies to make sure we see the end of a response body before
// proceeding and reading on the connection again.
//
// It wraps a ReadCloser but runs fn (if non-nil) at most
// once, right before its final (error-producing) Read or Close call
// returns. fn should return the new error to return from Read or Close.
//
// If earlyCloseFn is non-nil and Close is called before io.EOF is
// seen, earlyCloseFn is called instead of fn, and its return value is
// the return value from Close.
type bodyEOFSignal struct {
	body         io.ReadCloser
	mu           sync.Mutex        // guards following 4 fields
	closed       bool              // whether Close has been called
	rerr         error             // sticky Read error
	fn           func(error) error // err will be nil on Read io.EOF
	earlyCloseFn func() error      // optional alt Close func used if io.EOF not seen
}

var errReadOnClosedResBody = errors.New("http: read on closed response body")

func (es *bodyEOFSignal) Read(p []byte) (n int, err error) {
	es.mu.Lock()
	closed, rerr := es.closed, es.rerr
	es.mu.Unlock()
	if closed {
		return 0, errReadOnClosedResBody
	}
	if rerr != nil {
		return 0, rerr
	}

	n, err = es.body.Read(p)
	if err != nil {
		es.mu.Lock()
		defer es.mu.Unlock()
		if es.rerr == nil {
			es.rerr = err
		}
		err = es.condfn(err)
	}
	return
}

func (es *bodyEOFSignal) Close() error {
	es.mu.Lock()
	defer es.mu.Unlock()
	if es.closed {
		return nil
	}
	es.closed = true
	if es.earlyCloseFn != nil && es.rerr != io.EOF {
		return es.earlyCloseFn()
	}
	err := es.body.Close()
	return es.condfn(err)
}

// caller must hold es.mu.
func (es *bodyEOFSignal) condfn(err error) error {
	if es.fn == nil {
		return err
	}
	err = es.fn(err)
	es.fn = nil
	return err
}

// gzipReader wraps a response body so it can lazily
// call gzip.NewReader on the first call to Read
type gzipReader struct {
	body *bodyEOFSignal // underlying HTTP/1 response body framing
	zr   *gzip.Reader   // lazily-initialized gzip reader
	zerr error          // any error from gzip.NewReader; sticky
}

func (gz *gzipReader) Read(p []byte) (n int, err error) {
	if gz.zr == nil {
		if gz.zerr == nil {
			gz.zr, gz.zerr = gzip.NewReader(gz.body)
		}
		if gz.zerr != nil {
			return 0, gz.zerr
		}
	}

	gz.body.mu.Lock()
	if gz.body.closed {
		err = errReadOnClosedResBody
	}
	gz.body.mu.Unlock()

	if err != nil {
		return 0, err
	}
	return gz.zr.Read(p)
}

func (gz *gzipReader) Close() error {
	return gz.body.Close()
}

type readerAndCloser struct {
	io.Reader
	io.Closer
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

// fakeLocker is a sync.Locker which does nothing. It's used to guard
// test-only fields when not under test, to avoid runtime atomic
// overhead.
type fakeLocker struct{}

func (fakeLocker) Lock()   {}
func (fakeLocker) Unlock() {}

// clneTLSConfig returns a shallow clone of cfg, or a new zero tls.Config if
// cfg is nil. This is safe to call even if cfg is in active use by a TLS
// client or server.
func cloneTLSConfig(cfg *tls.Config) *tls.Config {
	if cfg == nil {
		return &tls.Config{}
	}
	return cfg.Clone()
}

type connLRU struct {
	ll *list.List // list.Element.Value type is of *persistConn
	m  map[*persistConn]*list.Element
}

// add adds pc to the head of the linked list.
func (cl *connLRU) add(pc *persistConn) {
	if cl.ll == nil {
		cl.ll = list.New()
		cl.m = make(map[*persistConn]*list.Element)
	}
	ele := cl.ll.PushFront(pc)
	if _, ok := cl.m[pc]; ok {
		panic("persistConn was already in LRU")
	}
	cl.m[pc] = ele
}

// [Min] 从connLRU中删除最老的连接，并返回该连接
func (cl *connLRU) removeOldest() *persistConn {
	ele := cl.ll.Back()
	pc := ele.Value.(*persistConn)
	cl.ll.Remove(ele)
	delete(cl.m, pc)
	return pc
}

// remove removes pc from cl.
// [Min] 从connLRU中删除persistConn
func (cl *connLRU) remove(pc *persistConn) {
	if ele, ok := cl.m[pc]; ok {
		cl.ll.Remove(ele)
		delete(cl.m, pc)
	}
}

// len returns the number of items in the cache.
// [Min] connLRU中的连接数
func (cl *connLRU) len() int {
	return len(cl.m)
}

// validPort reports whether p (without the colon) is a valid port in
// a URL, per RFC 3986 Section 3.2.3, which says the port may be
// empty, or only contain digits.
// [Min] 判断 port 是否有效，p 中是否都是数字
func validPort(p string) bool {
	for _, r := range []byte(p) {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
