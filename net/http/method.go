// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

// Common HTTP methods.
//
// Unless otherwise noted, these are defined in RFC 7231 section 4.3.
// [Min] https://zh.wikipedia.org/wiki/%E8%B6%85%E6%96%87%E6%9C%AC%E4%BC%A0%E8%BE%93%E5%8D%8F%E8%AE%AE
const (
	// [Min] 向指定的资源发出“显示”请求。使用GET方法应该只用在读取数据，而不应当被用于产生“副作用”的操作中，例如在Web Application中。其中一个原因是GET可能会被网络蜘蛛等随意访问。
	MethodGet = "GET"
	// [Min] 与GET方法一样，都是向服务器发出指定资源的请求。只不过服务器将不传回资源的本文部分。它的好处在于，使用这个方法可以在不必传输全部内容的情况下，就可以获取其中“关于该资源的信息”（元信息或称元数据）。
	MethodHead = "HEAD"
	// [Min] 向指定资源提交数据，请求服务器进行处理（例如提交表单或者上传文件）。数据被包含在请求本文中。这个请求可能会创建新的资源或修改现有资源，或二者皆有。
	MethodPost = "POST"
	// [Min] 向指定资源位置上传其最新内容。
	MethodPut = "PUT"
	// [Min] 用于将局部修改应用到资源。
	MethodPatch = "PATCH" // RFC 5789
	// [Min] 请求服务器删除Request-URI所标识的资源。
	MethodDelete = "DELETE"
	// [Min] HTTP/1.1协议中预留给能够将连接改为管道方式的代理服务器。通常用于SSL加密服务器的链接（经由非加密的HTTP代理服务器）。
	MethodConnect = "CONNECT"
	// [Min] 这个方法可使服务器传回该资源所支持的所有HTTP请求方法。用'*'来代替资源名称，向Web服务器发送OPTIONS请求，可以测试服务器功能是否正常运作。
	MethodOptions = "OPTIONS"
	// [Min] 回显服务器收到的请求，主要用于测试或诊断。
	MethodTrace = "TRACE"
)
