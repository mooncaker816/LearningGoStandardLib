// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"internal/nettrace"
	"internal/poll"
	"time"
)

// A Dialer contains options for connecting to an address.
//
// The zero value for each field is equivalent to dialing
// without that option. Dialing with the zero value of Dialer
// is therefore equivalent to just calling the Dial function.
type Dialer struct {
	// Timeout is the maximum amount of time a dial will wait for
	// a connect to complete. If Deadline is also set, it may fail
	// earlier.
	//
	// The default is no timeout.
	//
	// When using TCP and dialing a host name with multiple IP
	// addresses, the timeout may be divided between them.
	//
	// With or without a timeout, the operating system may impose
	// its own earlier timeout. For instance, TCP timeouts are
	// often around 3 minutes.
	Timeout time.Duration

	// Deadline is the absolute point in time after which dials
	// will fail. If Timeout is set, it may fail earlier.
	// Zero means no deadline, or dependent on the operating system
	// as with the Timeout option.
	Deadline time.Time

	// LocalAddr is the local address to use when dialing an
	// address. The address must be of a compatible type for the
	// network being dialed.
	// If nil, a local address is automatically chosen.
	LocalAddr Addr

	// DualStack enables RFC 6555-compliant "Happy Eyeballs"
	// dialing when the network is "tcp" and the host in the
	// address parameter resolves to both IPv4 and IPv6 addresses.
	// This allows a client to tolerate networks where one address
	// family is silently broken.
	DualStack bool

	// FallbackDelay specifies the length of time to wait before
	// spawning a fallback connection, when DualStack is enabled.
	// If zero, a default delay of 300ms is used.
	FallbackDelay time.Duration

	// KeepAlive specifies the keep-alive period for an active
	// network connection.
	// If zero, keep-alives are not enabled. Network protocols
	// that do not support keep-alives ignore this field.
	KeepAlive time.Duration

	// Resolver optionally specifies an alternate resolver to use.
	Resolver *Resolver

	// Cancel is an optional channel whose closure indicates that
	// the dial should be canceled. Not all types of dials support
	// cancelation.
	//
	// Deprecated: Use DialContext instead.
	Cancel <-chan struct{}
}

// [Min] 返回两个时间中较早的那一个，如果其中一个是零时间，则返回另一个
func minNonzeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

// deadline returns the earliest of:
//   - now+Timeout
//   - d.Deadline
//   - the context's deadline
// Or zero, if none of Timeout, Deadline, or context's deadline is set.
// [Min] 返回该 Dialer 的 deadline，考虑了 Timeout，Deadline，和 context deadline，取最早的一个
func (d *Dialer) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	if d.Timeout != 0 { // including negative, for historical reasons
		earliest = now.Add(d.Timeout)
	}
	if d, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, d)
	}
	return minNonzeroTime(earliest, d.Deadline)
}

// [Min] 返回Resolver，如果为 nil，则返回DefaultResolver，零值
func (d *Dialer) resolver() *Resolver {
	if d.Resolver != nil {
		return d.Resolver
	}
	return DefaultResolver
}

// partialDeadline returns the deadline to use for a single address,
// when multiple addresses are pending.
// [Min] 对于多个地址未处理地址的情况下，单个地址的 deadline
// [Min] 首先计算出离最终 deadline 的总剩余时间，再尝试将这段时间平均分配给每个地址，
// [Min] 如果这个时间太短（< 2s），则取2s 和总剩余时间的最小值给当前处理地址，计算出 deadline 返回
func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, poll.ErrTimeout
	}
	// Tentatively allocate equal time to each remaining address.
	timeout := timeRemaining / time.Duration(addrsRemaining)
	// If the time per address is too short, steal from the end of the list.
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		if timeRemaining < saneMinimum {
			timeout = timeRemaining
		} else {
			timeout = saneMinimum
		}
	}
	return now.Add(timeout), nil
}

// [Min] 如果定义了FallbackDelay > 0，直接返回，否则以300 ms 返回
func (d *Dialer) fallbackDelay() time.Duration {
	if d.FallbackDelay > 0 {
		return d.FallbackDelay
	} else {
		return 300 * time.Millisecond
	}
}

// [Min] 解析 network
func parseNetwork(ctx context.Context, network string, needsProto bool) (afnet string, proto int, err error) {
	// [Min] ':' 后跟 proto
	i := last(network, ':')
	/* [Min]
	如果没有':'，说明没有 proto，对需要 proto 的报错，network 可选值为
	case "tcp", "tcp4", "tcp6":
	case "udp", "udp4", "udp6":
	case "ip", "ip4", "ip6":
	*/
	if i < 0 { // no colon
		switch network {
		case "tcp", "tcp4", "tcp6":
		case "udp", "udp4", "udp6":
		case "ip", "ip4", "ip6":
			if needsProto {
				return "", 0, UnknownNetworkError(network)
			}
		case "unix", "unixgram", "unixpacket":
		default:
			return "", 0, UnknownNetworkError(network)
		}
		return network, 0, nil
	}
	/* [Min]
	有 proto，只能是"ip", "ip4", "ip6"，
	再解析 proto 字符串（全数字），如果解析不成功，查询本地协议/etc/protocals，还没有就报错
	*/
	afnet = network[:i]
	switch afnet {
	case "ip", "ip4", "ip6":
		protostr := network[i+1:]
		proto, i, ok := dtoi(protostr)
		if !ok || i != len(protostr) {
			proto, err = lookupProtocol(ctx, protostr)
			if err != nil {
				return "", 0, err
			}
		}
		return afnet, proto, nil
	}
	return "", 0, UnknownNetworkError(network)
}

// resolveAddrList resolves addr using hint and returns a list of
// addresses. The result contains at least one address when error is
// nil.
// [Min] 根据 hint Addr，返回 addrList，hint 相当于一个参照地址，一般为本地地址，而 addr 为目标地址
func (r *Resolver) resolveAddrList(ctx context.Context, op, network, addr string, hint Addr) (addrList, error) {
	// [Min] 解析 network
	afnet, _, err := parseNetwork(ctx, network, true)
	if err != nil {
		return nil, err
	}
	// [Min] 对应 dial 操作，addr 不能为空
	if op == "dial" && addr == "" {
		return nil, errMissingAddress
	}
	switch afnet {
	case "unix", "unixgram", "unixpacket":
		// [Min] 返回UnixAddr
		addr, err := ResolveUnixAddr(afnet, addr)
		if err != nil {
			return nil, err
		}
		if op == "dial" && hint != nil && addr.Network() != hint.Network() {
			return nil, &AddrError{Err: "mismatched local address type", Addr: hint.String()}
		}
		return addrList{addr}, nil
	}
	addrs, err := r.internetAddrList(ctx, afnet, addr)
	// [Min] 如果没有 hint 或者不是 dial，或者报错了，直接返回
	if err != nil || op != "dial" || hint == nil {
		return addrs, err
	}
	var (
		tcp      *TCPAddr
		udp      *UDPAddr
		ip       *IPAddr
		wildcard bool
	)
	switch hint := hint.(type) {
	case *TCPAddr:
		tcp = hint
		wildcard = tcp.isWildcard()
	case *UDPAddr:
		udp = hint
		wildcard = udp.isWildcard()
	case *IPAddr:
		ip = hint
		wildcard = ip.isWildcard()
	}
	naddrs := addrs[:0]
	// [Min] 将 addrList 中的每个 addr 与 hint 做比较
	// [Min] 首先必须 network 相同，否则报错
	// [Min] 其次，当addr 和 hint 包含的 IP 都不是全0 ip，但却不是同类型 ip 的时候，忽略该地址
	for _, addr := range addrs {
		if addr.Network() != hint.Network() {
			return nil, &AddrError{Err: "mismatched local address type", Addr: hint.String()}
		}
		switch addr := addr.(type) {
		case *TCPAddr:
			if !wildcard && !addr.isWildcard() && !addr.IP.matchAddrFamily(tcp.IP) {
				continue
			}
			naddrs = append(naddrs, addr)
		case *UDPAddr:
			if !wildcard && !addr.isWildcard() && !addr.IP.matchAddrFamily(udp.IP) {
				continue
			}
			naddrs = append(naddrs, addr)
		case *IPAddr:
			if !wildcard && !addr.isWildcard() && !addr.IP.matchAddrFamily(ip.IP) {
				continue
			}
			naddrs = append(naddrs, addr)
		}
	}
	if len(naddrs) == 0 {
		return nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: hint.String()}
	}
	return naddrs, nil
}

// Dial connects to the address on the named network.
//
// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only),
// "udp", "udp4" (IPv4-only), "udp6" (IPv6-only), "ip", "ip4"
// (IPv4-only), "ip6" (IPv6-only), "unix", "unixgram" and
// "unixpacket".
//
// For TCP and UDP networks, the address has the form "host:port".
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses.
// The port must be a literal port number or a service name.
// If the host is a literal IPv6 address it must be enclosed in square
// brackets, as in "[2001:db8::1]:80" or "[fe80::1%zone]:80".
// The zone specifies the scope of the literal IPv6 address as defined
// in RFC 4007.
// The functions JoinHostPort and SplitHostPort manipulate a pair of
// host and port in this form.
// When using TCP, and the host resolves to multiple IP addresses,
// Dial will try each IP address in order until one succeeds.
//
// Examples:
//	Dial("tcp", "golang.org:http")
//	Dial("tcp", "192.0.2.1:http")
//	Dial("tcp", "198.51.100.1:80")
//	Dial("udp", "[2001:db8::1]:domain")
//	Dial("udp", "[fe80::1%lo0]:53")
//	Dial("tcp", ":80")
//
// For IP networks, the network must be "ip", "ip4" or "ip6" followed
// by a colon and a literal protocol number or a protocol name, and
// the address has the form "host". The host must be a literal IP
// address or a literal IPv6 address with zone.
// It depends on each operating system how the operating system
// behaves with a non-well known protocol number such as "0" or "255".
//
// Examples:
//	Dial("ip4:1", "192.0.2.1")
//	Dial("ip6:ipv6-icmp", "2001:db8::1")
//	Dial("ip6:58", "fe80::1%lo0")
//
// For TCP, UDP and IP networks, if the host is empty or a literal
// unspecified IP address, as in ":80", "0.0.0.0:80" or "[::]:80" for
// TCP and UDP, "", "0.0.0.0" or "::" for IP, the local system is
// assumed.
//
// For Unix networks, the address must be a file system path.
// [Min] 以零值 Dialer 进行拨号，返回 Conn
func Dial(network, address string) (Conn, error) {
	var d Dialer
	return d.Dial(network, address)
}

// DialTimeout acts like Dial but takes a timeout.
//
// The timeout includes name resolution, if required.
// When using TCP, and the host in the address parameter resolves to
// multiple IP addresses, the timeout is spread over each consecutive
// dial, such that each is given an appropriate fraction of the time
// to connect.
//
// See func Dial for a description of the network and address
// parameters.
// [Min] 和 Dial 相似，只不过设置了 Dialer 的 Timeout
func DialTimeout(network, address string, timeout time.Duration) (Conn, error) {
	d := Dialer{Timeout: timeout}
	return d.Dial(network, address)
}

// dialParam contains a Dial's parameters and configuration.
// [Min] 包含了 Dialer 本身的信息和 Dial 动作必不可少的 network 和 address
type dialParam struct {
	Dialer
	network, address string
}

// Dial connects to the address on the named network.
//
// See func Dial for a description of the network and address
// parameters.
// [Min] 调用DialContext 发起 Dial， 此时会创建一个空的 Context
func (d *Dialer) Dial(network, address string) (Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using
// the provided context.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// When using TCP, and the host in the address parameter resolves to multiple
// network addresses, any dial timeout (from d.Timeout or ctx) is spread
// over each consecutive dial, such that each is given an appropriate
// fraction of the time to connect.
// For example, if a host has 4 IP addresses and the timeout is 1 minute,
// the connect to each single address will be given 15 seconds to complete
// before trying the next one.
//
// See func Dial for a description of the network and address
// parameters.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (Conn, error) {
	if ctx == nil {
		panic("nil context")
	}
	// [Min] 获取 deadline，综合考虑了 d.Timeout,d.Deadline 和 ctx.Deadline()，取最早的一个值
	deadline := d.deadline(ctx, time.Now())
	if !deadline.IsZero() {
		// [Min] 根据此 deadline，同步 context 中的 deadline
		if d, ok := ctx.Deadline(); !ok || deadline.Before(d) {
			subCtx, cancel := context.WithDeadline(ctx, deadline)
			defer cancel()
			ctx = subCtx
		}
	}
	// [Min] Dialer 本身的 Cancel 通道不为 nil，则继承上述 ctx，当 Cancel 通道收到消息后，执行 cancel()，使得后续继承此 ctx
	if oldCancel := d.Cancel; oldCancel != nil {
		subCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		go func() {
			select {
			case <-oldCancel:
				cancel() // subCtx 发起 cancel，并向下传播
			case <-subCtx.Done(): //父亲 ctx 发起了 cancel
			}
		}()
		ctx = subCtx // [Min] 后续在 subCtx 的基础上继续继承下去
	}

	// Shadow the nettrace (if any) during resolve so Connect events don't fire for DNS lookups.
	// [Min] 复制一个当前状态下的 ctx，用于取消后续对ConnectStart，ConnectDone调用
	resolveCtx := ctx
	if trace, _ := ctx.Value(nettrace.TraceKey{}).(*nettrace.Trace); trace != nil {
		shadow := *trace
		shadow.ConnectStart = nil
		shadow.ConnectDone = nil
		resolveCtx = context.WithValue(resolveCtx, nettrace.TraceKey{}, &shadow)
	}

	// [Min] 获得 addrList
	addrs, err := d.resolver().resolveAddrList(resolveCtx, "dial", network, address, d.LocalAddr)
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: nil, Addr: nil, Err: err}
	}

	dp := &dialParam{
		Dialer:  *d,
		network: network,
		address: address,
	}

	var primaries, fallbacks addrList
	if d.DualStack && network == "tcp" {
		// [Min] 将 addrs 分为两类，primaries 为所有与第一个地址对应 isIPv4 同真同假的地址，剩余的为 fallbacks
		primaries, fallbacks = addrs.partition(isIPv4)
	} else {
		primaries = addrs
	}

	var c Conn
	// [Min] 如果 fallbacks 不为空，几乎同时对 primaries 和 fallbacks 两组进行处理，但是组内还是顺序进行 dial
	// [Min] 其中 fallbacks 组会根据 d.FallbackDealy 延迟处理
	if len(fallbacks) > 0 {
		c, err = dialParallel(ctx, dp, primaries, fallbacks)
	} else {
		// [Min] 顺序处理每个地址
		c, err = dialSerial(ctx, dp, primaries)
	}
	if err != nil {
		return nil, err
	}

	if tc, ok := c.(*TCPConn); ok && d.KeepAlive > 0 {
		setKeepAlive(tc.fd, true)
		setKeepAlivePeriod(tc.fd, d.KeepAlive)
		testHookSetKeepAlive()
	}
	return c, nil
}

// dialParallel races two copies of dialSerial, giving the first a
// head start. It returns the first established connection and
// closes the others. Otherwise it returns an error from the first
// primary address.
// [Min] 两组地址几乎同时开始挨个尝试拨号，返回第一个成功拨号的连接
// [Min] fallbacks 组会根据fallbackDelay() 延迟开始处理
func dialParallel(ctx context.Context, dp *dialParam, primaries, fallbacks addrList) (Conn, error) {
	if len(fallbacks) == 0 {
		return dialSerial(ctx, dp, primaries)
	}

	// [Min] 当一个组先得到一个 Conn， returned 用于通知处理另一个较慢的组的 goroutine 结束处理
	returned := make(chan struct{})
	defer close(returned)

	type dialResult struct {
		Conn
		error
		primary bool
		done    bool
	}
	// [Min] 用于接收最快的那个 Conn 的通道，一旦接收到了成功的 Conn，则直接返回
	results := make(chan dialResult) // unbuffered

	// [Min] 用于竞赛的逻辑，primary 用来区别两组
	startRacer := func(ctx context.Context, primary bool) {
		// [Min] 获取对应组别的地址，存入 ras
		ras := primaries
		if !primary {
			ras = fallbacks
		}
		// [Min] 组内按顺序拨号，一旦返回，就表示对该组已经处理完成，要么是第一个成功的Conn，要么是第一个错误
		c, err := dialSerial(ctx, dp, ras)
		select {
		// [Min] 及时将拨号结果返回给 results 通道
		case results <- dialResult{Conn: c, error: err, primary: primary, done: true}:
		// [Min] fallbacks 组快，结束此 goroutine，
		// [Min] 但也有可能 primaries 组也已经有成功的 Conn，只是还没来得及返回，
		// [Min] 这种情况就要关闭这个 Conn
		case <-returned:
			if c != nil {
				c.Close()
			}
		}
	}

	var primary, fallback dialResult

	// Start the main racer.
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	// [Min] 直接开始 primaries 组处理
	go startRacer(primaryCtx, true)

	// Start the timer for the fallback racer.
	// [Min] 开启 fallbacks 组 dealy timer
	fallbackTimer := time.NewTimer(dp.fallbackDelay())
	defer fallbackTimer.Stop()

	for {
		select {
		case <-fallbackTimer.C:
			// [Min] fallbacks 组开始处理
			fallbackCtx, fallbackCancel := context.WithCancel(ctx)
			defer fallbackCancel()
			go startRacer(fallbackCtx, false)

		case res := <-results:
			// [Min] 收到较快组的结果，如果没有 error，直接返回此 Conn，
			// [Min] returned 也会被关闭用于通知另一组结束处理
			if res.error == nil {
				return res.Conn, nil
			}
			// [Min] 如果有错，根据组暂存此结果
			if res.primary {
				primary = res
			} else {
				fallback = res
			}
			// [Min] 当两个组都完成了处理，且之前都没有返回成功的 Conn，优先返回 primary 组的错误
			if primary.done && fallback.done {
				return nil, primary.error
			}
			// [Min] 如果 primary 组已经处理完了，且没有成功的 Conn 返回，
			// [Min] 而此时 fallbacks 组还没开始处理（还在 delay），将此 delay 取消，立即开始处理 fallbacks 组
			if res.primary && fallbackTimer.Stop() {
				// [Min] timer.Stop()返回真，说明 timer 还没到时间
				// If we were able to stop the timer, that means it
				// was running (hadn't yet started the fallback), but
				// we just got an error on the primary path, so start
				// the fallback immediately (in 0 nanoseconds).
				fallbackTimer.Reset(0)
			}
		}
	}
}

// dialSerial connects to a list of addresses in sequence, returning
// either the first successful connection, or the first error.
// [Min] 对一组地址按顺序进行拨号，返回第一个成功拨号的 Conn，或者第一个碰到的 error
func dialSerial(ctx context.Context, dp *dialParam, ras addrList) (Conn, error) {
	var firstErr error // The error from the first address is most relevant.

	for i, ra := range ras {
		select {
		// [Min] 超时返回
		case <-ctx.Done():
			return nil, &OpError{Op: "dial", Net: dp.network, Source: dp.LocalAddr, Addr: ra, Err: mapErr(ctx.Err())}
		default:
		}

		deadline, _ := ctx.Deadline()
		// [Min] 获取单地址的处理 deadline
		partialDeadline, err := partialDeadline(time.Now(), deadline, len(ras)-i)
		if err != nil {
			// Ran out of time.
			if firstErr == nil {
				firstErr = &OpError{Op: "dial", Net: dp.network, Source: dp.LocalAddr, Addr: ra, Err: err}
			}
			break
		}
		// [Min] 单地址 ctx
		dialCtx := ctx
		if partialDeadline.Before(deadline) {
			var cancel context.CancelFunc
			dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
			defer cancel()
		}

		// [Min] 单地址拨号
		c, err := dialSingle(dialCtx, dp, ra)
		// [Min] 成功立即返回
		if err == nil {
			return c, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	if firstErr == nil {
		firstErr = &OpError{Op: "dial", Net: dp.network, Source: nil, Addr: nil, Err: errMissingAddress}
	}
	return nil, firstErr
}

// dialSingle attempts to establish and returns a single connection to
// the destination address.
// [Min] 根据地址的类型进行单地址拨号
func dialSingle(ctx context.Context, dp *dialParam, ra Addr) (c Conn, err error) {
	trace, _ := ctx.Value(nettrace.TraceKey{}).(*nettrace.Trace)
	if trace != nil {
		raStr := ra.String()
		if trace.ConnectStart != nil {
			trace.ConnectStart(dp.network, raStr)
		}
		if trace.ConnectDone != nil {
			defer func() { trace.ConnectDone(dp.network, raStr, err) }()
		}
	}
	// [Min] local address 和 remote address 已经在之前 resolveAddrList的时候确保了类型的统一
	// [Min] 此时只要根据类型选择相应的函数进行 dial
	la := dp.LocalAddr
	switch ra := ra.(type) {
	case *TCPAddr:
		la, _ := la.(*TCPAddr)
		c, err = dialTCP(ctx, dp.network, la, ra)
	case *UDPAddr:
		la, _ := la.(*UDPAddr)
		c, err = dialUDP(ctx, dp.network, la, ra)
	case *IPAddr:
		la, _ := la.(*IPAddr)
		c, err = dialIP(ctx, dp.network, la, ra)
	case *UnixAddr:
		la, _ := la.(*UnixAddr)
		c, err = dialUnix(ctx, dp.network, la, ra)
	default:
		return nil, &OpError{Op: "dial", Net: dp.network, Source: la, Addr: ra, Err: &AddrError{Err: "unexpected address type", Addr: dp.address}}
	}
	if err != nil {
		return nil, &OpError{Op: "dial", Net: dp.network, Source: la, Addr: ra, Err: err} // c is non-nil interface containing nil pointer
	}
	return c, nil
}

// Listen announces on the local network address.
//
// The network must be "tcp", "tcp4", "tcp6", "unix" or "unixpacket".
//
// For TCP networks, if the host in the address parameter is empty or
// a literal unspecified IP address, Listen listens on all available
// unicast and anycast IP addresses of the local system.
// To only use IPv4, use network "tcp4".
// The address can use a host name, but this is not recommended,
// because it will create a listener for at most one of the host's IP
// addresses.
// If the port in the address parameter is empty or "0", as in
// "127.0.0.1:" or "[::1]:0", a port number is automatically chosen.
// The Addr method of Listener can be used to discover the chosen
// port.
//
// See func Dial for a description of the network and address
// parameters.
// [Min] 获得对本地指定地址进行监听的 listener，针对 TCP，Unix
func Listen(network, address string) (Listener, error) {
	// [Min] 获取 addrList
	addrs, err := DefaultResolver.resolveAddrList(context.Background(), "listen", network, address, nil)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
	}
	var l Listener
	// [Min] 第一个是 IPv4 的地址，根据其类型调用相应的 Listen 函数获得 Listener
	switch la := addrs.first(isIPv4).(type) {
	case *TCPAddr:
		l, err = ListenTCP(network, la)
	case *UnixAddr:
		l, err = ListenUnix(network, la)
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: la, Err: &AddrError{Err: "unexpected address type", Addr: address}}
	}
	if err != nil {
		return nil, err // l is non-nil interface containing nil pointer
	}
	return l, nil
}

// ListenPacket announces on the local network address.
//
// The network must be "udp", "udp4", "udp6", "unixgram", or an IP
// transport. The IP transports are "ip", "ip4", or "ip6" followed by
// a colon and a literal protocol number or a protocol name, as in
// "ip:1" or "ip:icmp".
//
// For UDP and IP networks, if the host in the address parameter is
// empty or a literal unspecified IP address, ListenPacket listens on
// all available IP addresses of the local system except multicast IP
// addresses.
// To only use IPv4, use network "udp4" or "ip4:proto".
// The address can use a host name, but this is not recommended,
// because it will create a listener for at most one of the host's IP
// addresses.
// If the port in the address parameter is empty or "0", as in
// "127.0.0.1:" or "[::1]:0", a port number is automatically chosen.
// The LocalAddr method of PacketConn can be used to discover the
// chosen port.
//
// See func Dial for a description of the network and address
// parameters.
// [Min] 功能与 Listen 类似，针对 UDP，IP，Unixgram
func ListenPacket(network, address string) (PacketConn, error) {
	addrs, err := DefaultResolver.resolveAddrList(context.Background(), "listen", network, address, nil)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
	}
	var l PacketConn
	switch la := addrs.first(isIPv4).(type) {
	case *UDPAddr:
		l, err = ListenUDP(network, la)
	case *IPAddr:
		l, err = ListenIP(network, la)
	case *UnixAddr:
		l, err = ListenUnixgram(network, la)
	default:
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: la, Err: &AddrError{Err: "unexpected address type", Addr: address}}
	}
	if err != nil {
		return nil, err // l is non-nil interface containing nil pointer
	}
	return l, nil
}
