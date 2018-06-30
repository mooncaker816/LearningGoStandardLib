// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"syscall"
)

// BUG(mikio): On every POSIX platform, reads from the "ip4" network
// using the ReadFrom or ReadFromIP method might not return a complete
// IPv4 packet, including its header, even if there is space
// available. This can occur even in cases where Read or ReadMsgIP
// could return a complete packet. For this reason, it is recommended
// that you do not use these methods if it is important to receive a
// full packet.
//
// The Go 1 compatibility guidelines make it impossible for us to
// change the behavior of these methods; use Read or ReadMsgIP
// instead.

// BUG(mikio): On NaCl and Plan 9, the ReadMsgIP and
// WriteMsgIP methods of IPConn are not implemented.

// BUG(mikio): On Windows, the File method of IPConn is not
// implemented.

// IPAddr represents the address of an IP end point.
// [Min] IPAddr 包含了 IP 和 Zone，实现了 Addr 接口（Network()+String()）
type IPAddr struct {
	IP   IP
	Zone string // IPv6 scoped addressing zone
}

// Network returns the address's network name, "ip".
// [Min] 返回network 类型 ip
func (a *IPAddr) Network() string { return "ip" }

// [Min] 返回 IP 地址和 zone 信息
func (a *IPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	ip := ipEmptyString(a.IP)
	if a.Zone != "" {
		return ip + "%" + a.Zone
	}
	return ip
}

// [Min]  IPAddr是否为通配nil 或全0 ip 地址
func (a *IPAddr) isWildcard() bool {
	if a == nil || a.IP == nil {
		return true
	}
	return a.IP.IsUnspecified()
}

// [Min] 过滤掉为 nil 的 IPAddr，并以接口的形式返回
func (a *IPAddr) opAddr() Addr {
	if a == nil {
		return nil
	}
	return a
}

// ResolveIPAddr returns an address of IP end point.
//
// The network must be an IP network name.
//
// If the host in the address parameter is not a literal IP address,
// ResolveIPAddr resolves the address to an address of IP end point.
// Otherwise, it parses the address as a literal IP address.
// The address parameter can use a host name, but this is not
// recommended, because it will return at most one of the host name's
// IP addresses.
//
// See func Dial for a description of the network and address
// parameters.
// [Min] 根据 network 和 address 字符串，构造 IPAddr
func ResolveIPAddr(network, address string) (*IPAddr, error) {
	// [Min] network 为空，默认为 ip
	if network == "" { // a hint wildcard for Go 1.0 undocumented behavior
		network = "ip"
	}
	// [Min]  仅解析 network，不带 protocal
	afnet, _, err := parseNetwork(context.Background(), network, false)
	if err != nil {
		return nil, err
	}
	switch afnet {
	case "ip", "ip4", "ip6":
	default:
		return nil, UnknownNetworkError(network)
	}
	// [Min] 构造AddrList
	addrs, err := DefaultResolver.internetAddrList(context.Background(), afnet, address)
	if err != nil {
		return nil, err
	}
	// [Min] 从 addrlist 中返回最佳地址
	return addrs.forResolve(network, address).(*IPAddr), nil
}

// IPConn is the implementation of the Conn and PacketConn interfaces
// for IP network connections.
// [Min] IPConn 包裹了 conn，实现了 Conn 和 PacketConn 接口
type IPConn struct {
	conn
}

// SyscallConn returns a raw network connection.
// This implements the syscall.Conn interface.
func (c *IPConn) SyscallConn() (syscall.RawConn, error) {
	if !c.ok() {
		return nil, syscall.EINVAL
	}
	return newRawConn(c.fd)
}

// ReadFromIP acts like ReadFrom but returns an IPAddr.
// [Min] 与 ReadFrom 相似，返回该 IPConn 的 IPAddr
func (c *IPConn) ReadFromIP(b []byte) (int, *IPAddr, error) {
	if !c.ok() {
		return 0, nil, syscall.EINVAL
	}
	n, addr, err := c.readFrom(b)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return n, addr, err
}

// ReadFrom implements the PacketConn ReadFrom method.
// [Min] 从 c 中读取 payload 到 b，并返回该 IPConn 的 IPAddr
// [Min] 注意，与一般意义上的 ReadFrom 的方向不同
func (c *IPConn) ReadFrom(b []byte) (int, Addr, error) {
	if !c.ok() {
		return 0, nil, syscall.EINVAL
	}
	n, addr, err := c.readFrom(b)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	if addr == nil {
		return n, nil, err
	}
	return n, addr, err
}

// ReadMsgIP reads a message from c, copying the payload into b and
// the associated out-of-band data into oob. It returns the number of
// bytes copied into b, the number of bytes copied into oob, the flags
// that were set on the message and the source address of the message.
//
// The packages golang.org/x/net/ipv4 and golang.org/x/net/ipv6 can be
// used to manipulate IP-level socket options in oob.
// [Min] 从 c 中读取数据，写入 b,oob，返回读取的数量和数据源地址
func (c *IPConn) ReadMsgIP(b, oob []byte) (n, oobn, flags int, addr *IPAddr, err error) {
	if !c.ok() {
		return 0, 0, 0, nil, syscall.EINVAL
	}
	n, oobn, flags, addr, err = c.readMsg(b, oob)
	if err != nil {
		err = &OpError{Op: "read", Net: c.fd.net, Source: c.fd.laddr, Addr: c.fd.raddr, Err: err}
	}
	return
}

// WriteToIP acts like WriteTo but takes an IPAddr.
// [Min] 和 WriteTo 类似
func (c *IPConn) WriteToIP(b []byte, addr *IPAddr) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	n, err := c.writeTo(b, addr)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return n, err
}

// WriteTo implements the PacketConn WriteTo method.
// [Min] 通过 c 将数据拷贝到 b，写入 addr
func (c *IPConn) WriteTo(b []byte, addr Addr) (int, error) {
	if !c.ok() {
		return 0, syscall.EINVAL
	}
	a, ok := addr.(*IPAddr)
	if !ok {
		return 0, &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr, Err: syscall.EINVAL}
	}
	n, err := c.writeTo(b, a)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: a.opAddr(), Err: err}
	}
	return n, err
}

// WriteMsgIP writes a message to addr via c, copying the payload from
// b and the associated out-of-band data from oob. It returns the
// number of payload and out-of-band bytes written.
//
// The packages golang.org/x/net/ipv4 and golang.org/x/net/ipv6 can be
// used to manipulate IP-level socket options in oob.
// [Min] 通过 c 将 b，oob 写入 addr
func (c *IPConn) WriteMsgIP(b, oob []byte, addr *IPAddr) (n, oobn int, err error) {
	if !c.ok() {
		return 0, 0, syscall.EINVAL
	}
	n, oobn, err = c.writeMsg(b, oob, addr)
	if err != nil {
		err = &OpError{Op: "write", Net: c.fd.net, Source: c.fd.laddr, Addr: addr.opAddr(), Err: err}
	}
	return
}

// [Min]  通过 fd新建一个 IPConn
func newIPConn(fd *netFD) *IPConn { return &IPConn{conn{fd}} }

// DialIP acts like Dial for IP networks.
//
// The network must be an IP network name; see func Dial for details.
//
// If laddr is nil, a local address is automatically chosen.
// If the IP field of raddr is nil or an unspecified IP address, the
// local system is assumed.
// [Min] 通过地址拨号，如果 laddr 为 nil，会自动选择 loacl address
// [Min] 如果 raddr 中的 IP 为 nil或者为未明示的 ip，默认为本地连本地
func DialIP(network string, laddr, raddr *IPAddr) (*IPConn, error) {
	// [Min] dialIP 会生成 fd 并调用 newIPConn 返回 IPConn
	c, err := dialIP(context.Background(), network, laddr, raddr)
	if err != nil {
		return nil, &OpError{Op: "dial", Net: network, Source: laddr.opAddr(), Addr: raddr.opAddr(), Err: err}
	}
	return c, nil
}

// ListenIP acts like ListenPacket for IP networks.
//
// The network must be an IP network name; see func Dial for details.
//
// If the IP field of laddr is nil or an unspecified IP address,
// ListenIP listens on all available IP addresses of the local system
// except multicast IP addresses.
// [Min] 返回待监听的本地 IPConn，如果本地监听ip 为 nil 或没有标识，则默认监听除多播地址以外的所有地址
func ListenIP(network string, laddr *IPAddr) (*IPConn, error) {
	c, err := listenIP(context.Background(), network, laddr)
	if err != nil {
		return nil, &OpError{Op: "listen", Net: network, Source: nil, Addr: laddr.opAddr(), Err: err}
	}
	return c, nil
}
