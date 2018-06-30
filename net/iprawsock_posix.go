// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux nacl netbsd openbsd solaris windows

package net

import (
	"context"
	"syscall"
)

// [Min] 根据 sockaddr 类型转为对应的 IPAddr
func sockaddrToIP(sa syscall.Sockaddr) Addr {
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		return &IPAddr{IP: sa.Addr[0:]}
	case *syscall.SockaddrInet6:
		return &IPAddr{IP: sa.Addr[0:], Zone: zoneCache.name(int(sa.ZoneId))}
	}
	return nil
}

// [Min] ip的类型
func (a *IPAddr) family() int {
	if a == nil || len(a.IP) <= IPv4len {
		return syscall.AF_INET
	}
	if a.IP.To4() != nil {
		return syscall.AF_INET
	}
	return syscall.AF_INET6
}

// [Min]  根据 family 将IPAddr 转为 sockaddr
func (a *IPAddr) sockaddr(family int) (syscall.Sockaddr, error) {
	if a == nil {
		return nil, nil
	}
	return ipToSockaddr(family, a.IP, 0, a.Zone)
}

// [Min] 根据类型返回环回地址
func (a *IPAddr) toLocal(net string) sockaddr {
	return &IPAddr{loopbackIP(net), a.Zone}
}

// [Min] 从 b 中读取数据至 c
func (c *IPConn) readFrom(b []byte) (int, *IPAddr, error) {
	// TODO(cw,rsc): consider using readv if we know the family
	// type to avoid the header trim/copy
	var addr *IPAddr
	n, sa, err := c.fd.readFrom(b)
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		addr = &IPAddr{IP: sa.Addr[0:]}
		n = stripIPv4Header(n, b)
	case *syscall.SockaddrInet6:
		addr = &IPAddr{IP: sa.Addr[0:], Zone: zoneCache.name(int(sa.ZoneId))}
	}
	return n, addr, err
}

func stripIPv4Header(n int, b []byte) int {
	if len(b) < 20 {
		return n
	}
	l := int(b[0]&0x0f) << 2
	if 20 > l || l > len(b) {
		return n
	}
	if b[0]>>4 != 4 {
		return n
	}
	copy(b, b[l:])
	return n - l
}

// [Min] 从 c 中读取数据至 b，oob
func (c *IPConn) readMsg(b, oob []byte) (n, oobn, flags int, addr *IPAddr, err error) {
	var sa syscall.Sockaddr
	n, oobn, flags, sa, err = c.fd.readMsg(b, oob)
	switch sa := sa.(type) {
	case *syscall.SockaddrInet4:
		addr = &IPAddr{IP: sa.Addr[0:]}
	case *syscall.SockaddrInet6:
		addr = &IPAddr{IP: sa.Addr[0:], Zone: zoneCache.name(int(sa.ZoneId))}
	}
	return
}

// [Min] 将 c 中的数据写入 b
func (c *IPConn) writeTo(b []byte, addr *IPAddr) (int, error) {
	if c.fd.isConnected {
		return 0, ErrWriteToConnected
	}
	if addr == nil {
		return 0, errMissingAddress
	}
	sa, err := addr.sockaddr(c.fd.family)
	if err != nil {
		return 0, err
	}
	return c.fd.writeTo(b, sa)
}

// [Min] 将 b，oob 通过 c 写入 addr
func (c *IPConn) writeMsg(b, oob []byte, addr *IPAddr) (n, oobn int, err error) {
	if c.fd.isConnected {
		return 0, 0, ErrWriteToConnected
	}
	if addr == nil {
		return 0, 0, errMissingAddress
	}
	sa, err := addr.sockaddr(c.fd.family)
	if err != nil {
		return 0, 0, err
	}
	return c.fd.writeMsg(b, oob, sa)
}

// [Min] 拨号，仅支持 ip 地址
func dialIP(ctx context.Context, netProto string, laddr, raddr *IPAddr) (*IPConn, error) {
	// [Min] 解析 network，仅支持 ip 类型的 network
	network, proto, err := parseNetwork(ctx, netProto, true)
	if err != nil {
		return nil, err
	}
	switch network {
	case "ip", "ip4", "ip6":
	default:
		return nil, UnknownNetworkError(netProto)
	}
	if raddr == nil {
		return nil, errMissingAddress
	}
	// [Min] 获取 fd
	fd, err := internetSocket(ctx, network, laddr, raddr, syscall.SOCK_RAW, proto, "dial")
	if err != nil {
		return nil, err
	}
	// [Min] 通过 fd  构造IPConn，并返回
	return newIPConn(fd), nil
}

// [Min] 返回待监听的本地IPConn
func listenIP(ctx context.Context, netProto string, laddr *IPAddr) (*IPConn, error) {
	network, proto, err := parseNetwork(ctx, netProto, true)
	if err != nil {
		return nil, err
	}
	switch network {
	case "ip", "ip4", "ip6":
	default:
		return nil, UnknownNetworkError(netProto)
	}
	// [Min] 获取 fd
	fd, err := internetSocket(ctx, network, laddr, nil, syscall.SOCK_RAW, proto, "listen")
	if err != nil {
		return nil, err
	}
	return newIPConn(fd), nil
}
