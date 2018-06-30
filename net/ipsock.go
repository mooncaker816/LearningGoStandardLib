// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"context"
	"sync"
)

// BUG(rsc,mikio): On DragonFly BSD and OpenBSD, listening on the
// "tcp" and "udp" networks does not listen for both IPv4 and IPv6
// connections. This is due to the fact that IPv4 traffic will not be
// routed to an IPv6 socket - two separate sockets are required if
// both address families are to be supported.
// See inet6(4) for details.

type ipStackCapabilities struct {
	sync.Once             // guards following
	ipv4Enabled           bool
	ipv6Enabled           bool
	ipv4MappedIPv6Enabled bool
}

var ipStackCaps ipStackCapabilities

// supportsIPv4 reports whether the platform supports IPv4 networking
// functionality.
func supportsIPv4() bool {
	ipStackCaps.Once.Do(ipStackCaps.probe)
	return ipStackCaps.ipv4Enabled
}

// supportsIPv6 reports whether the platform supports IPv6 networking
// functionality.
func supportsIPv6() bool {
	ipStackCaps.Once.Do(ipStackCaps.probe)
	return ipStackCaps.ipv6Enabled
}

// supportsIPv4map reports whether the platform supports mapping an
// IPv4 address inside an IPv6 address at transport layer
// protocols. See RFC 4291, RFC 4038 and RFC 3493.
func supportsIPv4map() bool {
	ipStackCaps.Once.Do(ipStackCaps.probe)
	return ipStackCaps.ipv4MappedIPv6Enabled
}

// An addrList represents a list of network endpoint addresses.
// [Min] 多个地址列表
type addrList []Addr

// isIPv4 reports whether addr contains an IPv4 address.
// [Min] 判断 addr 是否时 IPv4地址
func isIPv4(addr Addr) bool {
	switch addr := addr.(type) {
	case *TCPAddr:
		return addr.IP.To4() != nil
	case *UDPAddr:
		return addr.IP.To4() != nil
	case *IPAddr:
		return addr.IP.To4() != nil
	}
	return false
}

// isNotIPv4 reports whether addr does not contain an IPv4 address.
// [Min] 判断 addr 是否不是 IPv4地址
func isNotIPv4(addr Addr) bool { return !isIPv4(addr) }

// forResolve returns the most appropriate address in address for
// a call to ResolveTCPAddr, ResolveUDPAddr, or ResolveIPAddr.
// IPv4 is preferred, unless addr contains an IPv6 literal.
// [Min] 根据 network 的类型，从 addrlist 中返回第一个最佳匹配的地址，如果都不匹配，则返回第一个地址
func (addrs addrList) forResolve(network, addr string) Addr {
	var want6 bool
	switch network {
	case "ip":
		// IPv6 literal (addr does NOT contain a port)
		want6 = count(addr, ':') > 0
	case "tcp", "udp":
		// IPv6 literal. (addr contains a port, so look for '[')
		want6 = count(addr, '[') > 0
	}
	if want6 {
		return addrs.first(isNotIPv4) // [Min] 返回第一个不是 IPv4的地址
	}
	return addrs.first(isIPv4) // [Min] 返回第一个是 IPv4的地址
}

// first returns the first address which satisfies strategy, or if
// none do, then the first address of any kind.
// [Min] 根据判断匹配函数strategy，返回第一个匹配的地址，若都不满足，返回第一个地址
func (addrs addrList) first(strategy func(Addr) bool) Addr {
	for _, addr := range addrs {
		if strategy(addr) {
			return addr
		}
	}
	return addrs[0]
}

// partition divides an address list into two categories, using a
// strategy function to assign a boolean label to each address.
// The first address, and any with a matching label, are returned as
// primaries, while addresses with the opposite label are returned
// as fallbacks. For non-empty inputs, primaries is guaranteed to be
// non-empty.
// [Min] 根据 strategy 判断真假，与第一个 addr 同真同假的为 primaries,其余为 fallbacks
func (addrs addrList) partition(strategy func(Addr) bool) (primaries, fallbacks addrList) {
	var primaryLabel bool
	for i, addr := range addrs {
		label := strategy(addr)
		if i == 0 || label == primaryLabel {
			primaryLabel = label
			primaries = append(primaries, addr)
		} else {
			fallbacks = append(fallbacks, addr)
		}
	}
	return
}

// filterAddrList applies a filter to a list of IP addresses,
// yielding a list of Addr objects. Known filters are nil, ipv4only,
// and ipv6only. It returns every address when the filter is nil.
// The result contains at least one address when error is nil.
// [Min] 根据过滤函数，过滤 ip 地址
func filterAddrList(filter func(IPAddr) bool, ips []IPAddr, inetaddr func(IPAddr) Addr, originalAddr string) (addrList, error) {
	var addrs addrList
	for _, ip := range ips {
		if filter == nil || filter(ip) {
			addrs = append(addrs, inetaddr(ip))
		}
	}
	if len(addrs) == 0 {
		return nil, &AddrError{Err: errNoSuitableAddress.Error(), Addr: originalAddr}
	}
	return addrs, nil
}

// ipv4only reports whether addr is an IPv4 address.
// [Min] IP是否为 IPv4，用于过滤 IPv6
func ipv4only(addr IPAddr) bool {
	return addr.IP.To4() != nil
}

// ipv6only reports whether addr is an IPv6 address except IPv4-mapped IPv6 address.
// [Min] IP是否为 IPv6，用于过滤 IPv4
func ipv6only(addr IPAddr) bool {
	return len(addr.IP) == IPv6len && addr.IP.To4() == nil
}

// SplitHostPort splits a network address of the form "host:port",
// "host%zone:port", "[host]:port" or "[host%zone]:port" into host or
// host%zone and port.
//
// A literal IPv6 address in hostport must be enclosed in square
// brackets, as in "[::1]:80", "[::1%lo0]:80".
//
// See func Dial for a description of the hostport parameter, and host
// and port results.
// [Min] 分离 host 和 port
func SplitHostPort(hostport string) (host, port string, err error) {
	const (
		missingPort   = "missing port in address"
		tooManyColons = "too many colons in address"
	)
	addrErr := func(addr, why string) (host, port string, err error) {
		return "", "", &AddrError{Err: why, Addr: addr}
	}
	j, k := 0, 0

	// The port starts after the last colon.
	// [Min] 找到最后一个':'
	i := last(hostport, ':')
	if i < 0 {
		return addrErr(hostport, missingPort)
	}

	// [Min] 如果以'['开头，则':'前一个字符必须为']'
	if hostport[0] == '[' {
		// Expect the first ']' just before the last ':'.
		end := byteIndex(hostport, ']')
		if end < 0 {
			return addrErr(hostport, "missing ']' in address")
		}
		switch end + 1 {
		case len(hostport):
			// There can't be a ':' behind the ']' now.
			// [Min] ':'在']'前，且']'后为空
			return addrErr(hostport, missingPort)
		case i:
			// The expected result.
		default:
			// Either ']' isn't followed by a colon, or it is
			// followed by a colon that is not the last one.
			// [Min] 要么最后一个':'没有紧跟']'，要么']'后面跟的':'不是最后一个
			if hostport[end+1] == ':' {
				return addrErr(hostport, tooManyColons)
			}
			return addrErr(hostport, missingPort)
		}
		host = hostport[1:end]
		j, k = 1, end+1 // there can't be a '[' resp. ']' before these positions
	} else {
		host = hostport[:i]
		if byteIndex(host, ':') >= 0 {
			return addrErr(hostport, tooManyColons)
		}
	}
	if byteIndex(hostport[j:], '[') >= 0 {
		return addrErr(hostport, "unexpected '[' in address")
	}
	if byteIndex(hostport[k:], ']') >= 0 {
		return addrErr(hostport, "unexpected ']' in address")
	}

	port = hostport[i+1:]
	return host, port, nil
}

// [Min] 分离 host 和 zone
func splitHostZone(s string) (host, zone string) {
	// The IPv6 scoped addressing zone identifier starts after the
	// last percent sign.
	// [Min] 以最后一个'%'为界，左边为host，右边为 zone
	if i := last(s, '%'); i > 0 {
		host, zone = s[:i], s[i+1:]
	} else {
		host = s
	}
	return
}

// JoinHostPort combines host and port into a network address of the
// form "host:port". If host contains a colon, as found in literal
// IPv6 addresses, then JoinHostPort returns "[host]:port".
//
// See func Dial for a description of the host and port parameters.
// [Min] 连接 host 和 port，host:port或[host]:port
func JoinHostPort(host, port string) string {
	// We assume that host is a literal IPv6 address if host has
	// colons.
	if byteIndex(host, ':') >= 0 {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// internetAddrList resolves addr, which may be a literal IP
// address or a DNS name, and returns a list of internet protocol
// family addresses. The result contains at least one address when
// error is nil.
// [Min] 根据 net 和 addr 生成 addrlist
func (r *Resolver) internetAddrList(ctx context.Context, net, addr string) (addrList, error) {
	var (
		err        error
		host, port string
		portnum    int
	)
	switch net {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
		if addr != "" {
			if host, port, err = SplitHostPort(addr); err != nil {
				return nil, err
			}
			if portnum, err = r.LookupPort(ctx, net, port); err != nil {
				return nil, err
			}
		}
	case "ip", "ip4", "ip6":
		if addr != "" {
			host = addr
		}
	default:
		return nil, UnknownNetworkError(net)
	}
	inetaddr := func(ip IPAddr) Addr {
		switch net {
		case "tcp", "tcp4", "tcp6":
			return &TCPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "udp", "udp4", "udp6":
			return &UDPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone}
		case "ip", "ip4", "ip6":
			return &IPAddr{IP: ip.IP, Zone: ip.Zone}
		default:
			panic("unexpected network: " + net)
		}
	}
	if host == "" {
		return addrList{inetaddr(IPAddr{})}, nil
	}

	// Try as a literal IP address, then as a DNS name.
	var ips []IPAddr
	if ip := parseIPv4(host); ip != nil {
		ips = []IPAddr{{IP: ip}}
	} else if ip, zone := parseIPv6(host, true); ip != nil {
		ips = []IPAddr{{IP: ip, Zone: zone}}
		// Issue 18806: if the machine has halfway configured
		// IPv6 such that it can bind on "::" (IPv6unspecified)
		// but not connect back to that same address, fall
		// back to dialing 0.0.0.0.
		if ip.Equal(IPv6unspecified) {
			ips = append(ips, IPAddr{IP: IPv4zero})
		}
	} else {
		// Try as a DNS name.
		ips, err = r.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
	}

	// [Min] 根据 network 最后一位判断需要过滤的 ip 种类，调用 filterAddrList 进行过滤
	var filter func(IPAddr) bool
	if net != "" && net[len(net)-1] == '4' {
		filter = ipv4only
	}
	if net != "" && net[len(net)-1] == '6' {
		filter = ipv6only
	}
	return filterAddrList(filter, ips, inetaddr, host)
}

// [Min] 根据 net 类型，返回环回地址
func loopbackIP(net string) IP {
	if net != "" && net[len(net)-1] == '6' {
		return IPv6loopback
	}
	return IP{127, 0, 0, 1}
}
