// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// IP address manipulations
//
// IPv4 addresses are 4 bytes; IPv6 addresses are 16 bytes.
// An IPv4 address can be converted to an IPv6 address by
// adding a canonical prefix (10 zeros, 2 0xFFs).
// This library accepts either size of byte slice but always
// returns 16-byte addresses.

package net

import _ "unsafe" // for go:linkname

// IP address lengths (bytes).
const (
	IPv4len = 4
	IPv6len = 16
)

// An IP is a single IP address, a slice of bytes.
// Functions in this package accept either 4-byte (IPv4)
// or 16-byte (IPv6) slices as input.
//
// Note that in this documentation, referring to an
// IP address as an IPv4 address or an IPv6 address
// is a semantic property of the address, not just the
// length of the byte slice: a 16-byte slice can still
// be an IPv4 address.
// [Min] IP 是一个4字节或16字节长的切片，但不能仅根据切片的长度判断 IP 是 IPv4还是 IPv6
type IP []byte

// An IP mask is an IP address.
// [Min] IP掩码
type IPMask []byte

// An IPNet represents an IP network.
// [Min] 包含 IP 和 IPMask
type IPNet struct {
	IP   IP     // network number
	Mask IPMask // network mask
}

// IPv4 returns the IP address (in 16-byte form) of the
// IPv4 address a.b.c.d.
// [Min] 构造 IPv4，返回一个长为16的 byte slice，最后四个字节包含 IPv4 的地址
// [Min] 如[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff，192，168，1，1]
func IPv4(a, b, c, d byte) IP {
	p := make(IP, IPv6len)
	copy(p, v4InV6Prefix)
	p[12] = a
	p[13] = b
	p[14] = c
	p[15] = d
	return p
}

var v4InV6Prefix = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}

// IPv4Mask returns the IP mask (in 4-byte form) of the
// IPv4 mask a.b.c.d.
// [Min] 构造 IP 掩码，4字节长，如[255,255,255,0]
func IPv4Mask(a, b, c, d byte) IPMask {
	p := make(IPMask, IPv4len)
	p[0] = a
	p[1] = b
	p[2] = c
	p[3] = d
	return p
}

// CIDRMask returns an IPMask consisting of `ones' 1 bits
// followed by 0s up to a total length of `bits' bits.
// For a mask of this form, CIDRMask is the inverse of IPMask.Size.
/* [Min]
通过给定高位1的个数和掩码总共的位数，来构造掩码,如:
{12, 32, IPv4Mask(255, 240, 0, 0)},
{24, 32, IPv4Mask(255, 255, 255, 0)},
{48, 128, IPMask{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
*/
func CIDRMask(ones, bits int) IPMask {
	// [Min] 掩码位数必须为32或128，分别对应 ipv4和 ipv6
	if bits != 8*IPv4len && bits != 8*IPv6len {
		return nil
	}
	// [Min] 1的个数不能为负，也不能超过掩码位数
	if ones < 0 || ones > bits {
		return nil
	}
	l := bits / 8 // [Min] 掩码字节数
	m := make(IPMask, l)
	n := uint(ones)
	for i := 0; i < l; i++ {
		// [Min] 大于等于8说明该字节全是1，直接赋值0xff
		if n >= 8 {
			m[i] = 0xff
			n -= 8
			continue
		}
		// [Min] 不满8位时，先将11111111右移n位，此时高位为n个0，低位为8-n个1，再取反即可
		m[i] = ^byte(0xff >> n)
		n = 0
	}
	return m
}

// Well-known IPv4 addresses
var (
	IPv4bcast     = IPv4(255, 255, 255, 255) // limited broadcast
	IPv4allsys    = IPv4(224, 0, 0, 1)       // all systems
	IPv4allrouter = IPv4(224, 0, 0, 2)       // all routers
	IPv4zero      = IPv4(0, 0, 0, 0)         // all zeros
)

// Well-known IPv6 addresses
var (
	IPv6zero                   = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	IPv6unspecified            = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	IPv6loopback               = IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	IPv6interfacelocalallnodes = IP{0xff, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	IPv6linklocalallnodes      = IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	IPv6linklocalallrouters    = IP{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02}
)

// IsUnspecified reports whether ip is an unspecified address, either
// the IPv4 address "0.0.0.0" or the IPv6 address "::".
// [Min] 判断ip是否为全0IP
func (ip IP) IsUnspecified() bool {
	return ip.Equal(IPv4zero) || ip.Equal(IPv6unspecified)
}

// IsLoopback reports whether ip is a loopback address.
// [Min] 判断 IP 是否为环回地址
func (ip IP) IsLoopback() bool {
	// [Min] 先判断是否为IPv4，是则判断首字节是否为127
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 127
	}
	// [Min] 和IPv6的环回地址比较
	return ip.Equal(IPv6loopback)
}

// IsMulticast reports whether ip is a multicast address.
// [Min] 判断是否为多播地址
func (ip IP) IsMulticast() bool {
	// [Min] 先判断是否为IPv4，是则判断首字节的高四位是否为1110
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0]&0xf0 == 0xe0 // [Min] 首字节低四位置0后是否为224，即11100000
	}
	// [Min] IPv6地址首字节是否为 ff
	return len(ip) == IPv6len && ip[0] == 0xff
}

// IsInterfaceLocalMulticast reports whether ip is
// an interface-local multicast address.
// [Min] 判断节点本地多播地址，前两个字节是否为FF01
func (ip IP) IsInterfaceLocalMulticast() bool {
	return len(ip) == IPv6len && ip[0] == 0xff && ip[1]&0x0f == 0x01
}

// IsLinkLocalMulticast reports whether ip is a link-local
// multicast address.
// [Min] 判断链路本地多播地址，224.0.0.x，或前两个字节是否为FF02
func (ip IP) IsLinkLocalMulticast() bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 224 && ip4[1] == 0 && ip4[2] == 0
	}
	return len(ip) == IPv6len && ip[0] == 0xff && ip[1]&0x0f == 0x02
}

// IsLinkLocalUnicast reports whether ip is a link-local
// unicast address.
// [Min] 判断链路本地单播地址，169.254.x.x，或前两个字节是否为FE80
func (ip IP) IsLinkLocalUnicast() bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}
	return len(ip) == IPv6len && ip[0] == 0xfe && ip[1]&0xc0 == 0x80
}

// IsGlobalUnicast reports whether ip is a global unicast
// address.
//
// The identification of global unicast addresses uses address type
// identification as defined in RFC 1122, RFC 4632 and RFC 4291 with
// the exception of IPv4 directed broadcast addresses.
// It returns true even if ip is in IPv4 private address space or
// local IPv6 unicast address space.
// [Min] 判断全球单播地址
func (ip IP) IsGlobalUnicast() bool {
	return (len(ip) == IPv4len || len(ip) == IPv6len) &&
		!ip.Equal(IPv4bcast) &&
		!ip.IsUnspecified() &&
		!ip.IsLoopback() &&
		!ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast()
}

// Is p all zeros?
// [Min] 所有字节是否全0
func isZeros(p IP) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
}

// To4 converts the IPv4 address ip to a 4-byte representation.
// If ip is not an IPv4 address, To4 returns nil.
// [Min] 判断 IP 是否为 IPv4,是则返回4个字节的 IPv4 地址，否则返回 nil
func (ip IP) To4() IP {
	// [Min] 4个字节，肯定时 IPv4，直接返回
	if len(ip) == IPv4len {
		return ip
	}
	// [Min] 16个字节，且前12个字节为v4InV6Prefix，返回最后四个字节
	if len(ip) == IPv6len &&
		isZeros(ip[0:10]) &&
		ip[10] == 0xff &&
		ip[11] == 0xff {
		return ip[12:16]
	}
	return nil
}

// To16 converts the IP address ip to a 16-byte representation.
// If ip is not an IP address (it is the wrong length), To16 returns nil.
// [Min] 将 IP 转为16个字节的表达形式
func (ip IP) To16() IP {
	if len(ip) == IPv4len {
		return IPv4(ip[0], ip[1], ip[2], ip[3])
	}
	if len(ip) == IPv6len {
		return ip
	}
	return nil
}

// Default route masks for IPv4.
var (
	classAMask = IPv4Mask(0xff, 0, 0, 0)
	classBMask = IPv4Mask(0xff, 0xff, 0, 0)
	classCMask = IPv4Mask(0xff, 0xff, 0xff, 0)
)

// DefaultMask returns the default IP mask for the IP address ip.
// Only IPv4 addresses have default masks; DefaultMask returns
// nil if ip is not a valid IPv4 address.
// [Min] 返回 IP 的默认掩码，只有 IPv4 有默认掩码
func (ip IP) DefaultMask() IPMask {
	if ip = ip.To4(); ip == nil {
		return nil
	}
	switch true {
	case ip[0] < 0x80: // [Min] 首字节小于128，A类地址默认掩码255.0.0.0
		return classAMask
	case ip[0] < 0xC0: // [Min] 首字节[128,192)，B类地址默认掩码255.255.0.0
		return classBMask
	default: // [Min] 其他返回 C类地址默认掩码255.255.255.0
		return classCMask
	}
}

// [Min] slice中每个字节都是0xff
func allFF(b []byte) bool {
	for _, c := range b {
		if c != 0xff {
			return false
		}
	}
	return true
}

// Mask returns the result of masking the IP address ip with mask.
// [Min] 返回 IP 和掩码作用后的地址
func (ip IP) Mask(mask IPMask) IP {
	// [Min] 首先统一 mask 和 ip 的长度
	if len(mask) == IPv6len && len(ip) == IPv4len && allFF(mask[:12]) {
		mask = mask[12:]
	}
	if len(mask) == IPv4len && len(ip) == IPv6len && bytesEqual(ip[:12], v4InV6Prefix) {
		ip = ip[12:]
	}
	n := len(ip)
	if n != len(mask) {
		return nil
	}
	out := make(IP, n)
	for i := 0; i < n; i++ {
		out[i] = ip[i] & mask[i]
	}
	return out
}

// String returns the string form of the IP address ip.
// It returns one of 4 forms:
//   - "<nil>", if ip has length 0
//   - dotted decimal ("192.0.2.1"), if ip is an IPv4 or IP4-mapped IPv6 address
//   - IPv6 ("2001:db8::1"), if ip is a valid IPv6 address
//   - the hexadecimal form of ip, without punctuation, if no other cases apply
// [Min] 返回 IP 的字符串形式，具体参考https://zh.wikipedia.org/wiki/IPv6
func (ip IP) String() string {
	p := ip

	if len(ip) == 0 {
		return "<nil>"
	}

	// If IPv4, use dotted notation.
	// [Min] IPv4以x.x.x.x的格式返回
	if p4 := p.To4(); len(p4) == IPv4len {
		return uitoa(uint(p4[0])) + "." +
			uitoa(uint(p4[1])) + "." +
			uitoa(uint(p4[2])) + "." +
			uitoa(uint(p4[3]))
	}
	// [Min] 若不是 IPv4，且长度不为16，返回?hexstr
	if len(p) != IPv6len {
		return "?" + hexString(ip)
	}

	// Find longest run of zeros.
	e0 := -1
	e1 := -1
	for i := 0; i < IPv6len; i += 2 {
		j := i
		for j < IPv6len && p[j] == 0 && p[j+1] == 0 {
			j += 2
		}
		if j > i && j-i > e1-e0 {
			e0 = i
			e1 = j
			i = j
		}
	}
	// The symbol "::" MUST NOT be used to shorten just one 16 bit 0 field.
	if e1-e0 <= 2 {
		e0 = -1
		e1 = -1
	}

	const maxLen = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	b := make([]byte, 0, maxLen)

	// Print with possible :: in place of run of zeros
	for i := 0; i < IPv6len; i += 2 {
		if i == e0 {
			b = append(b, ':', ':')
			i = e1
			if i >= IPv6len {
				break
			}
		} else if i > 0 {
			b = append(b, ':')
		}
		b = appendHex(b, (uint32(p[i])<<8)|uint32(p[i+1]))
	}
	return string(b)
}

// [Min] 将 byte 转为两个十六进制的字符串，并返回
func hexString(b []byte) string {
	s := make([]byte, len(b)*2)
	for i, tn := range b {
		s[i*2], s[i*2+1] = hexDigit[tn>>4], hexDigit[tn&0xf]
	}
	return string(s)
}

// ipEmptyString is like ip.String except that it returns
// an empty string when ip is unset.
// [Min] 和 IP.String()类似，只是当 ip 为空时返回""
func ipEmptyString(ip IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

// MarshalText implements the encoding.TextMarshaler interface.
// The encoding is the same as returned by String, with one exception:
// When len(ip) is zero, it returns an empty slice.
// [Min] 实现encoding.TextMarshaler接口
func (ip IP) MarshalText() ([]byte, error) {
	if len(ip) == 0 {
		return []byte(""), nil
	}
	if len(ip) != IPv4len && len(ip) != IPv6len {
		return nil, &AddrError{Err: "invalid IP address", Addr: hexString(ip)}
	}
	return []byte(ip.String()), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// The IP address is expected in a form accepted by ParseIP.
// [Min] 实现encoding.TextUnmarshaler接口
func (ip *IP) UnmarshalText(text []byte) error {
	if len(text) == 0 {
		*ip = nil
		return nil
	}
	s := string(text)
	x := ParseIP(s)
	if x == nil {
		return &ParseError{Type: "IP address", Text: s}
	}
	*ip = x
	return nil
}

// Equal reports whether ip and x are the same IP address.
// An IPv4 address and that same address in IPv6 form are
// considered to be equal.
// [Min] 判断两个 ip 是否相同，ip 可以为不同的类型
func (ip IP) Equal(x IP) bool {
	if len(ip) == len(x) {
		return bytesEqual(ip, x)
	}
	if len(ip) == IPv4len && len(x) == IPv6len {
		return bytesEqual(x[0:12], v4InV6Prefix) && bytesEqual(ip, x[12:])
	}
	if len(ip) == IPv6len && len(x) == IPv4len {
		return bytesEqual(ip[0:12], v4InV6Prefix) && bytesEqual(ip[12:], x)
	}
	return false
}

// bytes.Equal is implemented in runtime/asm_$goarch.s
//go:linkname bytesEqual bytes.Equal
// [Min] bytesEqual用来判断两个 byte slice 是否相同，长度相同，内容相同，
func bytesEqual(x, y []byte) bool

// [Min] 判断两个 ip 是否同是 IPv4或 IPv6
func (ip IP) matchAddrFamily(x IP) bool {
	return ip.To4() != nil && x.To4() != nil || ip.To16() != nil && ip.To4() == nil && x.To16() != nil && x.To4() == nil
}

// If mask is a sequence of 1 bits followed by 0 bits,
// return the number of 1 bits.
// [Min] 如果 mask 是严格的一堆1跟着一堆0，则返回1的个数，否则返回-1
func simpleMaskLength(mask IPMask) int {
	var n int
	for i, v := range mask {
		if v == 0xff {
			n += 8
			continue
		}
		// found non-ff byte
		// count 1 bits
		for v&0x80 != 0 {
			n++
			v <<= 1
		}
		// rest must be 0 bits
		if v != 0 {
			return -1
		}
		for i++; i < len(mask); i++ {
			if mask[i] != 0 {
				return -1
			}
		}
		break
	}
	return n
}

// Size returns the number of leading ones and total bits in the mask.
// If the mask is not in the canonical form--ones followed by zeros--then
// Size returns 0, 0.
// [Min] 返回 mask 中前置1的个数和 mask 的总位长，若 mask 不是严格的一堆1跟着一堆0，返回0，0
func (m IPMask) Size() (ones, bits int) {
	ones, bits = simpleMaskLength(m), len(m)*8
	if ones == -1 {
		return 0, 0
	}
	return
}

// String returns the hexadecimal form of m, with no punctuation.
// [Min] 返回 mask 的十六进制格式
func (m IPMask) String() string {
	if len(m) == 0 {
		return "<nil>"
	}
	return hexString(m)
}

// [Min] 相当于格式化 IPNet 中的 IP 和 mask 为各自类型对应的长度4或16
func networkNumberAndMask(n *IPNet) (ip IP, m IPMask) {
	// [Min] 不是 IPv4，长度也不是16，返回nil,nil
	if ip = n.IP.To4(); ip == nil {
		ip = n.IP
		if len(ip) != IPv6len {
			return nil, nil
		}
	}
	// [Min] 此时 ip若为 IPv4，长度一定为4，后续可仅根据长度来判断 ip 的类型
	m = n.Mask
	switch len(m) {
	case IPv4len:
		if len(ip) != IPv4len { // [Min] mask为4字节但 ip 不是IPv4，返回 nil,nil
			return nil, nil
		}
	case IPv6len:
		if len(ip) == IPv4len { // [Min] mask为16字节，但 ip 为 IPv4，只取后4个字节作为 mask
			m = m[12:]
		}
	default:
		return nil, nil
	}
	return
}

// Contains reports whether the network includes ip.
// [Min] 判断 IPNet 是否含有给定的 IP
func (n *IPNet) Contains(ip IP) bool {
	nn, m := networkNumberAndMask(n)
	if x := ip.To4(); x != nil {
		ip = x
	}
	// [Min] 先判断 格式化后ip 的长度是否相同
	l := len(ip)
	if l != len(nn) {
		return false
	}
	// [Min] 分别对 IPNet 中的 IP 和给定的 ip 作用IPNet中的掩码，判断是否相同
	for i := 0; i < l; i++ {
		if nn[i]&m[i] != ip[i]&m[i] {
			return false
		}
	}
	return true
}

// Network returns the address's network name, "ip+net".
func (n *IPNet) Network() string { return "ip+net" }

// String returns the CIDR notation of n like "192.0.2.1/24"
// or "2001:db8::/48" as defined in RFC 4632 and RFC 4291.
// If the mask is not in the canonical form, it returns the
// string which consists of an IP address, followed by a slash
// character and a mask expressed as hexadecimal form with no
// punctuation like "198.51.100.1/c000ff00".
// [Min] 将 IPNet 表示成 networkNumber/mask的形式，
// [Min] 其中mask 优先简单表示（前置1的个数），否则以完全的 hexstr 表示
func (n *IPNet) String() string {
	nn, m := networkNumberAndMask(n)
	if nn == nil || m == nil {
		return "<nil>"
	}
	l := simpleMaskLength(m)
	if l == -1 {
		return nn.String() + "/" + m.String()
	}
	return nn.String() + "/" + uitoa(uint(l))
}

// Parse IPv4 address (d.d.d.d).
// [Min] 根据字符串解析 IPv4
func parseIPv4(s string) IP {
	var p [IPv4len]byte
	for i := 0; i < IPv4len; i++ {
		if len(s) == 0 {
			// Missing octets.
			return nil
		}
		if i > 0 {
			if s[0] != '.' {
				return nil
			}
			s = s[1:]
		}
		n, c, ok := dtoi(s)  // [Min] n 为当前 s 的第一段数值，c 为第一个非数字的索引
		if !ok || n > 0xFF { // [Min] 解析不成功，或所得数值大于单字节最大值255，返回 nil
			return nil
		}
		s = s[c:] // [Min] 保留需要继续解析的字符串
		p[i] = byte(n)
	}
	if len(s) != 0 { // [Min] 解析完4段数值，剩余字符串必须为空
		return nil
	}
	return IPv4(p[0], p[1], p[2], p[3])
}

// parseIPv6 parses s as a literal IPv6 address described in RFC 4291
// and RFC 5952.  It can also parse a literal scoped IPv6 address with
// zone identifier which is described in RFC 4007 when zoneAllowed is
// true.
// [Min] 解析 IPv6
func parseIPv6(s string, zoneAllowed bool) (ip IP, zone string) {
	ip = make(IP, IPv6len)
	ellipsis := -1 // position of ellipsis in ip 省略符号的索引

	if zoneAllowed {
		s, zone = splitHostZone(s) // [Min] 分离出 zone
	}

	// Might have leading ellipsis
	// [Min] 一开始就是省略符号::
	if len(s) >= 2 && s[0] == ':' && s[1] == ':' {
		ellipsis = 0
		s = s[2:]
		// Might be only ellipsis
		// [Min] 若只是省略符号，直接返回零值
		if len(s) == 0 {
			return ip, zone
		}
	}

	// Loop, parsing hex numbers followed by colon.
	i := 0
	for i < IPv6len {
		// Hex number.
		n, c, ok := xtoi(s)    // [Min] n为 s 最左边的第一个16进制数值，c 为 s 中第一个非十六进制数字索引
		if !ok || n > 0xFFFF { // [Min] 若解析失败或者数值超过两个字节的最大值0xFFFF，返回nil
			return nil, zone
		}

		// If followed by dot, might be in trailing IPv4.
		// [Min] 如果分隔符为'.'，可能类似于这种形式 "::ffff:127.1.2.3" 或 "0:0:0:0:0000:ffff:127.1.2.3"
		if c < len(s) && s[c] == '.' {
			if ellipsis < 0 && i != IPv6len-IPv4len { // [Min] 没有省略符号，且'.'的位置不对
				// Not the right place.
				return nil, zone
			}
			if i+IPv4len > IPv6len {
				// Not enough room.
				return nil, zone
			}
			ip4 := parseIPv4(s) // [Min] 尝试将剩余的字符串进行 ipv4解析
			if ip4 == nil {
				return nil, zone
			}
			ip[i] = ip4[12]
			ip[i+1] = ip4[13]
			ip[i+2] = ip4[14]
			ip[i+3] = ip4[15]
			s = ""
			i += IPv4len
			break
		}

		// Save this 16-bit chunk.
		// [Min] 存储解析出的 n 对应的两个字节到 ip 切片中
		ip[i] = byte(n >> 8)
		ip[i+1] = byte(n)
		i += 2

		// Stop at end of string.
		s = s[c:]
		if len(s) == 0 {
			break
		}

		// Otherwise must be followed by colon and more.
		// [Min] 剩下的字符串必须以':'开头，且后面还要有内容
		if s[0] != ':' || len(s) == 1 {
			return nil, zone
		}
		s = s[1:]

		// Look for ellipsis.
		// [Min] 若舍去起始一个':'后还是':'，说明时省略符号
		if s[0] == ':' {
			if ellipsis >= 0 { // already have one 多于一个省略符号
				return nil, zone
			}
			ellipsis = i // [Min] 记录下省略符号在 ip 切片中的索引
			s = s[1:]
			if len(s) == 0 { // can be at end
				break
			}
		}
	}

	// Must have used entire string.
	if len(s) != 0 {
		return nil, zone
	}

	// If didn't parse enough, expand ellipsis.
	// [Min] 将省略的部分以0填充回 ip 切片中对应的位置
	if i < IPv6len {
		if ellipsis < 0 {
			return nil, zone
		}
		n := IPv6len - i
		for j := i - 1; j >= ellipsis; j-- {
			ip[j+n] = ip[j]
		}
		for j := ellipsis + n - 1; j >= ellipsis; j-- {
			ip[j] = 0
		}
	} else if ellipsis >= 0 {
		// Ellipsis must represent at least one 0 group.
		return nil, zone
	}
	return ip, zone
}

// ParseIP parses s as an IP address, returning the result.
// The string s can be in dotted decimal ("192.0.2.1")
// or IPv6 ("2001:db8::68") form.
// If s is not a valid textual representation of an IP address,
// ParseIP returns nil.
// [Min] 根据字符串中的最先碰到的分隔符'.'或':'来解析 IPv4或 IPv6
func ParseIP(s string) IP {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '.':
			return parseIPv4(s)
		case ':':
			ip, _ := parseIPv6(s, false)
			return ip
		}
	}
	return nil
}

// ParseCIDR parses s as a CIDR notation IP address and prefix length,
// like "192.0.2.0/24" or "2001:db8::/32", as defined in
// RFC 4632 and RFC 4291.
//
// It returns the IP address and the network implied by the IP and
// prefix length.
// For example, ParseCIDR("192.0.2.1/24") returns the IP address
// 192.0.2.1 and the network 192.0.2.0/24.
// [Min] 解析 CIDR
func ParseCIDR(s string) (IP, *IPNet, error) {
	i := byteIndex(s, '/')
	if i < 0 { // [Min] 字符串中必须有'/'
		return nil, nil, &ParseError{Type: "CIDR address", Text: s}
	}
	addr, mask := s[:i], s[i+1:] // [Min] 以'/'分离出 ip 和 mask
	// [Min] 先尝试解析 IPv4，不成功再尝试解析 IPv6
	iplen := IPv4len
	ip := parseIPv4(addr)
	if ip == nil {
		iplen = IPv6len
		ip, _ = parseIPv6(addr, false)
	}
	/* [Min]
	ip首先要解析成功
	mask 要成功解析出1的个数，且不能为负，不能大于该类ip对应的位长
	mask 不能有非十进制数字字符
	*/
	n, i, ok := dtoi(mask)
	if ip == nil || !ok || i != len(mask) || n < 0 || n > 8*iplen {
		return nil, nil, &ParseError{Type: "CIDR address", Text: s}
	}
	m := CIDRMask(n, 8*iplen) // [Min] 构造 mask
	return ip, &IPNet{IP: ip.Mask(m), Mask: m}, nil
}
