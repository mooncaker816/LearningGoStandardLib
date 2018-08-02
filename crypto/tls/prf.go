// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
)

// Split a premaster secret in two as specified in RFC 4346, section 5.
// [Min] 拆分预备主密码为2部分
func splitPreMasterSecret(secret []byte) (s1, s2 []byte) {
	s1 = secret[0 : (len(secret)+1)/2]
	s2 = secret[len(secret)/2:]
	return
}

// pHash implements the P_hash function, as defined in RFC 4346, section 5.
// [Min] 从种子出发，以 secret 为 key，不停计算 HMAC，直到填满 result 为止
// [Min] HMAC(HMAC(seed) + seed)
// [Min] HMAC(HMAC(HMAC(seed))+seed)
// [Min] ...
func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		copy(result[j:], b)
		j += len(b)

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

// prf10 implements the TLS 1.0 pseudo-random function, as defined in RFC 2246, section 5.
// [Min] 计算 prf10 伪随机数
func prf10(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New
	hashMD5 := md5.New

	// [Min] 合并 label 和 seed
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	// [Min] 将预备主密码拆分为两部分秘钥，以 labelAndSeed 为 seed，分别计算 MD5 和 SHA1的 HMAC
	s1, s2 := splitPreMasterSecret(secret)
	pHash(result, s1, labelAndSeed, hashMD5)
	result2 := make([]byte, len(result))
	pHash(result2, s2, labelAndSeed, hashSHA1)

	// [Min] 将两个 HMAC 异或，得出伪随机数
	for i, b := range result2 {
		result[i] ^= b
	}
}

// prf12 implements the TLS 1.2 pseudo-random function, as defined in RFC 5246, section 5.
// [Min] 返回计算 prf12 伪随机数的生成函数，和 prf10 相比，没有拆分，可以指定不同的 Hash 函数，直接调用 pHash
func prf12(hashFunc func() hash.Hash) func(result, secret, label, seed []byte) {
	return func(result, secret, label, seed []byte) {
		labelAndSeed := make([]byte, len(label)+len(seed))
		copy(labelAndSeed, label)
		copy(labelAndSeed[len(label):], seed)

		pHash(result, secret, labelAndSeed, hashFunc)
	}
}

// prf30 implements the SSL 3.0 pseudo-random function, as defined in
// www.mozilla.org/projects/security/pki/nss/ssl/draft302.txt section 6.
// [Min] 计算 prf30 伪随机数
func prf30(result, secret, label, seed []byte) {
	hashSHA1 := sha1.New()
	hashMD5 := md5.New()

	done := 0
	i := 0
	// RFC 5246 section 6.3 says that the largest PRF output needed is 128
	// bytes. Since no more ciphersuites will be added to SSLv3, this will
	// remain true. Each iteration gives us 16 bytes so 10 iterations will
	// be sufficient.
	var b [11]byte
	for done < len(result) {
		for j := 0; j <= i; j++ {
			b[j] = 'A' + byte(i)
		}

		hashSHA1.Reset()
		hashSHA1.Write(b[:i+1])
		hashSHA1.Write(secret)
		hashSHA1.Write(seed)
		digest := hashSHA1.Sum(nil)

		hashMD5.Reset()
		hashMD5.Write(secret)
		hashMD5.Write(digest)

		done += copy(result[done:], hashMD5.Sum(nil))
		i++
	}
}

const (
	tlsRandomLength      = 32 // Length of a random nonce in TLS 1.1.
	masterSecretLength   = 48 // Length of a master secret in TLS 1.1.
	finishedVerifyLength = 12 // Length of verify_data in a Finished message.
)

var masterSecretLabel = []byte("master secret")
var keyExpansionLabel = []byte("key expansion")
var clientFinishedLabel = []byte("client finished")
var serverFinishedLabel = []byte("server finished")

// [Min] 根据版本选择对应的伪随机数算法和 Hash 算法
func prfAndHashForVersion(version uint16, suite *cipherSuite) (func(result, secret, label, seed []byte), crypto.Hash) {
	switch version {
	case VersionSSL30:
		return prf30, crypto.Hash(0) // [Min] 0 是无效的 Hash，在 Go 标准库中并没有定义，因为 prf30 不能指定 Hash，这里就给了一个无效的值
	case VersionTLS10, VersionTLS11:
		return prf10, crypto.Hash(0) // [Min] 0 是无效的 Hash，在 Go 标准库中并没有定义，因为 prf10 不能指定 Hash，这里就给了一个无效的值
	case VersionTLS12:
		// [Min] 如果套件指定了SHA384算法，就使用SHA384，否则默认使用SHA256
		if suite.flags&suiteSHA384 != 0 {
			return prf12(sha512.New384), crypto.SHA384
		}
		return prf12(sha256.New), crypto.SHA256
	default:
		panic("unknown version")
	}
}

// [Min] 根据版本获取伪随机算法
func prfForVersion(version uint16, suite *cipherSuite) func(result, secret, label, seed []byte) {
	prf, _ := prfAndHashForVersion(version, suite)
	return prf
}

// masterFromPreMasterSecret generates the master secret from the pre-master
// secret. See http://tools.ietf.org/html/rfc5246#section-8.1
// [Min] 计算主密钥
func masterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret, clientRandom, serverRandom []byte) []byte {
	// [Min] 以 客户端随机数+服务端随机数 作为 seed
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	// [Min] 主密钥长度固定为48字节
	masterSecret := make([]byte, masterSecretLength)
	// [Min] 获取版本+套件对应的伪随机数算法，计算所得伪随机数即为主密钥
	prfForVersion(version, suite)(masterSecret, preMasterSecret, masterSecretLabel, seed)
	return masterSecret
}

// keysFromMasterSecret generates the connection keys from the master
// secret, given the lengths of the MAC key, cipher key and IV, as defined in
// RFC 2246, section 6.3.
// [Min] 通过主密钥生成与之相关的 clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV
func keysFromMasterSecret(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := make([]byte, n)
	prfForVersion(version, suite)(keyMaterial, masterSecret, keyExpansionLabel, seed)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

// lookupTLSHash looks up the corresponding crypto.Hash for a given
// hash from a TLS SignatureScheme.
// [Min] 根据签名算法，返回其中的运用的 hash 类型
func lookupTLSHash(signatureAlgorithm SignatureScheme) (crypto.Hash, error) {
	switch signatureAlgorithm {
	case PKCS1WithSHA1, ECDSAWithSHA1:
		return crypto.SHA1, nil
	case PKCS1WithSHA256, PSSWithSHA256, ECDSAWithP256AndSHA256:
		return crypto.SHA256, nil
	case PKCS1WithSHA384, PSSWithSHA384, ECDSAWithP384AndSHA384:
		return crypto.SHA384, nil
	case PKCS1WithSHA512, PSSWithSHA512, ECDSAWithP521AndSHA512:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("tls: unsupported signature algorithm: %#04x", signatureAlgorithm)
	}
}

// [Min] 根据版本和套件，构建一系列在处理 finishedMsg 时需要使用到的 hash 和伪随机数算法，以及缓存等
func newFinishedHash(version uint16, cipherSuite *cipherSuite) finishedHash {
	var buffer []byte
	if version == VersionSSL30 || version >= VersionTLS12 {
		buffer = []byte{}
	}

	// [Min] 根据版本和套件获得伪随机算法和 hash 类型，如果 hash 类型为0，说明 prf 的 hash 是固定的
	// [Min] 此时我们使用 sha1 作为 finishedMsg 的 hash 函数
	prf, hash := prfAndHashForVersion(version, cipherSuite)
	if hash != 0 {
		return finishedHash{hash.New(), hash.New(), nil, nil, buffer, version, prf}
	}

	return finishedHash{sha1.New(), sha1.New(), md5.New(), md5.New(), buffer, version, prf}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
// [Min] 处理 finishedMsg 时需要使用的一系列 hash和伪随机算法，以及缓存等
type finishedHash struct {
	client hash.Hash
	server hash.Hash

	// Prior to TLS 1.2, an additional MD5 hash is required.
	clientMD5 hash.Hash
	serverMD5 hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	buffer []byte

	version uint16
	prf     func(result, secret, label, seed []byte)
}

// [Min] 计算 msg 的 hash 并写入缓存（如果存在的话，SSL3.0, >= TLS 1.2)
func (h *finishedHash) Write(msg []byte) (n int, err error) {
	h.client.Write(msg)
	h.server.Write(msg)

	if h.version < VersionTLS12 {
		h.clientMD5.Write(msg)
		h.serverMD5.Write(msg)
	}

	if h.buffer != nil {
		h.buffer = append(h.buffer, msg...)
	}

	return len(msg), nil
}

// [Min] 结算 hash，作为计算 finshedMsg 中的 verifyData 时，调用 clientSum，serverSum 用的种子
func (h finishedHash) Sum() []byte {
	// [Min] 如果 >= TLS 1.2，直接结算 h.client
	// [Min] 否则，返回 h.clientMD5 + h.client，相当于返回 MD5 + SHA1
	if h.version >= VersionTLS12 {
		return h.client.Sum(nil)
	}

	out := make([]byte, 0, md5.Size+sha1.Size)
	out = h.clientMD5.Sum(out)
	return h.client.Sum(out)
}

// finishedSum30 calculates the contents of the verify_data member of a SSLv3
// Finished message given the MD5 and SHA1 hashes of a set of handshake
// messages.
// [Min] ssl3.0 特有的 sum，用于计算 finshedMsg 中的 verifyData
func finishedSum30(md5, sha1 hash.Hash, masterSecret []byte, magic []byte) []byte {
	md5.Write(magic)
	md5.Write(masterSecret)
	md5.Write(ssl30Pad1[:])
	md5Digest := md5.Sum(nil)

	md5.Reset()
	md5.Write(masterSecret)
	md5.Write(ssl30Pad2[:])
	md5.Write(md5Digest)
	md5Digest = md5.Sum(nil)

	sha1.Write(magic)
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad1[:40])
	sha1Digest := sha1.Sum(nil)

	sha1.Reset()
	sha1.Write(masterSecret)
	sha1.Write(ssl30Pad2[:40])
	sha1.Write(sha1Digest)
	sha1Digest = sha1.Sum(nil)

	ret := make([]byte, len(md5Digest)+len(sha1Digest))
	copy(ret, md5Digest)
	copy(ret[len(md5Digest):], sha1Digest)
	return ret
}

var ssl3ClientFinishedMagic = [4]byte{0x43, 0x4c, 0x4e, 0x54}
var ssl3ServerFinishedMagic = [4]byte{0x53, 0x52, 0x56, 0x52}

// clientSum returns the contents of the verify_data member of a client's
// Finished message.
// [Min] 计算客户端 finshedMsg 中的 verifyData
func (h finishedHash) clientSum(masterSecret []byte) []byte {
	if h.version == VersionSSL30 {
		return finishedSum30(h.clientMD5, h.client, masterSecret, ssl3ClientFinishedMagic[:])
	}

	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, clientFinishedLabel, h.Sum())
	return out
}

// serverSum returns the contents of the verify_data member of a server's
// Finished message.
// [Min] 计算服务端 finshedMsg 中的 verifyData
func (h finishedHash) serverSum(masterSecret []byte) []byte {
	if h.version == VersionSSL30 {
		return finishedSum30(h.serverMD5, h.server, masterSecret, ssl3ServerFinishedMagic[:])
	}

	out := make([]byte, finishedVerifyLength)
	h.prf(out, masterSecret, serverFinishedLabel, h.Sum())
	return out
}

// selectClientCertSignatureAlgorithm returns a SignatureScheme to sign a
// client's CertificateVerify with, or an error if none can be found.
// [Min] 签名类型是否满足服务端给出的列表中签名算法
func (h finishedHash) selectClientCertSignatureAlgorithm(serverList []SignatureScheme, sigType uint8) (SignatureScheme, error) {
	for _, v := range serverList {
		if signatureFromSignatureScheme(v) == sigType && isSupportedSignatureAlgorithm(v, supportedSignatureAlgorithms) {
			return v, nil
		}
	}
	return 0, errors.New("tls: no supported signature algorithm found for signing client certificate")
}

// hashForClientCertificate returns a digest, hash function, and TLS 1.2 hash
// id suitable for signing by a TLS client certificate.
// [Min] 计算 hash，用于后续以客户端证书私钥对该 hash 值进行签名，然后发送给服务端验证
func (h finishedHash) hashForClientCertificate(sigType uint8, signatureAlgorithm SignatureScheme, masterSecret []byte) ([]byte, crypto.Hash, error) {
	if (h.version == VersionSSL30 || h.version >= VersionTLS12) && h.buffer == nil {
		panic("a handshake hash for a client-certificate was requested after discarding the handshake buffer")
	}

	if h.version == VersionSSL30 {
		if sigType != signatureRSA {
			return nil, 0, errors.New("tls: unsupported signature type for client certificate")
		}

		md5Hash := md5.New()
		md5Hash.Write(h.buffer)
		sha1Hash := sha1.New()
		sha1Hash.Write(h.buffer)
		return finishedSum30(md5Hash, sha1Hash, masterSecret, nil), crypto.MD5SHA1, nil
	}
	if h.version >= VersionTLS12 {
		hashAlg, err := lookupTLSHash(signatureAlgorithm)
		if err != nil {
			return nil, 0, err
		}
		hash := hashAlg.New()
		hash.Write(h.buffer)
		return hash.Sum(nil), hashAlg, nil
	}

	if sigType == signatureECDSA {
		return h.server.Sum(nil), crypto.SHA1, nil
	}

	return h.Sum(), crypto.MD5SHA1, nil
}

// discardHandshakeBuffer is called when there is no more need to
// buffer the entirety of the handshake messages.
// [Min] 将 finshedHash 中的 buffer 置为 nil
func (h *finishedHash) discardHandshakeBuffer() {
	h.buffer = nil
}
