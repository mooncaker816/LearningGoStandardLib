// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"

	"golang_org/x/crypto/curve25519"
)

var errClientKeyExchange = errors.New("tls: invalid ClientKeyExchange message")
var errServerKeyExchange = errors.New("tls: invalid ServerKeyExchange message")

// rsaKeyAgreement implements the standard TLS key agreement where the client
// encrypts the pre-master secret to the server's public key.
type rsaKeyAgreement struct{}

// [Min] RSA 无需秘钥交换，公钥直接从证书中获取
func (ka rsaKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, nil
}

// [Min] RSA 服务端以私钥解密预备主密钥的密文，得到预备主密钥
func (ka rsaKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}

	ciphertext := ckx.ciphertext
	if version != VersionSSL30 {
		ciphertextLen := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
		if ciphertextLen != len(ckx.ciphertext)-2 {
			return nil, errClientKeyExchange
		}
		ciphertext = ckx.ciphertext[2:]
	}
	priv, ok := cert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Decrypter")
	}
	// Perform constant time RSA PKCS#1 v1.5 decryption
	preMasterSecret, err := priv.Decrypt(config.rand(), ciphertext, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 48})
	if err != nil {
		return nil, err
	}
	// We don't check the version number in the premaster secret. For one,
	// by checking it, we would leak information about the validity of the
	// encrypted pre-master secret. Secondly, it provides only a small
	// benefit against a downgrade attack and some implementations send the
	// wrong version anyway. See the discussion at the end of section
	// 7.4.7.1 of RFC 4346.
	return preMasterSecret, nil
}

// [Min] RSA 无需 ServerKeyExchange，公钥直接从证书中获取
func (ka rsaKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	return errors.New("tls: unexpected ServerKeyExchange")
}

// [Min] RSA 客户端随机生成预备主密钥，用服务端证书中的公钥加密，写入 clientKeyExchangeMsg
func (ka rsaKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	// [Min] 48自己的预备主密钥，头两位是版本值，后面是46字节随机数
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}

	// [Min] 用服务端证书中的公钥加密预备主密钥
	encrypted, err := rsa.EncryptPKCS1v15(config.rand(), cert.PublicKey.(*rsa.PublicKey), preMasterSecret)
	if err != nil {
		return nil, nil, err
	}
	// [Min] 构造 clientKeyExchangeMsg ： 预备主密钥长度 + 预备主密钥密文
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(len(encrypted) >> 8)
	ckx.ciphertext[1] = byte(len(encrypted))
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}

// sha1Hash calculates a SHA1 hash over the given byte slices.
// [Min] 计算sha1
func sha1Hash(slices [][]byte) []byte {
	hsha1 := sha1.New()
	for _, slice := range slices {
		hsha1.Write(slice)
	}
	return hsha1.Sum(nil)
}

// md5SHA1Hash implements TLS 1.0's hybrid hash function which consists of the
// concatenation of an MD5 and SHA1 hash.
// [Min] 同时计算 md5和 sha1，最后返回 md5 + sha1
func md5SHA1Hash(slices [][]byte) []byte {
	md5sha1 := make([]byte, md5.Size+sha1.Size)
	hmd5 := md5.New()
	for _, slice := range slices {
		hmd5.Write(slice)
	}
	copy(md5sha1, hmd5.Sum(nil))
	copy(md5sha1[md5.Size:], sha1Hash(slices))
	return md5sha1
}

// hashForServerKeyExchange hashes the given slices and returns their digest
// and the identifier of the hash function used. The signatureAlgorithm argument
// is only used for >= TLS 1.2 and identifies the hash function to use.
// [Min] 采用与签名算法相同的 hash 函数计算 hash，并返回相应的 hash 类型
func hashForServerKeyExchange(sigType uint8, signatureAlgorithm SignatureScheme, version uint16, slices ...[]byte) ([]byte, crypto.Hash, error) {
	if version >= VersionTLS12 {
		if !isSupportedSignatureAlgorithm(signatureAlgorithm, supportedSignatureAlgorithms) {
			return nil, crypto.Hash(0), errors.New("tls: unsupported hash function used by peer")
		}
		// [Min] 获取签名算法中的 hash 类型
		hashFunc, err := lookupTLSHash(signatureAlgorithm)
		if err != nil {
			return nil, crypto.Hash(0), err
		}
		h := hashFunc.New()
		// [Min] 计算该类型的 hash
		for _, slice := range slices {
			h.Write(slice)
		}
		digest := h.Sum(nil)
		// [Min] 返回 hash 值 和 hash 类型
		return digest, hashFunc, nil
	}
	// [Min] TLS1.2 以下，且是基于椭圆曲线的签名算法，计算 sha1
	if sigType == signatureECDSA {
		return sha1Hash(slices), crypto.SHA1, nil
	}
	// [Min] 其他计算 md5和 sha1的结合 hash
	return md5SHA1Hash(slices), crypto.MD5SHA1, nil
}

// pickTLS12HashForSignature returns a TLS 1.2 hash identifier for signing a
// ServerKeyExchange given the signature type being used and the client's
// advertised list of supported signature and hash combinations.
// [Min] 根据签名算法选择实现签名算法的具体方案，如 RSA 算法的 PKCS1WithSHA1等
func pickTLS12HashForSignature(sigType uint8, clientList []SignatureScheme) (SignatureScheme, error) {
	if len(clientList) == 0 {
		// If the client didn't specify any signature_algorithms
		// extension then we can assume that it supports SHA1. See
		// http://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
		switch sigType {
		case signatureRSA:
			return PKCS1WithSHA1, nil
		case signatureECDSA:
			return ECDSAWithSHA1, nil
		default:
			return 0, errors.New("tls: unknown signature algorithm")
		}
	}

	// [Min] 从客户提供的支持清单中选出对应的算法，并判断服务器是否支持，支持就返回
	for _, sigAlg := range clientList {
		if signatureFromSignatureScheme(sigAlg) != sigType {
			continue
		}
		if isSupportedSignatureAlgorithm(sigAlg, supportedSignatureAlgorithms) {
			return sigAlg, nil
		}
	}

	return 0, errors.New("tls: client doesn't support any common hash functions")
}

// [Min] 根据 CurveID 获取对应的曲线
func curveForCurveID(id CurveID) (elliptic.Curve, bool) {
	switch id {
	case CurveP256:
		return elliptic.P256(), true
	case CurveP384:
		return elliptic.P384(), true
	case CurveP521:
		return elliptic.P521(), true
	default:
		return nil, false
	}

}

// ecdheRSAKeyAgreement implements a TLS key agreement where the server
// generates an ephemeral EC public/private key pair and signs it. The
// pre-master secret is then calculated using ECDH. The signature may
// either be ECDSA or RSA.
type ecdheKeyAgreement struct {
	version    uint16
	sigType    uint8
	privateKey []byte
	curveid    CurveID

	// publicKey is used to store the peer's public value when X25519 is
	// being used.
	publicKey []byte
	// x and y are used to store the peer's public value when one of the
	// NIST curves is being used.
	x, y *big.Int
}

// [Min] 基于椭圆曲线的秘钥交换，生成需要交换的公钥，待验证的签名，
// [Min] 存入 serverKeyExchangeMsg 返回
func (ka *ecdheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	// [Min] 首先获取支持的椭圆曲线
	preferredCurves := config.curvePreferences()

	// [Min] 优先从服务端选出双方都支持的椭圆曲线，更新 ka.curveid
NextCandidate:
	for _, candidate := range preferredCurves {
		for _, c := range clientHello.supportedCurves {
			if candidate == c {
				ka.curveid = c
				break NextCandidate
			}
		}
	}

	if ka.curveid == 0 {
		return nil, errors.New("tls: no supported elliptic curves offered")
	}

	var ecdhePublic []byte

	if ka.curveid == X25519 {
		var scalar, public [32]byte
		if _, err := io.ReadFull(config.rand(), scalar[:]); err != nil {
			return nil, err
		}

		curve25519.ScalarBaseMult(&public, &scalar)
		ka.privateKey = scalar[:]
		ecdhePublic = public[:]
	} else {
		// [Min] 获取曲线，公钥基点也就确定了
		curve, ok := curveForCurveID(ka.curveid)
		if !ok {
			return nil, errors.New("tls: preferredCurves includes unsupported curve")
		}

		var x, y *big.Int
		var err error
		// [Min] 生成随机私钥 ka.privateKey，并生成公钥点（x，y）（基点的私钥倍）
		ka.privateKey, x, y, err = elliptic.GenerateKey(curve, config.rand())
		if err != nil {
			return nil, err
		}
		// [Min] 序列化公钥信息
		ecdhePublic = elliptic.Marshal(curve, x, y)
	}

	// http://tools.ietf.org/html/rfc4492#section-5.4
	serverECDHParams := make([]byte, 1+2+1+len(ecdhePublic))
	serverECDHParams[0] = 3 // named curve
	serverECDHParams[1] = byte(ka.curveid >> 8)
	serverECDHParams[2] = byte(ka.curveid)
	serverECDHParams[3] = byte(len(ecdhePublic))
	copy(serverECDHParams[4:], ecdhePublic)

	var signatureAlgorithm SignatureScheme

	if ka.version >= VersionTLS12 {
		var err error
		signatureAlgorithm, err = pickTLS12HashForSignature(ka.sigType, clientHello.supportedSignatureAlgorithms)
		if err != nil {
			return nil, err
		}
	}
	// [Min] 计算客户端随机数，服务端随机数，公钥信息serverECDHParams的 hash 值
	digest, hashFunc, err := hashForServerKeyExchange(ka.sigType, signatureAlgorithm, ka.version, clientHello.random, hello.random, serverECDHParams)
	if err != nil {
		return nil, err
	}

	// [Min] 验证证书的私钥可用于签名
	priv, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Signer")
	}
	var sig []byte
	// [Min] 验证证书的公钥与套件中对应的签名算法一致
	switch ka.sigType {
	case signatureECDSA:
		_, ok := priv.Public().(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("tls: ECDHE ECDSA requires an ECDSA server key")
		}
	case signatureRSA:
		_, ok := priv.Public().(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("tls: ECDHE RSA requires a RSA server key")
		}
	default:
		return nil, errors.New("tls: unknown ECDHE signature algorithm")
	}
	// [Min] 对上述 digest 用私钥进行签名
	sig, err = priv.Sign(config.rand(), digest, hashFunc)
	if err != nil {
		return nil, errors.New("tls: failed to sign ECDHE parameters: " + err.Error())
	}

	// [Min] 构造 serverKeyExchangeMsg：serverECDHParams + signatureAlgorithm（>= TLS 1.2） + 签名长度 + 签名
	skx := new(serverKeyExchangeMsg)
	sigAndHashLen := 0
	if ka.version >= VersionTLS12 {
		sigAndHashLen = 2
	}
	skx.key = make([]byte, len(serverECDHParams)+sigAndHashLen+2+len(sig))
	copy(skx.key, serverECDHParams)
	k := skx.key[len(serverECDHParams):]
	if ka.version >= VersionTLS12 {
		k[0] = byte(signatureAlgorithm >> 8)
		k[1] = byte(signatureAlgorithm)
		k = k[2:]
	}
	k[0] = byte(len(sig) >> 8)
	k[1] = byte(len(sig))
	copy(k[2:], sig)

	return skx, nil
}

// [Min] 收到客户端交换秘钥后计算预备主密钥
func (ka *ecdheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) == 0 || int(ckx.ciphertext[0]) != len(ckx.ciphertext)-1 {
		return nil, errClientKeyExchange
	}

	if ka.curveid == X25519 {
		if len(ckx.ciphertext) != 1+32 {
			return nil, errClientKeyExchange
		}

		var theirPublic, sharedKey, scalar [32]byte
		copy(theirPublic[:], ckx.ciphertext[1:])
		copy(scalar[:], ka.privateKey)
		curve25519.ScalarMult(&sharedKey, &scalar, &theirPublic)
		return sharedKey[:], nil
	}

	// [Min] 获取曲线
	curve, ok := curveForCurveID(ka.curveid)
	if !ok {
		panic("internal error")
	}
	// [Min] 头一位是长度，反序列化后续公钥信息，得到客户端公钥点（x，y）
	x, y := elliptic.Unmarshal(curve, ckx.ciphertext[1:]) // Unmarshal also checks whether the given point is on the curve
	if x == nil {
		return nil, errClientKeyExchange
	}
	// [Min] 客户端公钥点（x,y）的 ka.privateKey 倍即为共享密钥点
	x, _ = curve.ScalarMult(x, y, ka.privateKey)
	// [Min] 共享秘钥点的 x 坐标值就是预备主密钥，填不满前面补0
	preMasterSecret := make([]byte, (curve.Params().BitSize+7)>>3)
	xBytes := x.Bytes()
	copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

	return preMasterSecret, nil
}

// [Min] 客户端收到服务端秘钥交换信息后的处理，获得服务端公钥更新到 ka.x,ka.y 或者 ka.publicKey ，再验证签名
func (ka *ecdheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	if len(skx.key) < 4 {
		return errServerKeyExchange
	}
	if skx.key[0] != 3 { // named curve
		return errors.New("tls: server selected unsupported curve")
	}
	// [Min] 从消息中提取出 curveid
	ka.curveid = CurveID(skx.key[1])<<8 | CurveID(skx.key[2])

	// [Min] 公钥信息长度
	publicLen := int(skx.key[3])
	if publicLen+4 > len(skx.key) {
		return errServerKeyExchange
	}
	// [Min] 公钥信息的序列化流
	serverECDHParams := skx.key[:4+publicLen]
	publicKey := serverECDHParams[4:]

	// [Min] 如果是 >= TLS 1.2, sig 的头两位是具体的签名算法类型值，后面才是签名的长度+真正的签名
	// [Min] 服务端用私钥对 客户端随机数，服务端随机数，公钥信息serverECDHParams的 hash 值进行的签名
	// [Min] hash 与签名算法保持一致（>= TLS 1.2),或者为 SHA1，MD5SHA1（RSA 签名）
	sig := skx.key[4+publicLen:]
	if len(sig) < 2 {
		return errServerKeyExchange
	}

	if ka.curveid == X25519 {
		if len(publicKey) != 32 {
			return errors.New("tls: bad X25519 public value")
		}
		ka.publicKey = publicKey
	} else {
		// [Min] 获取 curve
		curve, ok := curveForCurveID(ka.curveid)
		if !ok {
			return errors.New("tls: server selected unsupported curve")
		}
		// [Min] 反序列化得到公钥信息
		ka.x, ka.y = elliptic.Unmarshal(curve, publicKey) // Unmarshal also checks whether the given point is on the curve
		if ka.x == nil {
			return errServerKeyExchange
		}
	}

	var signatureAlgorithm SignatureScheme

	// [Min] >= TLS1.2时，头两位为签名算法，判断是否与套件中的一致
	if ka.version >= VersionTLS12 {
		// handle SignatureAndHashAlgorithm
		signatureAlgorithm = SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])
		if signatureFromSignatureScheme(signatureAlgorithm) != ka.sigType {
			return errServerKeyExchange
		}
		sig = sig[2:]
		if len(sig) < 2 {
			return errServerKeyExchange
		}
	}
	// [Min] 签名的长度
	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errServerKeyExchange
	}
	// [Min] 真正的签名
	sig = sig[2:]

	// [Min] 与服务端计算同样的 hash
	digest, hashFunc, err := hashForServerKeyExchange(ka.sigType, signatureAlgorithm, ka.version, clientHello.random, serverHello.random, serverECDHParams)
	if err != nil {
		return err
	}
	// [Min] 验证签名
	switch ka.sigType {
	case signatureECDSA:
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("tls: ECDHE ECDSA requires a ECDSA server public key")
		}
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return err
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return errors.New("tls: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pubKey, digest, ecdsaSig.R, ecdsaSig.S) {
			return errors.New("tls: ECDSA verification failure")
		}
	case signatureRSA:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("tls: ECDHE RSA requires a RSA server public key")
		}
		if err := rsa.VerifyPKCS1v15(pubKey, hashFunc, digest, sig); err != nil {
			return err
		}
	default:
		return errors.New("tls: unknown ECDHE signature algorithm")
	}

	return nil
}

// [Min] ECDHE 客户端生成预备主密钥，交换秘钥的公钥信息，以及 clientKeyExchangeMsg
func (ka *ecdheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.curveid == 0 {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}

	var serialized, preMasterSecret []byte

	if ka.curveid == X25519 {
		var ourPublic, theirPublic, sharedKey, scalar [32]byte

		if _, err := io.ReadFull(config.rand(), scalar[:]); err != nil {
			return nil, nil, err
		}

		copy(theirPublic[:], ka.publicKey)
		curve25519.ScalarBaseMult(&ourPublic, &scalar)
		curve25519.ScalarMult(&sharedKey, &scalar, &theirPublic)
		serialized = ourPublic[:]
		preMasterSecret = sharedKey[:]
	} else {
		curve, ok := curveForCurveID(ka.curveid)
		if !ok {
			panic("internal error")
		}
		// [Min] 生成随机私钥 priv，并生成客户端的公钥点（mx，my）（基点的私钥倍）
		priv, mx, my, err := elliptic.GenerateKey(curve, config.rand())
		if err != nil {
			return nil, nil, err
		}
		// [Min] ka.x , ka.y 是服务端的公钥点，再乘以客户端的私钥就是共享秘钥点
		x, _ := curve.ScalarMult(ka.x, ka.y, priv)
		// [Min] 和私钥 priv 一样长
		preMasterSecret = make([]byte, (curve.Params().BitSize+7)>>3)
		xBytes := x.Bytes()
		// [Min] 将共享秘钥点的 x 坐标的值作为预备主密钥，填不满前面补零
		copy(preMasterSecret[len(preMasterSecret)-len(xBytes):], xBytes)

		// [Min] 序列化客户端公钥信息
		serialized = elliptic.Marshal(curve, mx, my)
	}

	// [Min] 构造 clientKeyExchangeMsg：公钥信息长度 + 公钥信息序列化流
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, 1+len(serialized))
	ckx.ciphertext[0] = byte(len(serialized))
	copy(ckx.ciphertext[1:], serialized)

	return preMasterSecret, ckx, nil
}
