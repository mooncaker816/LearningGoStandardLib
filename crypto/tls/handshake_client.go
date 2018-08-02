// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

type clientHandshakeState struct {
	c            *Conn
	serverHello  *serverHelloMsg
	hello        *clientHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
	session      *ClientSessionState
}

// [Min] 构造clientHelloMsg
func makeClientHello(config *Config) (*clientHelloMsg, error) {
	// [Min] config中的ServerName不能为空，除非客户端不需要验证服务端的证书
	// [Min] 一般只有在测试的时候才会设置 config.InsecureSkipVerify 为真
	// [Min] 服务端需要根据客户端提供的 ServerName 来选择合适的证书返还给客户端验证
	if len(config.ServerName) == 0 && !config.InsecureSkipVerify {
		return nil, errors.New("tls: either ServerName or InsecureSkipVerify must be specified in the tls.Config")
	}

	// [Min] 检查 config 中的 NextProtos
	nextProtosLength := 0
	for _, proto := range config.NextProtos {
		if l := len(proto); l == 0 || l > 255 {
			return nil, errors.New("tls: invalid NextProtos value")
		} else {
			nextProtosLength += 1 + l
		}
	}

	if nextProtosLength > 0xffff {
		return nil, errors.New("tls: NextProtos values too large")
	}

	// [Min] 初始化 clientHelloMsg
	hello := &clientHelloMsg{
		vers:                         config.maxVersion(),              // [Min] 默认选用 config 中的最大版本号
		compressionMethods:           []uint8{compressionNone},         // [Min] Go 只支持 compressionNone
		random:                       make([]byte, 32),                 // [Min] 客户端随机数
		ocspStapling:                 true,                             // [Min] 要求服务端提供证书状态
		scts:                         true,                             // [Min] 要求服务端提供 hs.cert.SignedCertificateTimestamps
		serverName:                   hostnameInSNI(config.ServerName), // [Min] 对 ServerNmae 进行标准化处理
		supportedCurves:              config.curvePreferences(),        // [Min] 客户端支持的椭圆曲线
		supportedPoints:              []uint8{pointFormatUncompressed}, // [Min] Go 只支持 pointFormatUncompressed
		nextProtoNeg:                 len(config.NextProtos) > 0,       // [Min] NPN 模式，让服务端返回支持的协议，客户端选择，Go 会优先采用 ALPN 模式
		secureRenegotiationSupported: true,                             // [Min] 是否支持安全重协商
		alpnProtocols:                config.NextProtos,                // [Min] ALPN 模式，客户端提供协议，服务端选择
	}
	// [Min] 更新客户端可用的密码套件 hello.cipherSuites
	// [Min] possibleCipherSuites 可能是default cipherSuites，也可能是指定的cipherSuites
	// [Min] 首先hello的可选cipherSuites必须在possibleCipherSuites里选出，且必须是Go 标准库支持的密码套件cipherSuites
	possibleCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(possibleCipherSuites))

NextCipherSuite:
	for _, suiteId := range possibleCipherSuites {
		for _, suite := range cipherSuites {
			if suite.id != suiteId {
				continue
			}
			// Don't advertise TLS 1.2-only cipher suites unless
			// we're attempting TLS 1.2.
			// [Min] 版本和套件的 flag 要一致
			if hello.vers < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
				continue
			}
			hello.cipherSuites = append(hello.cipherSuites, suiteId)
			continue NextCipherSuite
		}
	}

	// [Min] 设置客户端32字节随机数
	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// [Min] 设置客户端支持的签名算法
	if hello.vers >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms
	}

	return hello, nil
}

// c.out.Mutex <= L; c.handshakeMutex <= L.
// [Min] 客户端handshake
func (c *Conn) clientHandshake() error {
	// [Min] 如果 config 为 nil，先配置config，默认为空的config（零值）
	if c.config == nil {
		c.config = defaultConfig()
	}

	// This may be a renegotiation handshake, in which case some fields
	// need to be reset.
	c.didResume = false

	// [Min] 根据config构造clientHelloMsg
	hello, err := makeClientHello(c.config)
	if err != nil {
		return err
	}

	// [Min] 如果不是首次握手，将上一次结束信息 c.clientFinished 赋给 secureRenegotiation
	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	// [Min] 开始检查复用 Session 的可能
	var session *ClientSessionState
	var cacheKey string
	// [Min] 首先获取 config 中的 ClientSessionCache，如果不支持重用，seesionCache 设置为 nil
	sessionCache := c.config.ClientSessionCache
	if c.config.SessionTicketsDisabled {
		sessionCache = nil
	}

	// [Min] 如果此时 sessionCache 不为 nil，说明可以支持重用 session，设置 hello.ticketSupported 为真
	if sessionCache != nil {
		hello.ticketSupported = true
	}

	// Session resumption is not allowed if renegotiating because
	// renegotiation is primarily used to allow a client to send a client
	// certificate, which would be skipped if session resumption occurred.
	// [Min] 只有首次握手才能重用
	if sessionCache != nil && c.handshakes == 0 {
		// Try to resume a previously negotiated TLS session, if
		// available.
		// [Min] 根据ServerName 或服务器地址获取 sessioncachekey
		cacheKey = clientSessionCacheKey(c.conn.RemoteAddr(), c.config)
		// [Min] 从 sessionCache 中获取该 session
		candidateSession, ok := sessionCache.Get(cacheKey)
		if ok {
			// Check that the ciphersuite/version used for the
			// previous session are still valid.
			// [Min] 如果找到了，再次检查该 session 使用的密码套件是否在客户端的支持列表中
			cipherSuiteOk := false
			for _, id := range hello.cipherSuites {
				if id == candidateSession.cipherSuite {
					cipherSuiteOk = true
					break
				}
			}

			// [Min] 检查该 session 使用的版本是否有效
			versOk := candidateSession.vers >= c.config.minVersion() &&
				candidateSession.vers <= c.config.maxVersion()
			if versOk && cipherSuiteOk {
				session = candidateSession
			}
		}
	}

	// [Min] 如果 session 可用，将 session.sessionTicket 赋值给 hello.sessionTicket
	if session != nil {
		hello.sessionTicket = session.sessionTicket
		// A random session ID is used to detect when the
		// server accepted the ticket and is resuming a session
		// (see RFC 5077).
		// [Min] 同时新建一个16字节的随机数作为该重用 session 的 id
		hello.sessionId = make([]byte, 16)
		if _, err := io.ReadFull(c.config.rand(), hello.sessionId); err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	// [Min] 构造 clientHandshakeState
	hs := &clientHandshakeState{
		c:       c,       // [Min] TLS Conn
		hello:   hello,   // [Min] clientHelloMsg
		session: session, // [Min] 重用 session
	}

	// [Min] 调用 clientHandshakeState.handshake，真正开始 handshake
	if err = hs.handshake(); err != nil {
		return err
	}

	// If we had a successful handshake and hs.session is different from
	// the one already cached - cache a new one
	// [Min] 如果 handshake 成功后，返回的 hs.session 与之前的不同，将新的 hs.session 存入缓存中，cacheKey 不变
	if sessionCache != nil && hs.session != nil && session != hs.session {
		sessionCache.Put(cacheKey, hs.session)
	}

	return nil
}

// Does the handshake, either a full one or resumes old session.
// Requires hs.c, hs.hello, and, optionally, hs.session to be set.
func (hs *clientHandshakeState) handshake() error {
	c := hs.c

	// send ClientHello
	// [Min] 明文写入 clientHelloMsg，直接推送到服务端，没有走c.sendBuf
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	// [Min] 读取 handshake 的返回消息，并构建对应类型的消息体实例 msg
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	var ok bool
	// [Min] 期待返回的是 serverHelloMsg
	if hs.serverHello, ok = msg.(*serverHelloMsg); !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(hs.serverHello, msg)
	}

	// [Min] 选择 TLS 版本，设置 hs.c.vers，hs.c.haveVers
	if err = hs.pickTLSVersion(); err != nil {
		return err
	}

	// [Min] 选择加密套件，设置 hs.c.cipherSuite
	if err = hs.pickCipherSuite(); err != nil {
		return err
	}

	// [Min] 处理 SeverHelloMsg，并决定是否重用 session
	isResume, err := hs.processServerHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(c.vers, hs.suite)

	// No signatures of the handshake are needed in a resumption.
	// Otherwise, in a full handshake, if we don't have any certificates
	// configured then we will never send a CertificateVerify message and
	// thus no signatures are needed in that case either.
	if isResume || (len(c.config.Certificates) == 0 && c.config.GetClientCertificate == nil) {
		hs.finishedHash.discardHandshakeBuffer()
	}

	hs.finishedHash.Write(hs.hello.marshal())
	hs.finishedHash.Write(hs.serverHello.marshal())

	c.buffering = true
	if isResume {
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	} else {
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.sendFinished(c.clientFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		if err := hs.readSessionTicket(); err != nil {
			return err
		}
		if err := hs.readFinished(c.serverFinished[:]); err != nil {
			return err
		}
	}

	c.didResume = isResume
	c.handshakeComplete = true

	return nil
}

// [Min] 匹配对应的 TLS 版本，更新到 hs.c.vers，hs.c.haveVers
func (hs *clientHandshakeState) pickTLSVersion() error {
	vers, ok := hs.c.config.mutualVersion(hs.serverHello.vers)
	if !ok || vers < VersionTLS10 {
		// TLS 1.0 is the minimum version supported as a client.
		hs.c.sendAlert(alertProtocolVersion)
		return fmt.Errorf("tls: server selected unsupported protocol version %x", hs.serverHello.vers)
	}

	hs.c.vers = vers
	hs.c.haveVers = true

	return nil
}

// [Min] 匹配加密套件，更新 hs.c.cipherSuite
func (hs *clientHandshakeState) pickCipherSuite() error {
	if hs.suite = mutualCipherSuite(hs.hello.cipherSuites, hs.serverHello.cipherSuite); hs.suite == nil {
		hs.c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server chose an unconfigured cipher suite")
	}

	hs.c.cipherSuite = hs.suite.id
	return nil
}

// [Min] 客户端 fullhandshake
func (hs *clientHandshakeState) doFullHandshake() error {
	c := hs.c

	// [Min] 期待收到服务端的证书信息，证书必须存在且不为空
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	certMsg, ok := msg.(*certificateMsg)
	if !ok || len(certMsg.certificates) == 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(certMsg, msg)
	}
	// [Min] 累计计算 hash
	hs.finishedHash.Write(certMsg.marshal())

	if c.handshakes == 0 {
		// [Min] 如果是初次握手，解析证书
		// If this is the first handshake on a connection, process and
		// (optionally) verify the server's certificates.
		certs := make([]*x509.Certificate, len(certMsg.certificates))
		for i, asn1Data := range certMsg.certificates {
			cert, err := x509.ParseCertificate(asn1Data)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return errors.New("tls: failed to parse certificate from server: " + err.Error())
			}
			certs[i] = cert
		}

		// [Min] 如果不是跳过验证，对证书进行验证，并更新 c.verifiedChains，c.peerCertificates
		if !c.config.InsecureSkipVerify {
			opts := x509.VerifyOptions{
				Roots:         c.config.RootCAs,
				CurrentTime:   c.config.time(),
				DNSName:       c.config.ServerName,
				Intermediates: x509.NewCertPool(),
			}

			for i, cert := range certs {
				if i == 0 {
					continue
				}
				opts.Intermediates.AddCert(cert)
			}
			c.verifiedChains, err = certs[0].Verify(opts)
			if err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}

		// [Min] 自定义的验证
		if c.config.VerifyPeerCertificate != nil {
			if err := c.config.VerifyPeerCertificate(certMsg.certificates, c.verifiedChains); err != nil {
				c.sendAlert(alertBadCertificate)
				return err
			}
		}

		switch certs[0].PublicKey.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			break
		default:
			c.sendAlert(alertUnsupportedCertificate)
			return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
		}

		c.peerCertificates = certs
	} else {
		// [Min] 不是首次握手，需确保服务端的证书没有改变
		// This is a renegotiation handshake. We require that the
		// server's identity (i.e. leaf certificate) is unchanged and
		// thus any previous trust decision is still valid.
		//
		// See https://mitls.org/pages/attacks/3SHAKE for the
		// motivation behind this requirement.
		if !bytes.Equal(c.peerCertificates[0].Raw, certMsg.certificates[0]) {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: server's identity changed during renegotiation")
		}
	}

	// [Min] 再次读取 handshake 的 msg，此时有可能是客户端主动要求服务端发送的 certificateStatusMsg
	msg, err = c.readHandshake()
	if err != nil {
		return err
	}

	cs, ok := msg.(*certificateStatusMsg)
	if ok {
		// RFC4366 on Certificate Status Request:
		// The server MAY return a "certificate_status" message.

		// [Min] 如果服务端ocspStapling标记为假，但收到了certificateStatusMsg，报警
		if !hs.serverHello.ocspStapling {
			// If a server returns a "CertificateStatus" message, then the
			// server MUST have included an extension of type "status_request"
			// with empty "extension_data" in the extended server hello.

			c.sendAlert(alertUnexpectedMessage)
			return errors.New("tls: received unexpected CertificateStatus message")
		}
		// [Min] 累计计算 hash，并置 c.ocspResponse = cs.response
		hs.finishedHash.Write(cs.marshal())

		if cs.statusType == statusTypeOCSP {
			c.ocspResponse = cs.response
		}

		// [Min] 读取下一条 handshake 消息
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	// [Min] 可能是 serverKeyExchangeMsg，如果采用的是 RSA 交换秘钥的模式，没有 serverKeyExchangeMsg
	keyAgreement := hs.suite.ka(c.vers)

	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		// [Min] 如果是 serverKeyExchangeMsg，先累计计算 hash，再处理
		hs.finishedHash.Write(skx.marshal())
		// [Min] 从 serverKeyExchangeMs 获取服务端公钥，并验证签名
		err = keyAgreement.processServerKeyExchange(c.config, hs.hello, hs.serverHello, c.peerCertificates[0], skx)
		if err != nil {
			c.sendAlert(alertUnexpectedMessage)
			return err
		}

		// [Min] 读取下一条消息
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	var chainToSend *Certificate
	var certRequested bool
	certReq, ok := msg.(*certificateRequestMsg)
	// [Min] 此时可能是服务端要求客户端发送证书的请求消息
	if ok {
		certRequested = true
		// [Min] 累计计算 hash
		hs.finishedHash.Write(certReq.marshal())

		// [Min] 根据要求获取客户端的证书
		if chainToSend, err = hs.getCertificate(certReq); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		// [Min] 读取下一条消息
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	// [Min] 应该是 HelloDone 消息
	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}
	// [Min] 累计 hash
	hs.finishedHash.Write(shd.marshal())

	// If the server requested a certificate then we have to send a
	// Certificate message, even if it's empty because we don't have a
	// certificate to send.
	// [Min] 发送客户端证书信息
	if certRequested {
		certMsg = new(certificateMsg)
		certMsg.certificates = chainToSend.Certificate
		hs.finishedHash.Write(certMsg.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
			return err
		}
	}

	// [Min] 构造客户端秘钥交换消息，由于已经收到服务端的公钥信息，所以同时可以生成预备主密钥了
	preMasterSecret, ckx, err := keyAgreement.generateClientKeyExchange(c.config, hs.hello, c.peerCertificates[0])
	if err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	// [Min] 累计计算 hash，并将 clientKeyExchangeMsg 写入 conn 缓存
	if ckx != nil {
		hs.finishedHash.Write(ckx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, ckx.marshal()); err != nil {
			return err
		}
	}

	// [Min] 如果发送了证书给服务端，那么也要发送签名让服务端验证
	if chainToSend != nil && len(chainToSend.Certificate) > 0 {
		certVerify := &certificateVerifyMsg{
			hasSignatureAndHash: c.vers >= VersionTLS12,
		}

		// [Min] 证书支持签名
		key, ok := chainToSend.PrivateKey.(crypto.Signer)
		if !ok {
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: client certificate private key of type %T does not implement crypto.Signer", chainToSend.PrivateKey)
		}

		// [Min] 证书的签名类型，RSA 或 ECDSA
		var signatureType uint8
		switch key.Public().(type) {
		case *ecdsa.PublicKey:
			signatureType = signatureECDSA
		case *rsa.PublicKey:
			signatureType = signatureRSA
		default:
			c.sendAlert(alertInternalError)
			return fmt.Errorf("tls: failed to sign handshake with client certificate: unknown client certificate key type: %T", key)
		}

		// SignatureAndHashAlgorithm was introduced in TLS 1.2.
		if certVerify.hasSignatureAndHash {
			// [Min] 以证书的签名类型为基准，获取一种符合服务端要求的签名算法
			certVerify.signatureAlgorithm, err = hs.finishedHash.selectClientCertSignatureAlgorithm(certReq.supportedSignatureAlgorithms, signatureType)
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
		}
		// [Min] 计算 hash
		digest, hashFunc, err := hs.finishedHash.hashForClientCertificate(signatureType, certVerify.signatureAlgorithm, hs.masterSecret)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		// [Min] 对上述 hash 值以私钥采用同样的 hash 函数进行签名
		certVerify.signature, err = key.Sign(c.config.rand(), digest, hashFunc)
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}

		// [Min] 累计计算 hash，将 certificateVerifyMsg 写入 conn 缓存
		hs.finishedHash.Write(certVerify.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certVerify.marshal()); err != nil {
			return err
		}
	}

	// [Min] 根据预备主密钥，客户端随机数，服务端随机数，计算主密钥
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.random)
	// [Min] 一般测试用
	if err := c.config.writeKeyLog(hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}

	// [Min] 清空 finishedHash 中的 buffer
	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *clientHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.hello.random, hs.serverHello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

// [Min] 是否重用 session，客户端和服务端的 sessionId 要一致
func (hs *clientHandshakeState) serverResumedSession() bool {
	// If the server responded with the same sessionId then it means the
	// sessionTicket is being used to resume a TLS session.
	return hs.session != nil && hs.hello.sessionId != nil &&
		bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId)
}

// [Min] 处理 SeverHelloMsg，检查相应的返回是否有效，支持，更新对应的字段到 TLS.Conn 中
func (hs *clientHandshakeState) processServerHello() (bool, error) {
	c := hs.c

	// [Min] Go 只支持非压缩
	if hs.serverHello.compressionMethod != compressionNone {
		c.sendAlert(alertUnexpectedMessage)
		return false, errors.New("tls: server selected unsupported compression format")
	}

	// [Min] 首次握手secureRenegotiation必须为空
	if c.handshakes == 0 && hs.serverHello.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.serverHello.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
	}

	// [Min] 安全重协商的检查
	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.clientFinished[:])
		copy(expectedSecureRenegotiation[12:], c.serverFinished[:])
		if !bytes.Equal(hs.serverHello.secureRenegotiation, expectedSecureRenegotiation[:]) {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: incorrect renegotiation extension contents")
		}
	}

	// [Min] NPN，ALPN 模式的检查
	clientDidNPN := hs.hello.nextProtoNeg
	clientDidALPN := len(hs.hello.alpnProtocols) > 0
	serverHasNPN := hs.serverHello.nextProtoNeg
	serverHasALPN := len(hs.serverHello.alpnProtocol) > 0

	if !clientDidNPN && serverHasNPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested NPN extension")
	}

	if !clientDidALPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised unrequested ALPN extension")
	}

	if serverHasNPN && serverHasALPN {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server advertised both NPN and ALPN extensions")
	}

	if serverHasALPN {
		c.clientProtocol = hs.serverHello.alpnProtocol
		c.clientProtocolFallback = false
	}
	c.scts = hs.serverHello.scts

	// [Min] 重用 session
	if !hs.serverResumedSession() {
		return false, nil
	}

	// [Min] 决定重用 session 了，再检查版本，加密套件是否和协商的结果一致
	if hs.session.vers != c.vers {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different version")
	}

	if hs.session.cipherSuite != hs.suite.id {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: server resumed a session with a different cipher suite")
	}

	// Restore masterSecret and peerCerts from previous state
	// [Min] session 可以重用，则更新主密钥，证书等
	hs.masterSecret = hs.session.masterSecret
	c.peerCertificates = hs.session.serverCertificates
	c.verifiedChains = hs.session.verifiedChains
	return true, nil
}

func (hs *clientHandshakeState) readFinished(out []byte) error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if c.in.err != nil {
		return c.in.err
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverFinished, msg)
	}

	verify := hs.finishedHash.serverSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: server's Finished message was incorrect")
	}
	hs.finishedHash.Write(serverFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *clientHandshakeState) readSessionTicket() error {
	if !hs.serverHello.ticketSupported {
		return nil
	}

	c := hs.c
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	sessionTicketMsg, ok := msg.(*newSessionTicketMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(sessionTicketMsg, msg)
	}
	hs.finishedHash.Write(sessionTicketMsg.marshal())

	hs.session = &ClientSessionState{
		sessionTicket:      sessionTicketMsg.ticket,
		vers:               c.vers,
		cipherSuite:        hs.suite.id,
		masterSecret:       hs.masterSecret,
		serverCertificates: c.peerCertificates,
		verifiedChains:     c.verifiedChains,
	}

	return nil
}

func (hs *clientHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}
	if hs.serverHello.nextProtoNeg {
		nextProto := new(nextProtoMsg)
		proto, fallback := mutualProtocol(c.config.NextProtos, hs.serverHello.nextProtos)
		nextProto.proto = proto
		c.clientProtocol = proto
		c.clientProtocolFallback = fallback

		hs.finishedHash.Write(nextProto.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, nextProto.marshal()); err != nil {
			return err
		}
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.clientSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

// tls11SignatureSchemes contains the signature schemes that we synthesise for
// a TLS <= 1.1 connection, based on the supported certificate types.
var tls11SignatureSchemes = []SignatureScheme{ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512, PKCS1WithSHA1}

const (
	// tls11SignatureSchemesNumECDSA is the number of initial elements of
	// tls11SignatureSchemes that use ECDSA.
	tls11SignatureSchemesNumECDSA = 3
	// tls11SignatureSchemesNumRSA is the number of trailing elements of
	// tls11SignatureSchemes that use RSA.
	tls11SignatureSchemesNumRSA = 4
)

// [Min] 客户端按服务端的要求获取证书
func (hs *clientHandshakeState) getCertificate(certReq *certificateRequestMsg) (*Certificate, error) {
	c := hs.c

	var rsaAvail, ecdsaAvail bool
	// [Min] 可以发送的证书类型
	for _, certType := range certReq.certificateTypes {
		switch certType {
		case certTypeRSASign:
			rsaAvail = true
		case certTypeECDSASign:
			ecdsaAvail = true
		}
	}

	if c.config.GetClientCertificate != nil {
		// [Min] 如果 config 中配置了获取客户端证书的方法，就调用该方法获取证书
		var signatureSchemes []SignatureScheme

		// [Min] 证书签名的要求
		if !certReq.hasSignatureAndHash {
			// Prior to TLS 1.2, the signature schemes were not
			// included in the certificate request message. In this
			// case we use a plausible list based on the acceptable
			// certificate types.
			signatureSchemes = tls11SignatureSchemes
			if !ecdsaAvail {
				signatureSchemes = signatureSchemes[tls11SignatureSchemesNumECDSA:]
			}
			if !rsaAvail {
				signatureSchemes = signatureSchemes[:len(signatureSchemes)-tls11SignatureSchemesNumRSA]
			}
		} else {
			signatureSchemes = certReq.supportedSignatureAlgorithms
		}

		// [Min] 调用 GetClientCertificate 获取证书
		return c.config.GetClientCertificate(&CertificateRequestInfo{
			AcceptableCAs:    certReq.certificateAuthorities,
			SignatureSchemes: signatureSchemes,
		})
	}

	// RFC 4346 on the certificateAuthorities field: A list of the
	// distinguished names of acceptable certificate authorities.
	// These distinguished names may specify a desired
	// distinguished name for a root CA or for a subordinate CA;
	// thus, this message can be used to describe both known roots
	// and a desired authorization space. If the
	// certificate_authorities list is empty then the client MAY
	// send any certificate of the appropriate
	// ClientCertificateType, unless there is some external
	// arrangement to the contrary.

	// We need to search our list of client certs for one
	// where SignatureAlgorithm is acceptable to the server and the
	// Issuer is in certReq.certificateAuthorities
	// [Min] 从 config 的 Certificates 中查找符合条件的证书
findCert:
	for i, chain := range c.config.Certificates {
		// [Min] 如果要求既不是 RSA 证书也不是 ECDSA 证书，跳过
		if !rsaAvail && !ecdsaAvail {
			continue
		}

		for j, cert := range chain.Certificate {
			x509Cert := chain.Leaf
			// parse the certificate if this isn't the leaf
			// node, or if chain.Leaf was nil
			if j != 0 || x509Cert == nil {
				var err error
				if x509Cert, err = x509.ParseCertificate(cert); err != nil {
					c.sendAlert(alertInternalError)
					return nil, errors.New("tls: failed to parse client certificate #" + strconv.Itoa(i) + ": " + err.Error())
				}
			}

			switch {
			case rsaAvail && x509Cert.PublicKeyAlgorithm == x509.RSA:
			case ecdsaAvail && x509Cert.PublicKeyAlgorithm == x509.ECDSA:
			default:
				continue findCert
			}

			// [Min] 如果没有限定证书的授权组织，直接返回，否则需匹配组织
			if len(certReq.certificateAuthorities) == 0 {
				// they gave us an empty list, so just take the
				// first cert from c.config.Certificates
				return &chain, nil
			}

			for _, ca := range certReq.certificateAuthorities {
				if bytes.Equal(x509Cert.RawIssuer, ca) {
					return &chain, nil
				}
			}
		}
	}

	// [Min] 没有满足条件的证书，返回一个空证书
	// No acceptable certificate found. Don't send a certificate.
	return new(Certificate), nil
}

// clientSessionCacheKey returns a key used to cache sessionTickets that could
// be used to resume previously negotiated TLS sessions with a server.
// [Min] 获取 SessionCacheKey，优先 config.ServerName 》serverAddr.String()
func clientSessionCacheKey(serverAddr net.Addr, config *Config) string {
	if len(config.ServerName) > 0 {
		return config.ServerName
	}
	return serverAddr.String()
}

// mutualProtocol finds the mutual Next Protocol Negotiation or ALPN protocol
// given list of possible protocols and a list of the preference order. The
// first list must not be empty. It returns the resulting protocol and flag
// indicating if the fallback case was reached.
// [Min] 以preferenceProtos为基准，在protos中进行匹配，不成功返回protos中的第一个
func mutualProtocol(protos, preferenceProtos []string) (string, bool) {
	for _, s := range preferenceProtos {
		for _, c := range protos {
			if s == c {
				return s, false
			}
		}
	}

	return protos[0], true
}

// hostnameInSNI converts name into an approriate hostname for SNI.
// Literal IP addresses and absolute FQDNs are not permitted as SNI values.
// See https://tools.ietf.org/html/rfc6066#section-3.
// [Min] 目前 hostname 只能是DNS hostnames，不能是ip地址
func hostnameInSNI(name string) string {
	host := name
	if len(host) > 0 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if i := strings.LastIndex(host, "%"); i > 0 {
		host = host[:i]
	}
	if net.ParseIP(host) != nil {
		return ""
	}
	for len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
