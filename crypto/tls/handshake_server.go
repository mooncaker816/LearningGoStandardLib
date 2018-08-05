// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
)

// serverHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeState struct {
	c                     *Conn
	clientHello           *clientHelloMsg
	hello                 *serverHelloMsg
	suite                 *cipherSuite
	ellipticOk            bool
	ecdsaOk               bool
	rsaDecryptOk          bool
	rsaSignOk             bool
	sessionState          *sessionState
	finishedHash          finishedHash
	masterSecret          []byte
	certsFromClient       [][]byte
	cert                  *Certificate
	cachedClientHelloInfo *ClientHelloInfo
}

// serverHandshake performs a TLS handshake as a server.
// c.out.Mutex <= L; c.handshakeMutex <= L.
// [Min] 服务端握手
func (c *Conn) serverHandshake() error {
	// If this is the first server handshake, we generate a random key to
	// encrypt the tickets with.
	c.config.serverInitOnce.Do(func() { c.config.serverInit(nil) })

	hs := serverHandshakeState{
		c: c,
	}
	// [Min] 读取客户端 helloMsg，更新相关信息，同时决定是否重用 session，如果重用，
	// [Min] 那么 session 的信息就已经从 hs.clientHello.sessionTicket 中恢复到了 hs.sessionState
	isResume, err := hs.readClientHello()
	if err != nil {
		return err
	}

	// For an overview of TLS handshaking, see https://tools.ietf.org/html/rfc5246#section-7.3
	// [Min] 开启缓存写入
	c.buffering = true
	if isResume {
		// The client has included a session ticket and so we do an abbreviated handshake.
		// [Min] 告知重用 session，验证客户端证书，恢复主密钥 hs.masterSecret = hs.sessionState.masterSecret
		if err := hs.doResumeHandshake(); err != nil {
			return err
		}
		// [Min] 根据主密钥建立加密通讯需要的 cipher，hash，更新到客户端和服务端各自对应的 halfConn 的预备字段中，等待切换
		if err := hs.establishKeys(); err != nil {
			return err
		}
		// ticketSupported is set in a resumption handshake if the
		// ticket from the client was encrypted with an old session
		// ticket key and thus a refreshed ticket should be sent.
		// [Min] 如果重用的 sessionState 是使用老的 ticketKey 解密而得，
		// [Min] 需要用最新的 key 重新加密生成新的 ticket，并返回给客户端让其同步刷新
		if hs.hello.ticketSupported {
			if err := hs.sendSessionTicket(); err != nil {
				return err
			}
		}
		// [Min] 发送finishedMsg，并将 fishishedMsg 中的 verifyData 写入 c.serverFinished[:]
		// [Min] 切换 c.out 为加密模式
		if err := hs.sendFinished(c.serverFinished[:]); err != nil {
			return err
		}
		// [Min] 推送 c.sendBuf 中累积的消息到客户端，依次包括：serverHelloMsg，newSessionTicketMsg（可选），finishedMsg。
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		// [Min] 读取客户端的 finishedMsg，正常情况会切换 c.in 的 cipher 和 mac 设置，转为加密模式，还会进行 finishedMsg 的相关验证
		if err := hs.readFinished(nil); err != nil {
			return err
		}
		// [Min] 至此，服务端的 c.in，c.out 都已经为加密模式，重用 session 完成
		c.didResume = true
	} else {
		// [Min] 非重用 session
		// The client didn't include a session ticket, or it wasn't
		// valid so we do a full handshake.
		// [Min] 完整的 handshake
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		// [Min] 根据主密钥建立加密通讯需要的 cipher，hash，更新到客户端和服务端各自对应的 halfConn 的预备字段中，等待切换
		if err := hs.establishKeys(); err != nil {
			return err
		}
		// [Min] 完整 handshake 的情况，由客户端先发起 finishedMsg，服务端先读
		// [Min] 会切换 c.in 为加密模式
		if err := hs.readFinished(c.clientFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		// [Min] 之前已经调用过一次 flush，缓存写入模式已经关闭，
		// [Min] 我们需要重启缓存写入模式
		c.buffering = true
		// [Min] 根据当前的 sessionState，制作 sessionTicket 发给客户端，以备后用
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		// [Min] 发送 finishedMsgs，切换 c.out 为加密模式
		if err := hs.sendFinished(nil); err != nil {
			return err
		}
		// [Min] 推送消息到客户端
		if _, err := c.flush(); err != nil {
			return err
		}
	}
	c.handshakeComplete = true

	return nil
}

// readClientHello reads a ClientHello message from the client and decides
// whether we will perform session resumption.
// [Min] 服务端读取客户端的 HelloMsg，同时会决定是否重用 session
func (hs *serverHandshakeState) readClientHello() (isResume bool, err error) {
	c := hs.c

	// [Min] 读取客户端的 helloMsg
	msg, err := c.readHandshake()
	if err != nil {
		return false, err
	}
	var ok bool
	hs.clientHello, ok = msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return false, unexpectedMessageError(hs.clientHello, msg)
	}

	if c.config.GetConfigForClient != nil {
		// [Min] 根据客户端的 helloMsg 生成一个新的 config
		if newConfig, err := c.config.GetConfigForClient(hs.clientHelloInfo()); err != nil {
			c.sendAlert(alertInternalError)
			return false, err
		} else if newConfig != nil {
			// [Min] 新的 config 中
			// [Min] sessionTicketKeys 从 c.config 中拷贝
			// [Min] SessionTicketKey 如果已经设置就不变，没有设置（0），则也从 c.config 中拷贝
			newConfig.serverInitOnce.Do(func() { newConfig.serverInit(c.config) })
			c.config = newConfig
		}
	}

	// [Min] 根据客户端中的版本号，协商双方都可用的版本号
	c.vers, ok = c.config.mutualVersion(hs.clientHello.vers)
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return false, fmt.Errorf("tls: client offered an unsupported, maximum protocol version of %x", hs.clientHello.vers)
	}
	c.haveVers = true

	// [Min] 构建服务端 HelloMsg
	hs.hello = new(serverHelloMsg)

	supportedCurve := false
	preferredCurves := c.config.curvePreferences()
	// [Min] 判断客户端支持的Curve服务端是否也支持
Curves:
	for _, curve := range hs.clientHello.supportedCurves {
		for _, supported := range preferredCurves {
			if supported == curve {
				supportedCurve = true
				break Curves
			}
		}
	}

	// [Min] 判断客户端支持的PointFormat是否包含pointFormatUncompressed
	// [Min] Go标准库目前只支持pointFormatUncompressed
	supportedPointFormat := false
	for _, pointFormat := range hs.clientHello.supportedPoints {
		if pointFormat == pointFormatUncompressed {
			supportedPointFormat = true
			break
		}
	}
	// [Min] 椭圆曲线算法可用
	hs.ellipticOk = supportedCurve && supportedPointFormat

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	// [Min] Go 标准库只支持非压缩，所以客户端提供的压缩方法中必须含有非压缩的方法
	// [Min] 注：Go 实现的客户端hellomsg只设置了非压缩的方法
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	// [Min] 如果压缩方法不一致，报警
	if !foundCompression {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: client does not support uncompressed connections")
	}

	// [Min] 设置服务端版本号，随机数
	hs.hello.vers = c.vers
	hs.hello.random = make([]byte, 32)
	_, err = io.ReadFull(c.config.rand(), hs.hello.random)
	if err != nil {
		c.sendAlert(alertInternalError)
		return false, err
	}

	// [Min] 初次handshake 客户端 hello msg 中 secureRenegotiation必须为空
	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	// [Min] 服务端的安全重协商支持标志与客户端保持一致
	hs.hello.secureRenegotiationSupported = hs.clientHello.secureRenegotiationSupported
	hs.hello.compressionMethod = compressionNone
	// [Min] 将 config 中的 serverName 设置为客户端 helloMsg 中 serverName
	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	// [Min] 优先ALPN模式，服务器从客户端提供的protos中选择自己支持的返回，
	// [Min] fallback表示是否因为没有匹配成功而选择了客户端提供的第一个proto
	if len(hs.clientHello.alpnProtocols) > 0 {
		if selectedProto, fallback := mutualProtocol(hs.clientHello.alpnProtocols, c.config.NextProtos); !fallback {
			hs.hello.alpnProtocol = selectedProto
			c.clientProtocol = selectedProto
		}
	} else {
		// [Min] NPN 模式，服务端返回自己支持的protos，让客户端自己去选择
		// Although sending an empty NPN extension is reasonable, Firefox has
		// had a bug around this. Best to send nothing at all if
		// c.config.NextProtos is empty. See
		// https://golang.org/issue/5445.
		if hs.clientHello.nextProtoNeg && len(c.config.NextProtos) > 0 {
			hs.hello.nextProtoNeg = true
			hs.hello.nextProtos = c.config.NextProtos
		}
	}

	// [Min] 获取最适合 clientHelloMsg 的证书
	hs.cert, err = c.config.getCertificate(hs.clientHelloInfo())
	if err != nil {
		c.sendAlert(alertInternalError)
		return false, err
	}
	// [Min] 如果客户端提出需要 scts，则返回 hs.cert.SignedCertificateTimestamps
	if hs.clientHello.scts {
		hs.hello.scts = hs.cert.SignedCertificateTimestamps
	}

	// [Min] 根据选择的证书，判断公钥支持的签名算法
	if priv, ok := hs.cert.PrivateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecdsaOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			c.sendAlert(alertInternalError)
			return false, fmt.Errorf("tls: unsupported signing key type (%T)", priv.Public())
		}
	}
	// [Min] 根据选择的证书，判断公钥支持的解密算法
	if priv, ok := hs.cert.PrivateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:
			c.sendAlert(alertInternalError)
			return false, fmt.Errorf("tls: unsupported decryption key type (%T)", priv.Public())
		}
	}

	// [Min] 根据客户端提供的 sessionTicket，检查是否重用 session，如果重用，
	// [Min] 那么 session 的信息就已经从 hs.clientHello.sessionTicket 中恢复到了 hs.sessionState
	if hs.checkForResumption() {
		return true, nil
	}

	// [Min] 以下为非重用 session 的情况，我们仍需继续协商套件
	var preferenceList, supportedList []uint16
	// [Min] 如果优先服务器加密套件，则将服务器加密套件作为优先选择的列表，客户端发送的列表作为支持的列表
	// [Min] 否则，相反
	if c.config.PreferServerCipherSuites {
		preferenceList = c.config.cipherSuites()
		supportedList = hs.clientHello.cipherSuites
	} else {
		preferenceList = hs.clientHello.cipherSuites
		supportedList = c.config.cipherSuites()
	}

	// [Min] 从优先选择列表中依次判断套件是否在支持列表中，且双方实现该套件的参数都可用，
	// [Min] 是就协商成功，设置hs.suite，否就继续协商，直到preferenceList完结
	for _, id := range preferenceList {
		if hs.setCipherSuite(id, supportedList, c.vers) {
			break
		}
	}

	// [Min] 如果没有协商出双方都可以的套件，报警
	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: no cipher suite supported by both client and server")
	}

	// See https://tools.ietf.org/html/rfc7507.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// The client is doing a fallback connection.
			if hs.clientHello.vers < c.config.maxVersion() {
				c.sendAlert(alertInappropriateFallback)
				return false, errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	return false, nil
}

// checkForResumption reports whether we should perform resumption on this connection.
// [Min] 根据客户端提供的 sessionTicket，检查是否重用 session
func (hs *serverHandshakeState) checkForResumption() bool {
	c := hs.c

	// [Min] 首先 SessionTicketsDisabled 不能为禁用
	if c.config.SessionTicketsDisabled {
		return false
	}

	var ok bool
	// [Min] 拷贝客户端 helloMsg 中的 sessionTicket
	var sessionTicket = append([]uint8{}, hs.clientHello.sessionTicket...)
	// [Min] 对 ticket 解密，还原为 sessionState，如果无法还原，不重用
	if hs.sessionState, ok = c.decryptTicket(sessionTicket); !ok {
		return false
	}

	// Never resume a session for a different TLS version.
	// [Min] 如果 TLS 版本不同，不重用
	if c.vers != hs.sessionState.vers {
		return false
	}

	cipherSuiteOk := false
	// Check that the client is still offering the ciphersuite in the session.
	// [Min] 检查客户端对该重用 session 的加密套件仍然支持
	for _, id := range hs.clientHello.cipherSuites {
		if id == hs.sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return false
	}

	// Check that we also support the ciphersuite from the session.
	// [Min] 检查服务端仍然支持该套件，并设置套件
	if !hs.setCipherSuite(hs.sessionState.cipherSuite, c.config.cipherSuites(), hs.sessionState.vers) {
		return false
	}

	sessionHasClientCerts := len(hs.sessionState.certificates) != 0
	needClientCerts := c.config.ClientAuth == RequireAnyClientCert || c.config.ClientAuth == RequireAndVerifyClientCert
	// [Min] 如果服务端需要客户端提供证书（验证），但重用 session 中没有任何证书，则不能重用
	if needClientCerts && !sessionHasClientCerts {
		return false
	}
	// [Min] 如果 session 有证书，但服务端不要求客户端提供证书，也不能重用
	if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
		return false
	}

	return true
}

// [Min] 重用 session 的 handshake，返回 helloMsg，告知 session 重用，验证客户端证书并恢复主密钥
func (hs *serverHandshakeState) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	// We echo the client's session ID in the ServerHello to let it know
	// that we're doing a resumption.
	// [Min] 重用 session 的情况下，sessionId 和客户端发过来的保持一致，
	// [Min] 这样客户端就可以通过 sessionId 没有变化来判断 session 的重用
	hs.hello.sessionId = hs.clientHello.sessionId
	// [Min] 表明客户端提供的 ticket 是否可以恢复成 sessionState 使用
	// [Min] 同时也记录 sessionTicket 是否需要以最新的 key 重制生成 ticket 来刷新（实际内容不变）
	hs.hello.ticketSupported = hs.sessionState.usedOldKey
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	// [Min] 将服务端 helloMsg 写入缓存
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	// [Min] 验证客户端的证书链
	if len(hs.sessionState.certificates) > 0 {
		if _, err := hs.processCertsFromClient(hs.sessionState.certificates); err != nil {
			return err
		}
	}

	// [Min] 客户端证书没问题，再从 sessionState 中恢复主密钥
	hs.masterSecret = hs.sessionState.masterSecret

	return nil
}

// [Min] 完整的 handshake
func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	// [Min] 如果客户端要求 ocspStapling，且证书状态不为空，设置 hs.hello.ocspStapling 为真
	if hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0 {
		hs.hello.ocspStapling = true
	}

	// [Min] 设置是否支持 ticket，套件 id
	hs.hello.ticketSupported = hs.clientHello.ticketSupported && !c.config.SessionTicketsDisabled
	hs.hello.cipherSuite = hs.suite.id

	// [Min] 根据版本和套件新建 finishedHash
	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	// [Min] 如果不需要客户端证书，直接将 finishedHash.buffer 置为 nil
	if c.config.ClientAuth == NoClientCert {
		// No need to keep a full record of the handshake if client
		// certificates won't be used.
		hs.finishedHash.discardHandshakeBuffer()
	}
	// [Min] 计算 clientHelloMsg 和 serverHelloMsg 的 hash
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	// [Min] 将 serverHelloMsg 写入 tls.Conn 的缓存 sendBuf 中
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	// [Min] 构造certificateMsg，将服务端证书写入缓存 c.sendBuf 中，并完成该消息
	certMsg := new(certificateMsg)
	certMsg.certificates = hs.cert.Certificate
	hs.finishedHash.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	// [Min] 如果需要 ocspStapling，构造 certificateStatusMsg，写入缓存 c.sendBuf 中，并完成该消息
	if hs.hello.ocspStapling {
		certStatus := new(certificateStatusMsg)
		certStatus.statusType = statusTypeOCSP
		certStatus.response = hs.cert.OCSPStaple
		hs.finishedHash.Write(certStatus.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certStatus.marshal()); err != nil {
			return err
		}
	}

	// [Min] 获得该套件的 keyAgreement 实例
	keyAgreement := hs.suite.ka(c.vers)
	// [Min] 生成交换的公钥和签名，组成 serverKeyExchangeMsg
	// [Min] 也可能不需要交换公钥，如 RSA 秘钥交换
	skx, err := keyAgreement.generateServerKeyExchange(c.config, hs.cert, hs.clientHello, hs.hello)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	// [Min] 如果 skx 不为 nil，说明不是 RSA，RSA无需发送 serverKeyExchangeMsg
	// [Min] 再把 serverKeyExchangeMsg 写入缓存 c.sendBuf 中，并完成该消息
	if skx != nil {
		hs.finishedHash.Write(skx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, skx.marshal()); err != nil {
			return err
		}
	}

	// [Min] 如果服务端需要验证客户端的证书，则要发送验证请求
	if c.config.ClientAuth >= RequestClientCert {
		// Request a client certificate
		certReq := new(certificateRequestMsg)
		// [Min] 要求证书为 RSASign 或 ECDSASign
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		// [Min] >= TLS 1.2，提供服务端支持的签名算法
		if c.vers >= VersionTLS12 {
			certReq.hasSignatureAndHash = true
			certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms
		}

		// An empty list of certificateAuthorities signals to
		// the client that it may send any certificate in response
		// to our request. When we know the CAs we trust, then
		// we can send them down, so that the client can choose
		// an appropriate certificate to give to us.
		// [Min] 限定证书的授权组织
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		// [Min] 累计计算 hash 并写入 conn 的缓存
		hs.finishedHash.Write(certReq.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certReq.marshal()); err != nil {
			return err
		}
	}

	// [Min] 至此，hello 阶段完成，发送 helloDone 消息
	helloDone := new(serverHelloDoneMsg)
	hs.finishedHash.Write(helloDone.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, helloDone.marshal()); err != nil {
		return err
	}

	// [Min] 从缓存中将累积的消息推送到客户端，依次包括：
	// [Min] serverHelloMsg，certificateMsg，certificateStatusMsg（可选），
	// [Min] serverKeyExchangeMsg（非 RSA 秘钥交换），certificateRequestMsg（可选），serverHelloDoneMsg
	if _, err := c.flush(); err != nil {
		return err
	}

	var pub crypto.PublicKey // public key for client auth, if any

	// [Min] 读取 handshake 返回消息
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	var ok bool
	// If we requested a client certificate, then the client must send a
	// certificate message, even if it's empty.
	if c.config.ClientAuth >= RequestClientCert {
		// [Min] 如果之前要求了客户端提供证书，此时应该先收到证书消息
		if certMsg, ok = msg.(*certificateMsg); !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certMsg, msg)
		}
		// [Min] 累计计算 hash
		hs.finishedHash.Write(certMsg.marshal())

		// [Min] 如果证书消息中并没有实际包含证书，但服务端又要求有证书，报警
		if len(certMsg.certificates) == 0 {
			// The client didn't actually send a certificate
			switch c.config.ClientAuth {
			case RequireAnyClientCert, RequireAndVerifyClientCert:
				c.sendAlert(alertBadCertificate)
				return errors.New("tls: client didn't provide a certificate")
			}
		}

		// [Min] 处理客户端的证书，返回公钥
		pub, err = hs.processCertsFromClient(certMsg.certificates)
		if err != nil {
			return err
		}

		// [Min] 读取下一条消息
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	// Get client key exchange
	// [Min] 接下来应该收到客户端交换 key 的消息
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}
	// [Min] 完成消息
	hs.finishedHash.Write(ckx.marshal())

	// [Min] 此时有了客户端交换秘钥的公钥，就可以生成预备主密钥了
	preMasterSecret, err := keyAgreement.processClientKeyExchange(c.config, hs.cert, ckx, c.vers)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	// [Min] 计算主密钥
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.clientHello.random, hs.hello.random)
	if err := c.config.writeKeyLog(hs.clientHello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	// If we received a client cert in response to our certificate request message,
	// the client will send us a certificateVerifyMsg immediately after the
	// clientKeyExchangeMsg. This message is a digest of all preceding
	// handshake-layer messages that is signed using the private key corresponding
	// to the client's certificate. This allows us to verify that the client is in
	// possession of the private key of the certificate.
	// [Min] 验证客户端的签名
	if len(c.peerCertificates) > 0 {
		// [Min] 读取一条消息，理应是 certificateVerifyMsg
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		// Determine the signature type.
		// [Min] 获取签名算法
		var signatureAlgorithm SignatureScheme
		var sigType uint8
		if certVerify.hasSignatureAndHash {
			signatureAlgorithm = certVerify.signatureAlgorithm
			if !isSupportedSignatureAlgorithm(signatureAlgorithm, supportedSignatureAlgorithms) {
				return errors.New("tls: unsupported hash function for client certificate")
			}
			sigType = signatureFromSignatureScheme(signatureAlgorithm)
		} else {
			// Before TLS 1.2 the signature algorithm was implicit
			// from the key type, and only one hash per signature
			// algorithm was possible. Leave signatureAlgorithm
			// unset.
			switch pub.(type) {
			case *ecdsa.PublicKey:
				sigType = signatureECDSA
			case *rsa.PublicKey:
				sigType = signatureRSA
			}
		}

		// [Min] 验证签名
		switch key := pub.(type) {
		case *ecdsa.PublicKey:
			if sigType != signatureECDSA {
				err = errors.New("tls: bad signature type for client's ECDSA certificate")
				break
			}
			ecdsaSig := new(ecdsaSignature)
			if _, err = asn1.Unmarshal(certVerify.signature, ecdsaSig); err != nil {
				break
			}
			if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
				err = errors.New("tls: ECDSA signature contained zero or negative values")
				break
			}
			var digest []byte
			if digest, _, err = hs.finishedHash.hashForClientCertificate(sigType, signatureAlgorithm, hs.masterSecret); err != nil {
				break
			}
			if !ecdsa.Verify(key, digest, ecdsaSig.R, ecdsaSig.S) {
				err = errors.New("tls: ECDSA verification failure")
			}
		case *rsa.PublicKey:
			if sigType != signatureRSA {
				err = errors.New("tls: bad signature type for client's RSA certificate")
				break
			}
			var digest []byte
			var hashFunc crypto.Hash
			if digest, hashFunc, err = hs.finishedHash.hashForClientCertificate(sigType, signatureAlgorithm, hs.masterSecret); err != nil {
				break
			}
			err = rsa.VerifyPKCS1v15(key, hashFunc, digest, certVerify.signature)
		}
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: could not validate signature of connection nonces: " + err.Error())
		}

		hs.finishedHash.Write(certVerify.marshal())
	}

	// [Min] 客户端证书验证完毕，清空 finishedHash 的 buffer
	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

// [Min] 根据主密钥建立加密通讯需要的 cipher，hash，更新到客户端和服务端各自对应的 halfConn 的预备字段中，等待切换
func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	// [Min] 通过主密钥生成一系列计算 mac，加解密需要使用到的 key，和初始化向量
	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction

	if hs.suite.aead == nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	// [Min] 将 client 的 cipher，hash 算法更新到 in 的预备字段中，等待正式切换
	// [Min] 将 server 的 cipher，hash 算法更新到 out 的预备字段中，等待正式切换
	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

// [Min] 读取客户端 finishedMsg
func (hs *serverHandshakeState) readFinished(out []byte) error {
	c := hs.c

	// [Min] 首先客户端也应该先返回一个 recordTypeChangeCipherSpec 的消息
	// [Min] 此时会将 c.in 的 cipher，mac 切换为之前协商后的结果
	c.readRecord(recordTypeChangeCipherSpec)
	if c.in.err != nil {
		return c.in.err
	}

	// [Min] 如果是 NPN 模式，此时应该收到客户端的对此的回复
	if hs.hello.nextProtoNeg {
		msg, err := c.readHandshake()
		if err != nil {
			return err
		}
		nextProto, ok := msg.(*nextProtoMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(nextProto, msg)
		}
		hs.finishedHash.Write(nextProto.marshal())
		c.clientProtocol = nextProto.proto
	}

	// [Min] 接下来应该收到客户端的 finishedMsg
	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	// [Min] 计算 clientSum，并验证 clientFinished.verifyData 是否一致
	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tls: client's Finished message is incorrect")
	}

	// [Min] 再次计算客户端发送的 finishedMsg 的 hash 并将 verify 拷贝至 out
	hs.finishedHash.Write(clientFinished.marshal())
	copy(out, verify)
	return nil
}

// [Min] 根据当前协商好的信息，制作 sessionTicket，并返回给客户端
func (hs *serverHandshakeState) sendSessionTicket() error {
	if !hs.hello.ticketSupported {
		return nil
	}

	c := hs.c
	m := new(newSessionTicketMsg)

	var err error
	// [Min] sessionState 的内容
	state := sessionState{
		vers:         c.vers,
		cipherSuite:  hs.suite.id,
		masterSecret: hs.masterSecret,
		certificates: hs.certsFromClient,
	}
	m.ticket, err = c.encryptTicket(&state)
	if err != nil {
		return err
	}

	hs.finishedHash.Write(m.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, m.marshal()); err != nil {
		return err
	}

	return nil
}

// [Min] 发送 finshedMsg
func (hs *serverHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	// [Min] 发送切换信号，此时会将 c.out 中的 cipher 和 mac 切换，转为加密模式
	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}

	// [Min] 构造 finishedMsg，并序列化，然后完成该消息并写入 c.sendBuf 中等待正式发送
	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}

	// [Min] 同步 config 中 cipherSuite
	c.cipherSuite = hs.suite.id
	// [Min] 将 verifyData 拷贝至 out
	copy(out, finished.verifyData)

	return nil
}

// processCertsFromClient takes a chain of client certificates either from a
// Certificates message or from a sessionState and verifies them. It returns
// the public key of the leaf certificate.
// [Min] 处理客户端的证书链，正常情况，更新了 c.verifiedChains，c.peerCertificates ，并返回公钥
func (hs *serverHandshakeState) processCertsFromClient(certificates [][]byte) (crypto.PublicKey, error) {
	c := hs.c

	hs.certsFromClient = certificates
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	// [Min] 解析证书
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, errors.New("tls: failed to parse client certificate: " + err.Error())
		}
	}

	// [Min] 如果需要验证，且有有效证书，进行验证
	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		opts := x509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}

		chains, err := certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, errors.New("tls: failed to verify client's certificate: " + err.Error())
		}

		c.verifiedChains = chains
	}

	// [Min] 自定义的对对端证书的验证
	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, err
		}
	}

	if len(certs) == 0 {
		return nil, nil
	}

	var pub crypto.PublicKey
	switch key := certs[0].PublicKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		pub = key
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return nil, fmt.Errorf("tls: client's certificate contains an unsupported public key of type %T", certs[0].PublicKey)
	}
	c.peerCertificates = certs
	return pub, nil
}

// setCipherSuite sets a cipherSuite with the given id as the serverHandshakeState
// suite if that cipher suite is acceptable to use.
// It returns a bool indicating if the suite was set.
// [Min] 协商加密套件，id是从优先套件列表中的套件id
func (hs *serverHandshakeState) setCipherSuite(id uint16, supportedCipherSuites []uint16, version uint16) bool {
	for _, supported := range supportedCipherSuites {
		if id == supported {
			var candidate *cipherSuite

			for _, s := range cipherSuites {
				if s.id == id {
					candidate = s
					break
				}
			}
			if candidate == nil {
				continue
			}
			// Don't select a ciphersuite which we can't
			// support for this client.
			// [Min] 如果套件使用了椭圆曲线秘钥协商算法，要求ellipticOk为真，即curve要都支持，且format为pointFormatUncompressed
			// [Min] 相应的签名算法也要和准备发送给客户端的证书中的公钥支持的签名算法保持一致
			if candidate.flags&suiteECDHE != 0 {
				if !hs.ellipticOk {
					continue
				}
				// [Min] 如果候选套件的签名算法为ECDSA，证书中的公钥也要支持ECDSA
				// [Min] 否则，证书中的公钥要支持RSA签名
				if candidate.flags&suiteECDSA != 0 {
					if !hs.ecdsaOk {
						continue
					}
				} else if !hs.rsaSignOk {
					continue
				}
				// [Min] 未使用椭圆曲线算法，RSA协商算法
			} else if !hs.rsaDecryptOk {
				continue
			}
			// [Min] 协商的版本号是否达到了候选套件对版本的要求
			if version < VersionTLS12 && candidate.flags&suiteTLS12 != 0 {
				continue
			}
			hs.suite = candidate
			return true
		}
	}
	return false
}

// suppVersArray is the backing array of ClientHelloInfo.SupportedVersions
// [Min] 支持版本的倒序
var suppVersArray = [...]uint16{VersionTLS12, VersionTLS11, VersionTLS10, VersionSSL30}

// [Min] 将客户端的 helloMsg 存入 cachedClientHelloInfo
func (hs *serverHandshakeState) clientHelloInfo() *ClientHelloInfo {
	if hs.cachedClientHelloInfo != nil {
		return hs.cachedClientHelloInfo
	}

	var supportedVersions []uint16
	if hs.clientHello.vers > VersionTLS12 {
		supportedVersions = suppVersArray[:]
	} else if hs.clientHello.vers >= VersionSSL30 {
		supportedVersions = suppVersArray[VersionTLS12-hs.clientHello.vers:]
	}

	hs.cachedClientHelloInfo = &ClientHelloInfo{
		CipherSuites:      hs.clientHello.cipherSuites,
		ServerName:        hs.clientHello.serverName,
		SupportedCurves:   hs.clientHello.supportedCurves,
		SupportedPoints:   hs.clientHello.supportedPoints,
		SignatureSchemes:  hs.clientHello.supportedSignatureAlgorithms,
		SupportedProtos:   hs.clientHello.alpnProtocols,
		SupportedVersions: supportedVersions,
		Conn:              hs.c.conn,
	}

	return hs.cachedClientHelloInfo
}
