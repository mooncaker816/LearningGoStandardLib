// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
)

// sessionState contains the information that is serialized into a session
// ticket in order to later resume a connection.
// [Min] sessionState 包含了重用 session 需要用的所有要素
// [Min] sessionState -> 序列化流 -> ticketKeyName + iv + 加密后的序列化流 + mac 即为 sessionTicket
type sessionState struct {
	vers         uint16   // [Min] TLS 版本
	cipherSuite  uint16   // [Min] 加密套件
	masterSecret []byte   // [Min] 主密钥
	certificates [][]byte // [Min] 客户端的证书链
	// usedOldKey is true if the ticket from which this session came from
	// was encrypted with an older key and thus should be refreshed.
	// [Min] 表明该 ticket 是否是采用了老的 key 加密而成，
	// [Min] 如果是，后续会对该 sessionState 采用最新的 key 加密，生成最新的 ticket，（实质内容没有改变）
	// [Min] 再发送给客户端，让客户端更新，以便后续继续使用该 ticket
	usedOldKey bool
}

// [Min] 比较 sessionState 是否相同
func (s *sessionState) equal(i interface{}) bool {
	s1, ok := i.(*sessionState)
	if !ok {
		return false
	}

	if s.vers != s1.vers ||
		s.cipherSuite != s1.cipherSuite ||
		!bytes.Equal(s.masterSecret, s1.masterSecret) {
		return false
	}

	if len(s.certificates) != len(s1.certificates) {
		return false
	}

	for i := range s.certificates {
		if !bytes.Equal(s.certificates[i], s1.certificates[i]) {
			return false
		}
	}

	return true
}

// [Min] 序列化 sessionState
func (s *sessionState) marshal() []byte {
	length := 2 + 2 + 2 + len(s.masterSecret) + 2
	for _, cert := range s.certificates {
		length += 4 + len(cert)
	}

	ret := make([]byte, length)
	x := ret
	x[0] = byte(s.vers >> 8)
	x[1] = byte(s.vers)
	x[2] = byte(s.cipherSuite >> 8)
	x[3] = byte(s.cipherSuite)
	x[4] = byte(len(s.masterSecret) >> 8)
	x[5] = byte(len(s.masterSecret))
	x = x[6:]
	copy(x, s.masterSecret)
	x = x[len(s.masterSecret):]

	x[0] = byte(len(s.certificates) >> 8)
	x[1] = byte(len(s.certificates))
	x = x[2:]

	for _, cert := range s.certificates {
		x[0] = byte(len(cert) >> 24)
		x[1] = byte(len(cert) >> 16)
		x[2] = byte(len(cert) >> 8)
		x[3] = byte(len(cert))
		copy(x[4:], cert)
		x = x[4+len(cert):]
	}

	return ret
}

// [Min] 反序列化
func (s *sessionState) unmarshal(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	s.vers = uint16(data[0])<<8 | uint16(data[1])
	s.cipherSuite = uint16(data[2])<<8 | uint16(data[3])
	masterSecretLen := int(data[4])<<8 | int(data[5])
	data = data[6:]
	if len(data) < masterSecretLen {
		return false
	}

	s.masterSecret = data[:masterSecretLen]
	data = data[masterSecretLen:]

	if len(data) < 2 {
		return false
	}

	numCerts := int(data[0])<<8 | int(data[1])
	data = data[2:]

	s.certificates = make([][]byte, numCerts)
	for i := range s.certificates {
		if len(data) < 4 {
			return false
		}
		certLen := int(data[0])<<24 | int(data[1])<<16 | int(data[2])<<8 | int(data[3])
		data = data[4:]
		if certLen < 0 {
			return false
		}
		if len(data) < certLen {
			return false
		}
		s.certificates[i] = data[:certLen]
		data = data[certLen:]
	}

	return len(data) == 0
}

// [Min] 将 sessionState 转为 sessionTicket
func (c *Conn) encryptTicket(state *sessionState) ([]byte, error) {
	// [Min] 首先序列化 sessionState
	serialized := state.marshal()
	// [Min] ticket 结构：ticketKeyName + iv + 加密后的序列化流 + mac
	encrypted := make([]byte, ticketKeyNameLen+aes.BlockSize+len(serialized)+sha256.Size)
	keyName := encrypted[:ticketKeyNameLen]
	iv := encrypted[ticketKeyNameLen : ticketKeyNameLen+aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	// [Min] iv 为16字节的随机数
	if _, err := io.ReadFull(c.config.rand(), iv); err != nil {
		return nil, err
	}
	// [Min] 从 config 中获取 sessionTicketKeys ，用来将 sessionState 加密为 ticket
	// [Min] 注意，加密的时候总是使用第一个 sessionTicketKey，后续的都认为是老的 key
	key := c.config.ticketKeys()[0]
	// [Min] 从 key 中获取 keyName，并以 key.aseKey 为秘钥，iv 为初始向量，CTR 模式对序列化流加密
	copy(keyName, key.keyName[:])
	block, err := aes.NewCipher(key.aesKey[:])
	if err != nil {
		return nil, errors.New("tls: failed to create cipher while encrypting ticket: " + err.Error())
	}
	cipher.NewCTR(block, iv).XORKeyStream(encrypted[ticketKeyNameLen+aes.BlockSize:], serialized)

	// [Min] 对 keyName + iv + 加密的序列化流 以 key.hmacKey 为秘钥计算 HMAC
	mac := hmac.New(sha256.New, key.hmacKey[:])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	mac.Sum(macBytes[:0])

	return encrypted, nil
}

// [Min] 解密 ticket，转为对应的 sessionState
func (c *Conn) decryptTicket(encrypted []byte) (*sessionState, bool) {
	// [Min] 基本检查
	if c.config.SessionTicketsDisabled ||
		len(encrypted) < ticketKeyNameLen+aes.BlockSize+sha256.Size {
		return nil, false
	}

	// [Min] 首先从 ticket 中获取 keyName ，iv ，mac
	keyName := encrypted[:ticketKeyNameLen]
	iv := encrypted[ticketKeyNameLen : ticketKeyNameLen+aes.BlockSize]
	macBytes := encrypted[len(encrypted)-sha256.Size:]

	// [Min] 根据 keyName 从 config 中找到当时用于加密 sessionState 的 key
	keys := c.config.ticketKeys()
	keyIndex := -1
	for i, candidateKey := range keys {
		if bytes.Equal(keyName, candidateKey.keyName[:]) {
			keyIndex = i
			break
		}
	}

	if keyIndex == -1 {
		return nil, false
	}
	key := &keys[keyIndex]

	// [Min] 找到 key 后，首先校验 HMAC
	mac := hmac.New(sha256.New, key.hmacKey[:])
	mac.Write(encrypted[:len(encrypted)-sha256.Size])
	expected := mac.Sum(nil)

	if subtle.ConstantTimeCompare(macBytes, expected) != 1 {
		return nil, false
	}

	// [Min] HMAC 没问题，再解密 sessionState
	block, err := aes.NewCipher(key.aesKey[:])
	if err != nil {
		return nil, false
	}
	ciphertext := encrypted[ticketKeyNameLen+aes.BlockSize : len(encrypted)-sha256.Size]
	plaintext := ciphertext
	cipher.NewCTR(block, iv).XORKeyStream(plaintext, ciphertext)

	// [Min] 反序列化得到 sessionState，并标明 usedOldKey，0 表示 key 正常无需重制刷新，其他的都是老的 key，后续会以最新的 key 重制 ticket，并让客户端同步
	state := &sessionState{usedOldKey: keyIndex > 0}
	ok := state.unmarshal(plaintext)
	return state, ok
}
