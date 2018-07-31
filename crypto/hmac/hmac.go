// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*
Package hmac implements the Keyed-Hash Message Authentication Code (HMAC) as
defined in U.S. Federal Information Processing Standards Publication 198.
An HMAC is a cryptographic hash that uses a key to sign a message.
The receiver verifies the hash by recomputing it using the same key.

Receivers should be careful to use Equal to compare MACs in order to avoid
timing side-channels:

	// CheckMAC reports whether messageMAC is a valid HMAC tag for message.
	func CheckMAC(message, messageMAC, key []byte) bool {
		mac := hmac.New(sha256.New, key)
		mac.Write(message)
		expectedMAC := mac.Sum(nil)
		return hmac.Equal(messageMAC, expectedMAC)
	}
*/
package hmac

import (
	"crypto/subtle"
	"hash"
)

// FIPS 198-1:
// http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf

// key is zero padded to the block size of the hash function
// ipad = 0x36 byte repeated for key length
// opad = 0x5c byte repeated for key length
// hmac = H([key ^ opad] H([key ^ ipad] text))

/* [Min]
STEPS						STEP-BY-STEP DESCRIPTION
Step 1		If the length of K = B: set K0 = K. Goto step 4.
Step 2		If the length of K > B: hash K to obtain an L byte string, then append (B-L) zeros to create a B-byte string K0 (i.e., K0 = H(K) || 00...00). Go to step 4.
Step 3		If the length of K < B: append zeros to the end of K to create a B-byte string K0 (e.g., if K is 20 bytes in length and B = 64, then K will be appended with 44 zero bytes x’00’).
Step 4		Exclusive-Or K0 with ipad to produce a B-byte string: K0 ⊕ ipad.
Step 5		Append the stream of data 'text' to the string resulting from step 4: (K0 ⊕ ipad) || text.
Step 6		Apply H to the stream generated in step 5: H((K0 ⊕ ipad) || text).
Step 7		Exclusive-Or K0 with opad: K0 ⊕ opad.
Step 8		Append the result from step 6 to step 7: (K0 ⊕ opad) || H((K0 ⊕ ipad) || text).
Step 9		Apply H to the result from step 8: H((K0 ⊕ opad )|| H((K0 ⊕ ipad) || text)).
*/

type hmac struct {
	size         int       // [Min] HMAC的大小，由底层选用的hash决定
	blocksize    int       // [Min] 计算hash时的分块大小，由底层选用的hash决定
	opad, ipad   []byte    // [Min] key 和 opad，ipad 异或后的结果
	outer, inner hash.Hash // [Min] 底层使用的hash
}

// [Min] 计算in的HMAC，返回的结果为原始的in+HMAC
func (h *hmac) Sum(in []byte) []byte {
	origLen := len(in)
	in = h.inner.Sum(in)
	h.outer.Reset()
	h.outer.Write(h.opad)
	h.outer.Write(in[origLen:])
	return h.outer.Sum(in[:origLen])
}

// [Min] 将p写入inner hash中，计算即时hash值，保留状态
func (h *hmac) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

func (h *hmac) Size() int { return h.size }

func (h *hmac) BlockSize() int { return h.blocksize }

func (h *hmac) Reset() {
	h.inner.Reset()
	h.inner.Write(h.ipad)
}

// New returns a new HMAC hash using the given hash.Hash type and key.
// Note that unlike other hash implementations in the standard library,
// the returned Hash does not implement encoding.BinaryMarshaler
// or encoding.BinaryUnmarshaler.
// [Min] 新建一个HMAC的计算载体
func New(h func() hash.Hash, key []byte) hash.Hash {
	hm := new(hmac)
	hm.outer = h()
	hm.inner = h()
	hm.size = hm.inner.Size()
	hm.blocksize = hm.inner.BlockSize()
	hm.ipad = make([]byte, hm.blocksize)
	hm.opad = make([]byte, hm.blocksize)
	if len(key) > hm.blocksize {
		// If key is too big, hash it.
		// [Min] 如果key的长度大于分块大小，计算key的hash
		hm.outer.Write(key)
		key = hm.outer.Sum(nil)
	}
	copy(hm.ipad, key)
	copy(hm.opad, key)
	// [Min] 准备好key ⊕ ipad，key ⊕ opad
	for i := range hm.ipad {
		hm.ipad[i] ^= 0x36
	}
	for i := range hm.opad {
		hm.opad[i] ^= 0x5c
	}
	// [Min] 将key ⊕ ipad写入inner hash中，以便持续计算后续 key ⊕ ipad || text 的hash
	hm.inner.Write(hm.ipad)
	return hm
}

// Equal compares two MACs for equality without leaking timing information.
func Equal(mac1, mac2 []byte) bool {
	// We don't have to be constant time if the lengths of the MACs are
	// different as that suggests that a completely different hash function
	// was used.
	return subtle.ConstantTimeCompare(mac1, mac2) == 1
}
