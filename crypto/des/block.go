// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package des

import "encoding/binary"

// [Min] DES加解密
func cryptBlock(subkeys []uint64, dst, src []byte, decrypt bool) {
	// [Min] 现将64位数据从src中写入uint64
	b := binary.BigEndian.Uint64(src)
	// [Min] 对这64位作初始排序
	b = permuteInitialBlock(b)
	// [Min] 分成左右两部分，各32位
	left, right := uint32(b>>32), uint32(b)

	// [Min] 这里向左循环移一位，是为了配合后面轮函数的逻辑
	// [Min] 轮函数中没有按照原始要求将32位right先按照expansionFunction扩至48位，再与48位子秘钥异或
	// [Min] 而是巧妙的将48位子秘钥扩充至64位，每个字节的低六位为48位的一部分
	// [Min] 然后与32位的right交错异或，从而获得与原始需求一致的48位数据
	// [Min] 又因为这里左移了一位，所以轮函数的值与left异或前，也需要左移一位，这一步在init中已经进行
	left = (left << 1) | (left >> 31)
	right = (right << 1) | (right >> 31)

	// [Min] 根据加解密和轮次，确定子秘钥的索引，调用feistel执行两轮加解密，一共执行16轮
	if decrypt {
		for i := 0; i < 8; i++ {
			left, right = feistel(left, right, subkeys[15-2*i], subkeys[15-(2*i+1)])
		}
	} else {
		for i := 0; i < 8; i++ {
			left, right = feistel(left, right, subkeys[2*i], subkeys[2*i+1])
		}
	}

	// [Min] 将之前循环左移的一位返回原位
	left = (left << 31) | (left >> 1)
	right = (right << 31) | (right >> 1)

	// switch left & right and perform final permutation
	// [Min] 最后调换左右并拼成一位uint64，再执行最后的排序，然后按大字节序写入dst中
	preOutput := (uint64(right) << 32) | uint64(left)
	binary.BigEndian.PutUint64(dst, permuteFinalBlock(preOutput))
}

// Encrypt one block from src into dst, using the subkeys.
// [Min] DES 加密
func encryptBlock(subkeys []uint64, dst, src []byte) {
	cryptBlock(subkeys, dst, src, false)
}

// Decrypt one block from src into dst, using the subkeys.
// [Min] DES 解密
func decryptBlock(subkeys []uint64, dst, src []byte) {
	cryptBlock(subkeys, dst, src, true)
}

// DES Feistel function
// [Min] 进行两轮加密
// [Min] l0,r0 ->
// [Min] l1 = r0, r1 = l0 XOR f(r0) ->
// [Min] l2 = r1, r2 = l1 XOR f(r1)
func feistel(l, r uint32, k0, k1 uint64) (lout, rout uint32) {
	var t uint32

	t = r ^ uint32(k0>>32)
	l ^= feistelBox[7][t&0x3f] ^
		feistelBox[5][(t>>8)&0x3f] ^
		feistelBox[3][(t>>16)&0x3f] ^
		feistelBox[1][(t>>24)&0x3f]

	t = ((r << 28) | (r >> 4)) ^ uint32(k0)
	l ^= feistelBox[6][(t)&0x3f] ^
		feistelBox[4][(t>>8)&0x3f] ^
		feistelBox[2][(t>>16)&0x3f] ^
		feistelBox[0][(t>>24)&0x3f]

	t = l ^ uint32(k1>>32)
	r ^= feistelBox[7][t&0x3f] ^
		feistelBox[5][(t>>8)&0x3f] ^
		feistelBox[3][(t>>16)&0x3f] ^
		feistelBox[1][(t>>24)&0x3f]

	t = ((l << 28) | (l >> 4)) ^ uint32(k1)
	r ^= feistelBox[6][(t)&0x3f] ^
		feistelBox[4][(t>>8)&0x3f] ^
		feistelBox[2][(t>>16)&0x3f] ^
		feistelBox[0][(t>>24)&0x3f]

	return l, r
}

// feistelBox[s][16*i+j] contains the output of permutationFunction
// for sBoxes[s][i][j] << 4*(7-s)
// [Min] feistelBox 由init函数初始化，用于轮函数中将48位数据映射到32位，并按需求排序
// [Min] 以6-bit为单位，将48-bit分为8组
// [Min] feistelBox的第一个索引和sBoxes的第一个索引一样，表示当前取值所属组的索引
// [Min] feistelBox的第二个索引的值是一个6-bit的值，其高位和低位两个bit组成的数为i，中间4个bit组成的数为j
// [Min] 由i，j可以从sBoxes中确定一个最大不超过4-bit的数，从而将6-bit映射到4-bit，也就可以将48bits映射到32bits
var feistelBox [8][64]uint32

// general purpose function to perform DES block permutations
// [Min] permutation中给定了bit位的序号，从src中依次挑出相同序号位的bit，
// [Min] 不够64位，以0补足高位，构成一个新的uint64
func permuteBlock(src uint64, permutation []uint8) (block uint64) {
	for position, n := range permutation {
		bit := (src >> n) & 1
		block |= bit << uint((len(permutation)-1)-position)
	}
	return
}

// [Min] 准备计算轮函数值的参数，一个轮函数的值可以看成是8个4-bit组成的32位的值
// [Min] 每一个4-bit由Select function确定
// [Min] init会提前将获取Select function的值的输入条件由i,j转化为其对应的6-bit数t
// [Min] 并且将该select function的输出值（4-bit）移动到轮函数输出值（32-bit）的对应位置，
// [Min] 同时按筛选排序规则permutationFunction处理，存入feistelBox[s][t]，即为轮函数的部分输出值
// [Min] 当轮函数得到B0...B7后，即为t索引的值，此时只要去feistelBox找到对应的值再求异或和即为轮函数的输出32 bits
func init() {
	for s := range sBoxes {
		for i := 0; i < 4; i++ {
			for j := 0; j < 16; j++ {
				f := uint64(sBoxes[s][i][j]) << (4 * (7 - uint(s)))
				f = permuteBlock(f, permutationFunction[:])

				// Row is determined by the 1st and 6th bit.
				// Column is the middle four bits.
				// [Min] 将i,j转化为对应的6-bit t
				row := uint8(((i & 2) << 4) | i&1)
				col := uint8(j << 1)
				t := row | col

				// The rotation was performed in the feistel rounds, being factored out and now mixed into the feistelBox.
				// [Min] 由于在调用feistel之前，left和right都左移了一位，
				// [Min] 所以在和轮函数的值作异或的时候，轮函数的值也要左移一位
				f = (f << 1) | (f >> 31)

				// [Min] 轮函数的部分输出，部分对应的关键位含有有效值，其他都为0
				// [Min] 所以将8部分异或后，即为轮函数的最终值
				feistelBox[s][t] = uint32(f)
			}
		}
	}
}

// permuteInitialBlock is equivalent to the permutation defined
// by initialPermutation.
// [Min] 初始排序，这里通过一系列位运算达到与直接给出的排序数组initialPermutation一致的效果
func permuteInitialBlock(block uint64) uint64 {
	// block = b7 b6 b5 b4 b3 b2 b1 b0 (8 bytes)
	b1 := block >> 48 // [Min] 0 0 0 0 0 0 b7 b6
	b2 := block << 48 // [Min] b1 b0 0 0 0 0 0 0
	// [Min] b7 b6 b5 b4 b3 b2 b1 b0 ⊕
	// [Min] 0  0  0  0  0  0  b7 b6 ⊕
	// [Min] b1 b0 0  0  0  0  0  0  ⊕
	// [Min] b7 b6 0  0  0  0  0  0  ⊕
	// [Min] 0  0  0  0  0  0  b1 b0
	// [Min] --------------------------
	// [Min] b1 b0 b5 b4 b3 b2 b7 b6
	block ^= b1 ^ b2 ^ b1<<48 ^ b2>>48

	// block = b1 b0 b5 b4 b3 b2 b7 b6
	b1 = block >> 32 & 0xff00ff // [Min] 0 0 0 0 0 b0 0 b4
	b2 = (block & 0xff00ff00)   // [Min] 0 0 0 0 b3 0 b7 0
	// [Min] b1 b0 b5 b4 b3 b2 b7 b6
	// [Min] 0  b0 0  b4 0  0  0  0
	// [Min] 0  0  0  0  b3 0  b7 0
	// [Min] 0  0  0  0  b0 0  b4 0
	// [Min] 0  b3 0  b7 0  0  0  0
	// [Min] -------------------------
	// [Min] b1 b3 b5 b7 b0 b2 b4 b6
	block ^= b1<<32 ^ b2 ^ b1<<8 ^ b2<<24 // exchange b0 b4 with b3 b7

	// block is now b1 b3 b5 b7 b0 b2 b4 b7, the permutation:
	//                  ...  8
	//                  ... 24
	//                  ... 40
	//                  ... 56
	//  7  6  5  4  3  2  1  0
	// 23 22 21 20 19 18 17 16
	//                  ... 32
	//                  ... 48

	// exchange 4,5,6,7 with 32,33,34,35 etc.
	b1 = block & 0x0f0f00000f0f0000
	b2 = block & 0x0000f0f00000f0f0
	block ^= b1 ^ b2 ^ b1>>12 ^ b2<<12

	// block is the permutation:
	//
	//   [+8]         [+40]
	//
	//  7  6  5  4
	// 23 22 21 20
	//  3  2  1  0
	// 19 18 17 16    [+32]

	// exchange 0,1,4,5 with 18,19,22,23
	b1 = block & 0x3300330033003300
	b2 = block & 0x00cc00cc00cc00cc
	block ^= b1 ^ b2 ^ b1>>6 ^ b2<<6

	// block is the permutation:
	// 15 14
	// 13 12
	// 11 10
	//  9  8
	//  7  6
	//  5  4
	//  3  2
	//  1  0 [+16] [+32] [+64]

	// exchange 0,2,4,6 with 9,11,13,15:
	b1 = block & 0xaaaaaaaa55555555
	block ^= b1 ^ b1>>33 ^ b1<<33

	// block is the permutation:
	// 6 14 22 30 38 46 54 62
	// 4 12 20 28 36 44 52 60
	// 2 10 18 26 34 42 50 58
	// 0  8 16 24 32 40 48 56
	// 7 15 23 31 39 47 55 63
	// 5 13 21 29 37 45 53 61
	// 3 11 19 27 35 43 51 59
	// 1  9 17 25 33 41 49 57
	return block
}

// permuteInitialBlock is equivalent to the permutation defined
// by finalPermutation.
// [Min] 最终排序，这里通过一系列位运算达到与直接给出的排序数组finalPermutation一致的效果
// [Min] 最终排序是初始排序的逆运算，将初始排序中打乱的顺序还原
func permuteFinalBlock(block uint64) uint64 {
	// Perform the same bit exchanges as permuteInitialBlock
	// but in reverse order.
	b1 := block & 0xaaaaaaaa55555555
	block ^= b1 ^ b1>>33 ^ b1<<33

	b1 = block & 0x3300330033003300
	b2 := block & 0x00cc00cc00cc00cc
	block ^= b1 ^ b2 ^ b1>>6 ^ b2<<6

	b1 = block & 0x0f0f00000f0f0000
	b2 = block & 0x0000f0f00000f0f0
	block ^= b1 ^ b2 ^ b1>>12 ^ b2<<12

	b1 = block >> 32 & 0xff00ff
	b2 = (block & 0xff00ff00)
	block ^= b1<<32 ^ b2 ^ b1<<8 ^ b2<<24

	b1 = block >> 48
	b2 = block << 48
	block ^= b1 ^ b2 ^ b1<<48 ^ b2>>48
	return block
}

// creates 16 28-bit blocks rotated according
// to the rotation schedule
// [Min] 每一轮次生成子秘钥对应的循环左移位数由ksRotations决定
// [Min] 根据ksRotations，生成Ci，Di
// [Min] 这里需要注意我们的C，D都是28位的，但是存储在32位的uint32中，左移时要注意
func ksRotate(in uint32) (out []uint32) {
	out = make([]uint32, 16)
	last := in
	for i := 0; i < 16; i++ {
		// 28-bit circular left shift
		// [Min] 28位总长对应的循环左移
		left := (last << (4 + ksRotations[i])) >> 4
		right := (last << 4) >> (32 - ksRotations[i])
		out[i] = left | right
		last = out[i]
	}
	return
}

// creates 16 56-bit subkeys from the original key
// [Min] 根据给定的64位秘钥，生成16个子秘钥
func (c *desCipher) generateSubkeys(keyBytes []byte) {
	// apply PC1 permutation to key
	// [Min] 按大字节序读取秘钥为一个uint64的数
	key := binary.BigEndian.Uint64(keyBytes)
	// [Min] 根据PC1获得按位排过序的56位有效位的key，存在uint64的低56位
	permutedKey := permuteBlock(key, permutedChoice1[:])

	// rotate halves of permuted key according to the rotation schedule
	// [Min] 将上述56位有效key拆分为左右C，D两部分，各28位，分别存在两个uint32的低28位
	// [Min] 再分别对C，D调用ksRotate，计算出C1...C16,D1...D16，存入leftRotations和rightRotations
	leftRotations := ksRotate(uint32(permutedKey >> 28))
	rightRotations := ksRotate(uint32(permutedKey<<4) >> 4)

	// generate subkeys
	// [Min] 最后根据PC2，从每一组CiDi组成的56位有效秘钥中得出48位有效子秘钥，
	// [Min] 再分配到
	for i := 0; i < 16; i++ {
		// combine halves to form 56-bit input to PC2
		// [Min] 拼接CD，存在uint64的低56位
		pc2Input := uint64(leftRotations[i])<<28 | uint64(rightRotations[i])
		// apply PC2 permutation to 7 byte input
		// [Min] 从上述56位中按PC2，筛选排序得最终48位有效子秘钥，
		// [Min]
		c.subkeys[i] = unpack(permuteBlock(pc2Input, permutedChoice2[:]))
	}
}

// Expand 48-bit input to 64-bit, with each 6-bit block padded by extra two bits at the top.
// By doing so, we can have the input blocks (four bits each), and the key blocks (six bits each) well-aligned without
// extra shifts/rotations for alignments.
// [Min] 将48位分为8组，一组6-bit，将6-bit高位填充2位（具体数值无关紧要），再按以下顺序组成64位的值
func unpack(x uint64) uint64 {
	var result uint64

	result = ((x>>(6*1))&0xff)<<(8*0) | // [Min] x:6-13 -> result:0-7
		((x>>(6*3))&0xff)<<(8*1) | // [Min] x:18-25 -> result:8-15
		((x>>(6*5))&0xff)<<(8*2) | // [Min] x:30-37 -> result:16-23
		((x>>(6*7))&0xff)<<(8*3) | // [Min] x:42-49 -> result:24-31
		((x>>(6*0))&0xff)<<(8*4) | // [Min] x:0-7 -> result:32-39
		((x>>(6*2))&0xff)<<(8*5) | // [Min] x:12-19 -> result:40-47
		((x>>(6*4))&0xff)<<(8*6) | // [Min] x:24-31 -> result:48-55
		((x>>(6*6))&0xff)<<(8*7) // [Min] x:36-43 -> result:56-63

	return result
}
