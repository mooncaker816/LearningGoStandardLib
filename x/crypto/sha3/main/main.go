package main

import (
	"fmt"

	"golang.org/x/crypto/sha3"
)

func main() {
	h := sha3.New512()
	// [Min] 连续写入并即时计算当前SHA3
	h.Write([]byte{'a'})
	ha := h.Sum(nil)
	h.Write([]byte{'b'})
	hab := h.Sum(nil)
	h.Write([]byte{'c'})
	habc := h.Sum(nil)
	// [Min] 阶段性SHA3和直接计算对应数据的SHA3完全相同
	fmt.Printf("%x\n", ha)
	fmt.Printf("%x\n", sha3.Sum512([]byte{'a'}))
	fmt.Printf("%x\n", hab)
	fmt.Printf("%x\n", sha3.Sum512([]byte{'a', 'b'}))
	fmt.Printf("%x\n", habc)
	fmt.Printf("%x\n", sha3.Sum512([]byte{'a', 'b', 'c'}))

	// [Min] Sum256和ShakeSum256在相同输出长度情况下，摘要是不同的，因为他们的填充首字节不同
	s256 := sha3.Sum256([]byte{'a'})
	shake256 := make([]byte, 32)
	sha3.ShakeSum256(shake256, []byte{'a'})
	fmt.Printf("%x\n", s256)
	fmt.Printf("%x\n", shake256)
}
