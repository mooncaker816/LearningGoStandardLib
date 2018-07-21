package main

import (
	"fmt"

	"golang.org/x/crypto/sha3"
)

func main() {
	h := sha3.New512()
	h.Write([]byte{'a'})
	ha := h.Sum(nil)
	h.Write([]byte{'b'})
	hab := h.Sum(nil)
	h.Write([]byte{'c'})
	habc := h.Sum(nil)
	fmt.Printf("%x\n", ha)
	fmt.Printf("%x\n", sha3.Sum512([]byte{'a'}))
	fmt.Printf("%x\n", hab)
	fmt.Printf("%x\n", sha3.Sum512([]byte{'a', 'b'}))
	fmt.Printf("%x\n", habc)
	fmt.Printf("%x\n", sha3.Sum512([]byte{'a', 'b', 'c'}))

	s256 := sha3.Sum256([]byte{'a'})
	shake256 := make([]byte, 32)
	sha3.ShakeSum256(shake256, []byte{'a'})
	fmt.Printf("%x\n", s256)
	fmt.Printf("%x\n", shake256)
}
