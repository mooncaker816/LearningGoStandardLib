package hex

import "fmt"

func ExampleEncode() {
	src := []byte("abcdeABCDE12345")
	dst := make([]byte, EncodedLen(len(src)))
	len := Encode(dst, src)
	fmt.Println(len)
	fmt.Println(dst)
	fmt.Println(string(dst))
	// Output:
	// 30
	// [54 49 54 50 54 51 54 52 54 53 52 49 52 50 52 51 52 52 52 53 51 49 51 50 51 51 51 52 51 53]
	// 616263646541424344453132333435
}

func ExampleDecode() {
	src := []byte("616263646541424344453132333435")
	dst := make([]byte, DecodedLen(len(src)))
	len, err := Decode(dst, src)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(len)
	fmt.Println(string(dst))
	// Output:
	// 15
	// abcdeABCDE12345
}

func ExampleEncodeToString() {
	src := "abcdeABCDE12345"
	fmt.Println(EncodeToString([]byte(src)))
	// Output:
	// 616263646541424344453132333435
}

func ExampleDecodeString() {
	src := "616263646541424344453132333435"
	rst, err := DecodeString(src)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(rst)
	fmt.Println(string(rst))
	// Output:
	// [97 98 99 100 101 65 66 67 68 69 49 50 51 52 53]
	// abcdeABCDE12345
}
