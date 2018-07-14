// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package json

// JSON value parser state machine.
// Just about at the limit of what is reasonable to write by hand.
// Some parts are a bit tedious, but overall it nicely factors out the
// otherwise common code from the multiple scanning functions
// in this package (Compact, Indent, checkValid, nextValue, etc).
//
// This file starts with two simple examples using the scanner
// before diving into the scanner itself.

import "strconv"

// Valid reports whether data is a valid JSON encoding.
// [Min] 检查 data 是否是有效的 JSON
func Valid(data []byte) bool {
	return checkValid(data, &scanner{}) == nil
}

// checkValid verifies that data is valid JSON-encoded data.
// scan is passed in for use by checkValid to avoid an allocation.
// [Min] 重置状态机，对每一个字符进行状态检查，状态机中的状态检查函数step由当前字符根据当前正在检查的目标的语法动态确定
func checkValid(data []byte, scan *scanner) error {
	scan.reset()
	for _, c := range data {
		scan.bytes++
		if scan.step(scan, c) == scanError {
			return scan.err
		}
	}
	if scan.eof() == scanError {
		return scan.err
	}
	return nil
}

// nextValue splits data after the next whole JSON value,
// returning that value and the bytes that follow it as separate slices.
// scan is passed in for use by nextValue to avoid an allocation.
func nextValue(data []byte, scan *scanner) (value, rest []byte, err error) {
	scan.reset()
	for i, c := range data {
		v := scan.step(scan, c)
		if v >= scanEndObject {
			switch v {
			// probe the scanner with a space to determine whether we will
			// get scanEnd on the next character. Otherwise, if the next character
			// is not a space, scanEndTop allocates a needless error.
			case scanEndObject, scanEndArray:
				if scan.step(scan, ' ') == scanEnd {
					return data[:i+1], data[i+1:], nil
				}
			case scanError:
				return nil, nil, scan.err
			case scanEnd:
				return data[:i], data[i:], nil
			}
		}
	}
	if scan.eof() == scanError {
		return nil, nil, scan.err
	}
	return data, nil, nil
}

// A SyntaxError is a description of a JSON syntax error.
type SyntaxError struct {
	msg    string // description of error
	Offset int64  // error occurred after reading Offset bytes
}

func (e *SyntaxError) Error() string { return e.msg }

// A scanner is a JSON scanning state machine.
// Callers call scan.reset() and then pass bytes in one at a time
// by calling scan.step(&scan, c) for each byte.
// The return value, referred to as an opcode, tells the
// caller about significant parsing events like beginning
// and ending literals, objects, and arrays, so that the
// caller can follow along if it wishes.
// The return value scanEnd indicates that a single top-level
// JSON value has been completed, *before* the byte that
// just got passed in.  (The indication must be delayed in order
// to recognize the end of numbers: is 123 a whole value or
// the beginning of 12345e+6?).
type scanner struct {
	// The step is a func to be called to execute the next transition.
	// Also tried using an integer constant and a single func
	// with a switch, but using the func directly was 10% faster
	// on a 64-bit Mac Mini, and it's nicer to read.
	step func(*scanner, byte) int

	// Reached end of top-level value.
	endTop bool

	// Stack of what we're in the middle of - array values, object keys, object values.
	parseState []int

	// Error that happened, if any.
	err error

	// 1-byte redo (see undo method)
	redo      bool
	redoCode  int
	redoState func(*scanner, byte) int

	// total bytes consumed, updated by decoder.Decode
	bytes int64
}

// These values are returned by the state transition functions
// assigned to scanner.state and the method scanner.eof.
// They give details about the current state of the scan that
// callers might be interested to know about.
// It is okay to ignore the return value of any particular
// call to scanner.state: if one call returns scanError,
// every subsequent call will return scanError too.
const (
	// Continue.
	scanContinue     = iota // uninteresting byte
	scanBeginLiteral        // end implied by next result != scanContinue
	scanBeginObject         // begin object
	scanObjectKey           // just finished object key (string)
	scanObjectValue         // just finished non-last object value
	scanEndObject           // end object (implies scanObjectValue if possible)
	scanBeginArray          // begin array
	scanArrayValue          // just finished array value
	scanEndArray            // end array (implies scanArrayValue if possible)
	scanSkipSpace           // space byte; can skip; known to be last "continue" result

	// Stop.
	scanEnd   // top-level value ended *before* this byte; known to be first "stop" result
	scanError // hit an error, scanner.err.
)

// These values are stored in the parseState stack.
// They give the current state of a composite value
// being scanned. If the parser is inside a nested value
// the parseState describes the nested state, outermost at entry 0.
// [Min] 对于混合型结构（内嵌对象或数组），除了要记录下扫描状态外，
// [Min] 还需要完整记录下他的结构，parseState 就是用来记录这个的
const (
	parseObjectKey   = iota // parsing object key (before colon)
	parseObjectValue        // parsing object value (after colon)
	parseArrayValue         // parsing array value
)

// reset prepares the scanner for use.
// It must be called before calling s.step.
// [Min] 重置 scanner，需在调用 step 之前调用
func (s *scanner) reset() {
	s.step = stateBeginValue
	s.parseState = s.parseState[0:0]
	s.err = nil
	s.redo = false
	s.endTop = false
}

// eof tells the scanner that the end of input has been reached.
// It returns a scan status just as s.step does.
// [Min] 用来结束状态机，如果有错，直接报错，如果 endTop 已经为真，说明 json 串已经解析成功
// [Min] 如果 endTop 不为真，我们不能判断该 json 串是否解析成功，可能恰好整个字符串扫描完了，
// [Min] 但endTop还没来得及在下一次 step 执行过程中修改为 true
// [Min] 这时，我们只要尝试以空格执行当前的 step 函数，再去判断 endTop 的真假就能判断 json 串是否解析成功
func (s *scanner) eof() int {
	if s.err != nil {
		return scanError
	}
	if s.endTop {
		return scanEnd
	}
	s.step(s, ' ')
	if s.endTop {
		return scanEnd
	}
	if s.err == nil {
		s.err = &SyntaxError{"unexpected end of JSON input", s.bytes}
	}
	return scanError
}

// pushParseState pushes a new parse state p onto the parse stack.
// [Min] 将 parse state 压入状态机的 parseState 中
func (s *scanner) pushParseState(p int) {
	s.parseState = append(s.parseState, p)
}

// popParseState pops a parse state (already obtained) off the stack
// and updates s.step accordingly.
// [Min] 将 parseState 中的最后一个状态弹出，修改 redo 为 false
// [Min] 如果此时 parseState 为空，置下一个检查函数 step 为 stateEndTop，用于检查是否已到了 EndTop，设 endTop 为真
// [Min] 否则置下一检查函数 step 为 stateEndValue，用于检查是否是 EndValue
func (s *scanner) popParseState() {
	n := len(s.parseState) - 1
	s.parseState = s.parseState[0:n]
	s.redo = false
	if n == 0 {
		s.step = stateEndTop
		s.endTop = true
	} else {
		s.step = stateEndValue
	}
}

// [Min] 判断是否为 space
func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// stateBeginValueOrEmpty is the state after reading `[`.
// [Min] 如果是 space，返回状态 scanSkipSpace 跳过该 space
// [Min] 如果是 ']'，说明是空值，检查 EndValue，并返回状态
// [Min] 其他，检查 BeginValue
func stateBeginValueOrEmpty(s *scanner, c byte) int {
	if c <= ' ' && isSpace(c) {
		return scanSkipSpace
	}
	if c == ']' {
		return stateEndValue(s, c)
	}
	return stateBeginValue(s, c)
}

// stateBeginValue is the state at the beginning of the input.
// [Min] 检查值，值可能包含一个对象{},也可能含有多个值[]
func stateBeginValue(s *scanner, c byte) int {
	if c <= ' ' && isSpace(c) {
		return scanSkipSpace
	}
	switch c {
	case '{':
		// [Min] 如果是{开头，则说明内嵌了一个对象，需要解析此对象，
		// [Min] 将下一步设为stateBeginStringOrEmpty（用来解析对象的 key），返回状态scanBeginObject
		// [Min] 同时将 parseState 记录为parseObjectKey
		s.step = stateBeginStringOrEmpty
		s.pushParseState(parseObjectKey)
		return scanBeginObject
	case '[':
		// [Min] 如果是[开头，则说明接下来是一个数组，需要解析此数组，
		// [Min] 将下一步设为 stateBeginValueOrEmpty，返回状态scanBeginArray
		// [Min] 同时将 parseState 记录为parseArrayValue
		s.step = stateBeginValueOrEmpty
		s.pushParseState(parseArrayValue)
		return scanBeginArray
	case '"':
		// [Min] 如果是"开头，说明记下来的是真正的字面量值，
		// [Min] 将下一步设为 stateInString，返回状态scanBeginLiteral
		s.step = stateInString
		return scanBeginLiteral
	case '-':
		// [Min] 如果是-，说明接下来是一个负数
		// [Min] 将下一步设为 stateNeg 处理负数，返回状态scanBeginLiteral
		s.step = stateNeg
		return scanBeginLiteral
	case '0': // beginning of 0.123
		// [Min] 如果是0，
		// [Min] 将下一步设为 state0 用来处理字面量中碰到的0，返回状态scanBeginLiteral
		s.step = state0
		return scanBeginLiteral
	case 't': // beginning of true
		// [Min] 如果是t，对应的值可能是 true
		// [Min] 将下一步设为 stateT 用来开启对 true 的解析，之后的逻辑会逐个检查后续字符是否依次为 r，u，e
		// [Min] 返回状态scanBeginLiteral
		s.step = stateT
		return scanBeginLiteral
	case 'f': // beginning of false
		// [Min] 如果是f，对应的值可能是 false
		// [Min] 将下一步设为 stateF 用来开启对 false 的解析，之后的逻辑会逐个检查后续字符是否依次为 a，l，s，e
		// [Min] 返回状态scanBeginLiteral
		s.step = stateF
		return scanBeginLiteral
	case 'n': // beginning of null
		// [Min] 如果是n，对应的值可能是 null
		// [Min] 将下一步设为 stateN 用来开启对 null 的解析，之后的逻辑会逐个检查后续字符是否依次为 u，l，l
		// [Min] 返回状态scanBeginLiteral
		s.step = stateN
		return scanBeginLiteral
	}
	// [Min] 解析以非0数字开始的数值，置 step 为 state1，返回状态scanBeginLiteral
	if '1' <= c && c <= '9' { // beginning of 1234.5
		s.step = state1
		return scanBeginLiteral
	}
	return s.error(c, "looking for beginning of value")
}

// stateBeginStringOrEmpty is the state after reading `{`.
// [Min] 如果是space，则返回scanSkipSpace
// [Min] 如果是},说明是空对象（认为没有key，值为空），在 parseState 中将刚刚压入的 parseObjectKey 改为 parseObjectValue
// [Min] 再结束对该值的解析 stateEndValue
// [Min] 其他按字符串开始解析
func stateBeginStringOrEmpty(s *scanner, c byte) int {
	if c <= ' ' && isSpace(c) {
		return scanSkipSpace
	}
	if c == '}' {
		n := len(s.parseState)
		s.parseState[n-1] = parseObjectValue
		return stateEndValue(s, c)
	}
	return stateBeginString(s, c)
}

// stateBeginString is the state after reading `{"key": value,`.
// [Min] 如果是 space，step 不变，返回scanSkipSpace状态
// [Min] 如果是 "，说明接下来的就是字符串字面量，step 改为 stateInString，返回scanBeginLiteral
// [Min] 其他报错
func stateBeginString(s *scanner, c byte) int {
	if c <= ' ' && isSpace(c) {
		return scanSkipSpace
	}
	if c == '"' {
		s.step = stateInString
		return scanBeginLiteral
	}
	return s.error(c, "looking for beginning of object key string")
}

// stateEndValue is the state after completing a value,
// such as after reading `{}` or `true` or `["x"`.
// [Min] 当一个值成功解析后的处理
func stateEndValue(s *scanner, c byte) int {
	n := len(s.parseState)
	// [Min] 如果到目前为止，已经能够解析出一个完整的 json（开始到现在每一层结构都已经解析成功），置 step 为 stateEndTop，后续应该都为space
	if n == 0 {
		// Completed top-level before the current byte.
		s.step = stateEndTop
		s.endTop = true
		return stateEndTop(s, c)
	}
	// [Min] 如果是space，返回 scanSkipSpace ，继续 stateEndValue
	if c <= ' ' && isSpace(c) {
		s.step = stateEndValue
		return scanSkipSpace
	}
	ps := s.parseState[n-1]
	// [Min] 获取当前解析的是一个什么结构，处于该结构的哪一部分
	switch ps {
	case parseObjectKey:
		// [Min] 如果是parseObjectKey，且当前字符为':'，
		// [Min] 说明我们已经完成了对该对象中某一键的解析，后面应该是该键对应的值，
		// [Min] 将结构状态改为 parseObjectValue，step 改为 stateBeginValue
		// [Min] 并返回当前状态 scanObjectKey，表明我们完成了 objectKey 的解析
		// [Min] 否则报错
		if c == ':' {
			s.parseState[n-1] = parseObjectValue
			s.step = stateBeginValue
			return scanObjectKey
		}
		return s.error(c, "after object key")
	case parseObjectValue:
		// [Min] 如果是 parseObjectValue，说明我们刚完成了对某一键值的解析
		// [Min] 如果当前是','，说明后面还有键值对，对下一个键进行解析，
		// [Min] 替换当前结构状态为parseObjectKey，改 step 为 stateBeginString，
		// [Min] 返回scanObjectValue
		// [Min] 如果当前是'}'，说明该对象已经解析完成，将用来记录当前对象结构状态的元素弹出
		// [Min] 返回 scanEndObject
		// [Min] 其他报错
		if c == ',' {
			s.parseState[n-1] = parseObjectKey
			s.step = stateBeginString
			return scanObjectValue
		}
		if c == '}' {
			s.popParseState()
			return scanEndObject
		}
		return s.error(c, "after object key:value pair")
	case parseArrayValue:
		// [Min] 如果是parseArrayValue，说明我们完成了数组中一个元素的解析，
		// [Min] 后面要么是','，表示还有元素，要么是']'，表示数组结束
		if c == ',' {
			// [Min] ','继续元素值的解析
			s.step = stateBeginValue
			return scanArrayValue
		}
		if c == ']' {
			// [Min] ']'结束数组解析，从 parseState 中弹出用来记录该数组层次结构的元素
			s.popParseState()
			return scanEndArray
		}
		return s.error(c, "after array element")
	}
	return s.error(c, "")
}

// stateEndTop is the state after finishing the top-level value,
// such as after reading `{}` or `[1,2,3]`.
// Only space characters should be seen now.
// [Min] 只有当 parseState 为空的时候，才会调用stateEndTop
// [Min] parseState 为空，说明该 json 字符串中的每一层结构都已经解析成功，
// [Min] 后续碰到的必须是 space，否则就报错
func stateEndTop(s *scanner, c byte) int {
	if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
		// Complain about non-space byte on next call.
		s.error(c, "after top-level value")
	}
	return scanEnd
}

// stateInString is the state after reading `"`.
// [Min] 解析字符串内容
// [Min] 如果是"，说明字符串字面量结束，置 step 为 stateEndValue 返回 scanContinue
// [Min] 如果是\，说明是一个转义字符，置 step 为 stateInStringEsc 返回 scanContinue
// [Min] 如果小于 0x20，无效字符报错
// [Min] 其他为有效字符， step 不变，返回scanContinue继续解析
func stateInString(s *scanner, c byte) int {
	if c == '"' {
		s.step = stateEndValue
		return scanContinue
	}
	if c == '\\' {
		s.step = stateInStringEsc
		return scanContinue
	}
	if c < 0x20 {
		return s.error(c, "in string literal")
	}
	return scanContinue
}

// stateInStringEsc is the state after reading `"\` during a quoted string.
// [Min] 解析转义字符
// [Min] 如果是\b,\f,\n,\r,\t,\\,\/,\"，说明有效的转义字符解析完毕，
// [Min] 置 step 为 stateInString，返回scanContinue继续解析字符串
// [Min] 如果碰到的是 u（小写后面接2个字节对应的4个十六进制数值，默认高位2个字节全是0），说明是一个 unicode 字符，置 step 为stateInStringEscU，
// [Min] 开始解析代表 unicode 字符的数值部分
// [Min] 理论上一个完整的 unicode 由4个字节（8个十六进制数）表示，这里只支持能表示成 0000xxxx 的字符
func stateInStringEsc(s *scanner, c byte) int {
	switch c {
	case 'b', 'f', 'n', 'r', 't', '\\', '/', '"':
		s.step = stateInString
		return scanContinue
	case 'u':
		s.step = stateInStringEscU
		return scanContinue
	}
	return s.error(c, "in string escape code")
}

// stateInStringEscU is the state after reading `"\u` during a quoted string.
// [Min]解析 unicode 码值的第一个十六进制数
func stateInStringEscU(s *scanner, c byte) int {
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
		s.step = stateInStringEscU1
		return scanContinue
	}
	// numbers
	return s.error(c, "in \\u hexadecimal character escape")
}

// stateInStringEscU1 is the state after reading `"\u1` during a quoted string.
// [Min]解析 unicode 码值的第二个十六进制数
func stateInStringEscU1(s *scanner, c byte) int {
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
		s.step = stateInStringEscU12
		return scanContinue
	}
	// numbers
	return s.error(c, "in \\u hexadecimal character escape")
}

// stateInStringEscU12 is the state after reading `"\u12` during a quoted string.
// [Min]解析 unicode 码值的第三个十六进制数
func stateInStringEscU12(s *scanner, c byte) int {
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
		s.step = stateInStringEscU123
		return scanContinue
	}
	// numbers
	return s.error(c, "in \\u hexadecimal character escape")
}

// stateInStringEscU123 is the state after reading `"\u123` during a quoted string.
// [Min]解析 unicode 码值的第四个十六进制数，成功继续继续剩余的字符串
func stateInStringEscU123(s *scanner, c byte) int {
	if '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F' {
		s.step = stateInString
		return scanContinue
	}
	// numbers
	return s.error(c, "in \\u hexadecimal character escape")
}

// stateNeg is the state after reading `-` during a number.
// [Min] 解析负数的数字部分
func stateNeg(s *scanner, c byte) int {
	if c == '0' {
		s.step = state0
		return scanContinue
	}
	if '1' <= c && c <= '9' {
		s.step = state1
		return scanContinue
	}
	return s.error(c, "in numeric literal")
}

// state1 is the state after reading a non-zero integer during a number,
// such as after reading `1` or `100` but not `0`.
// [Min] 解析一个非0开始的数值字面量，直到碰到非数字，转为 state0，可能是.,e,E
func state1(s *scanner, c byte) int {
	if '0' <= c && c <= '9' {
		s.step = state1
		return scanContinue
	}
	return state0(s, c)
}

// state0 is the state after reading `0` during a number.
// [Min] 如果是.，转为stateDot，如果是 e/E，转为stateE，其他转为stateEndValue，结束该数值的解析
func state0(s *scanner, c byte) int {
	if c == '.' {
		s.step = stateDot
		return scanContinue
	}
	if c == 'e' || c == 'E' {
		s.step = stateE
		return scanContinue
	}
	return stateEndValue(s, c)
}

// stateDot is the state after reading the integer and decimal point in a number,
// such as after reading `1.`.
// [Min] 解析小数部分，小数点后第一个字符必须为数字，后面可以有表示科学记数法的 e/E
func stateDot(s *scanner, c byte) int {
	// [Min] 数字转为stateDot0
	if '0' <= c && c <= '9' {
		s.step = stateDot0
		return scanContinue
	}
	return s.error(c, "after decimal point in numeric literal")
}

// stateDot0 is the state after reading the integer, decimal point, and subsequent
// digits of a number, such as after reading `3.14`.
// [Min] 数字继续，e/E 转为stateE，其他转stateEndValue，结束该数值的解析
func stateDot0(s *scanner, c byte) int {
	if '0' <= c && c <= '9' {
		return scanContinue
	}
	if c == 'e' || c == 'E' {
		s.step = stateE
		return scanContinue
	}
	return stateEndValue(s, c)
}

// stateE is the state after reading the mantissa and e in a number,
// such as after reading `314e` or `0.314e`.
// [Min] 如果是+，-，转stateESign，继续下一个字符，否则直接解析e后面的数字
func stateE(s *scanner, c byte) int {
	if c == '+' || c == '-' {
		s.step = stateESign
		return scanContinue
	}
	return stateESign(s, c)
}

// stateESign is the state after reading the mantissa, e, and sign in a number,
// such as after reading `314e-` or `0.314e+`.
// [Min]解析科学计数法中的数字，第一位必须是数字
func stateESign(s *scanner, c byte) int {
	if '0' <= c && c <= '9' {
		s.step = stateE0
		return scanContinue
	}
	return s.error(c, "in exponent of numeric literal")
}

// stateE0 is the state after reading the mantissa, e, optional sign,
// and at least one digit of the exponent in a number,
// such as after reading `314e-2` or `0.314e+1` or `3.14e0`.
// [Min] 科学计数法的数字解析，如果不是数字调用stateEndValue结束该数值的解析
func stateE0(s *scanner, c byte) int {
	if '0' <= c && c <= '9' {
		return scanContinue
	}
	return stateEndValue(s, c)
}

// stateT is the state after reading `t`.
// [Min] 解析 true 时，判断 t 后面紧跟的是不是 r，
// [Min] 是就置 step 为 stateTr 继续后续解析，否就报错
func stateT(s *scanner, c byte) int {
	if c == 'r' {
		s.step = stateTr
		return scanContinue
	}
	return s.error(c, "in literal true (expecting 'r')")
}

// stateTr is the state after reading `tr`.
// [Min] 解析 true 时，判断 tr 后面紧跟的是不是 u
// [Min] 是就置 step 为 stateTru 继续后续解析，否就报错
func stateTr(s *scanner, c byte) int {
	if c == 'u' {
		s.step = stateTru
		return scanContinue
	}
	return s.error(c, "in literal true (expecting 'u')")
}

// stateTru is the state after reading `tru`.
// [Min] 解析 true 时，判断 tru 后面紧跟的是不是 e
// [Min] 是就成功解析出了 true，置 step 为 stateEndValue，来完成对该值的解析，否就报错
func stateTru(s *scanner, c byte) int {
	if c == 'e' {
		s.step = stateEndValue
		return scanContinue
	}
	return s.error(c, "in literal true (expecting 'e')")
}

// stateF is the state after reading `f`.
// [Min] 解析 false 时，判断 f 后面紧跟的是不是 a，
// [Min] 是就置 step 为 stateFa 继续后续解析，否就报错
func stateF(s *scanner, c byte) int {
	if c == 'a' {
		s.step = stateFa
		return scanContinue
	}
	return s.error(c, "in literal false (expecting 'a')")
}

// stateFa is the state after reading `fa`.
// [Min] 解析 false 时，判断 fa 后面紧跟的是不是 l，
// [Min] 是就置 step 为 stateFal 继续后续解析，否就报错
func stateFa(s *scanner, c byte) int {
	if c == 'l' {
		s.step = stateFal
		return scanContinue
	}
	return s.error(c, "in literal false (expecting 'l')")
}

// stateFal is the state after reading `fal`.
// [Min] 解析 false 时，判断 fal 后面紧跟的是不是 s，
// [Min] 是就置 step 为 stateFals 继续后续解析，否就报错
func stateFal(s *scanner, c byte) int {
	if c == 's' {
		s.step = stateFals
		return scanContinue
	}
	return s.error(c, "in literal false (expecting 's')")
}

// stateFals is the state after reading `fals`.
// [Min] 解析 false 时，判断 fals 后面紧跟的是不是 e，
// [Min] 是就成功解析出了 false ，置 step 为 stateEndValue，来完成对该值的解析，否就报错
func stateFals(s *scanner, c byte) int {
	if c == 'e' {
		s.step = stateEndValue
		return scanContinue
	}
	return s.error(c, "in literal false (expecting 'e')")
}

// stateN is the state after reading `n`.
// [Min] 解析 null 时，判断 n 后面紧跟的是不是 u，
// [Min] 是就置 step 为 stateNu 继续后续解析，否就报错
func stateN(s *scanner, c byte) int {
	if c == 'u' {
		s.step = stateNu
		return scanContinue
	}
	return s.error(c, "in literal null (expecting 'u')")
}

// stateNu is the state after reading `nu`.
// [Min] 解析 null 时，判断 nu 后面紧跟的是不是 l，
// [Min] 是就置 step 为 stateNul 继续后续解析，否就报错
func stateNu(s *scanner, c byte) int {
	if c == 'l' {
		s.step = stateNul
		return scanContinue
	}
	return s.error(c, "in literal null (expecting 'l')")
}

// stateNul is the state after reading `nul`.
// [Min] 解析 null 时，判断 nul 后面紧跟的是不是 l，
// [Min] 是就成功解析出了 null ，置 step 为 stateEndValue，来完成对该值的解析，否就报错
func stateNul(s *scanner, c byte) int {
	if c == 'l' {
		s.step = stateEndValue
		return scanContinue
	}
	return s.error(c, "in literal null (expecting 'l')")
}

// stateError is the state after reaching a syntax error,
// such as after reading `[1}` or `5.1.2`.
// [Min] 当遇到语法错误的时候，返回状态scanError
func stateError(s *scanner, c byte) int {
	return scanError
}

// error records an error and switches to the error state.
// [Min] 记录下解析出错的字符和上下文，置 step 为 stateError，返回scanError
func (s *scanner) error(c byte, context string) int {
	s.step = stateError
	s.err = &SyntaxError{"invalid character " + quoteChar(c) + " " + context, s.bytes}
	return scanError
}

// quoteChar formats c as a quoted character literal
// [Min] 返回单引号扩起来的字符串，其中单引号返回'\''，双引号返回'"'，无法打印显示的字符以'转义形式'返回
func quoteChar(c byte) string {
	// special cases - different from quoted strings
	if c == '\'' {
		return `'\''`
	}
	if c == '"' {
		return `'"'`
	}

	// use quoted string with different quotation marks
	s := strconv.Quote(string(c))
	return "'" + s[1:len(s)-1] + "'"
}

// undo causes the scanner to return scanCode from the next state transition.
// This gives callers a simple 1-byte undo mechanism.
// [Min] 强制下一次执行 step 的时候以给定的 scanCode 返回而不修改任何状态（相当于执行一个空函数，返回 scanCode）
// [Min] 之后的 step 又会恢复 undo 之间的值
// [Min] undo 之后必须至少执行一次 step之后才能再次 undo
func (s *scanner) undo(scanCode int) {
	if s.redo {
		panic("json: invalid use of scanner")
	}
	s.redoCode = scanCode
	s.redoState = s.step
	s.step = stateRedo
	s.redo = true
}

// stateRedo helps implement the scanner's 1-byte undo.
// [Min] 将 redo 置为 false，同时将之前暂存在 redoState 的 step 恢复， 同时返回在 undo 中按需设置的 scanCode
func stateRedo(s *scanner, c byte) int {
	s.redo = false
	s.step = s.redoState
	return s.redoCode
}
