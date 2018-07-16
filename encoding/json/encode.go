// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package json implements encoding and decoding of JSON as defined in
// RFC 7159. The mapping between JSON and Go values is described
// in the documentation for the Marshal and Unmarshal functions.
//
// See "JSON and Go" for an introduction to this package:
// https://golang.org/doc/articles/json_and_go.html
package json

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"
)

// Marshal returns the JSON encoding of v.
//
// Marshal traverses the value v recursively.
// If an encountered value implements the Marshaler interface
// and is not a nil pointer, Marshal calls its MarshalJSON method
// to produce JSON. If no MarshalJSON method is present but the
// value implements encoding.TextMarshaler instead, Marshal calls
// its MarshalText method and encodes the result as a JSON string.
// The nil pointer exception is not strictly necessary
// but mimics a similar, necessary exception in the behavior of
// UnmarshalJSON.
//
// Otherwise, Marshal uses the following type-dependent default encodings:
//
// Boolean values encode as JSON booleans.
//
// Floating point, integer, and Number values encode as JSON numbers.
//
// String values encode as JSON strings coerced to valid UTF-8,
// replacing invalid bytes with the Unicode replacement rune.
// The angle brackets "<" and ">" are escaped to "\u003c" and "\u003e"
// to keep some browsers from misinterpreting JSON output as HTML.
// Ampersand "&" is also escaped to "\u0026" for the same reason.
// This escaping can be disabled using an Encoder that had SetEscapeHTML(false)
// called on it.
//
// Array and slice values encode as JSON arrays, except that
// []byte encodes as a base64-encoded string, and a nil slice
// encodes as the null JSON value.
//
// Struct values encode as JSON objects.
// Each exported struct field becomes a member of the object, using the
// field name as the object key, unless the field is omitted for one of the
// reasons given below.
//
// The encoding of each struct field can be customized by the format string
// stored under the "json" key in the struct field's tag.
// The format string gives the name of the field, possibly followed by a
// comma-separated list of options. The name may be empty in order to
// specify options without overriding the default field name.
//
// The "omitempty" option specifies that the field should be omitted
// from the encoding if the field has an empty value, defined as
// false, 0, a nil pointer, a nil interface value, and any empty array,
// slice, map, or string.
//
// As a special case, if the field tag is "-", the field is always omitted.
// Note that a field with name "-" can still be generated using the tag "-,".
//
// Examples of struct field tags and their meanings:
//
//   // Field appears in JSON as key "myName".
//   Field int `json:"myName"`
//
//   // Field appears in JSON as key "myName" and
//   // the field is omitted from the object if its value is empty,
//   // as defined above.
//   Field int `json:"myName,omitempty"`
//
//   // Field appears in JSON as key "Field" (the default), but
//   // the field is skipped if empty.
//   // Note the leading comma.
//   Field int `json:",omitempty"`
//
//   // Field is ignored by this package.
//   Field int `json:"-"`
//
//   // Field appears in JSON as key "-".
//   Field int `json:"-,"`
//
// The "string" option signals that a field is stored as JSON inside a
// JSON-encoded string. It applies only to fields of string, floating point,
// integer, or boolean types. This extra level of encoding is sometimes used
// when communicating with JavaScript programs:
//
//    Int64String int64 `json:",string"`
//
// The key name will be used if it's a non-empty string consisting of
// only Unicode letters, digits, and ASCII punctuation except quotation
// marks, backslash, and comma.
//
// Anonymous struct fields are usually marshaled as if their inner exported fields
// were fields in the outer struct, subject to the usual Go visibility rules amended
// as described in the next paragraph.
// An anonymous struct field with a name given in its JSON tag is treated as
// having that name, rather than being anonymous.
// An anonymous struct field of interface type is treated the same as having
// that type as its name, rather than being anonymous.
//
// The Go visibility rules for struct fields are amended for JSON when
// deciding which field to marshal or unmarshal. If there are
// multiple fields at the same level, and that level is the least
// nested (and would therefore be the nesting level selected by the
// usual Go rules), the following extra rules apply:
//
// 1) Of those fields, if any are JSON-tagged, only tagged fields are considered,
// even if there are multiple untagged fields that would otherwise conflict.
//
// 2) If there is exactly one field (tagged or not according to the first rule), that is selected.
//
// 3) Otherwise there are multiple fields, and all are ignored; no error occurs.
//
// Handling of anonymous struct fields is new in Go 1.1.
// Prior to Go 1.1, anonymous struct fields were ignored. To force ignoring of
// an anonymous struct field in both current and earlier versions, give the field
// a JSON tag of "-".
//
// Map values encode as JSON objects. The map's key type must either be a
// string, an integer type, or implement encoding.TextMarshaler. The map keys
// are sorted and used as JSON object keys by applying the following rules,
// subject to the UTF-8 coercion described for string values above:
//   - string keys are used directly
//   - encoding.TextMarshalers are marshaled
//   - integer keys are converted to strings
//
// Pointer values encode as the value pointed to.
// A nil pointer encodes as the null JSON value.
//
// Interface values encode as the value contained in the interface.
// A nil interface value encodes as the null JSON value.
//
// Channel, complex, and function values cannot be encoded in JSON.
// Attempting to encode such a value causes Marshal to return
// an UnsupportedTypeError.
//
// JSON cannot represent cyclic data structures and Marshal does not
// handle them. Passing cyclic structures to Marshal will result in
// an infinite recursion.
//
// [Min] 将 Go 类型数据编码为 JSON 字符串
// [Min] JSON 对象的 key 只能为字符串，所以对于 Go map 类型的数据，键的类型必须是 string，整型，无符号整型，指针类型，实现了 TextMarshaler 接口的类型中的一种
// [Min] 不支持对 Channel, complex, function 类型进行编码
// [Min] 不支持循环类的数据结构
// [Min] 对于指针，会自动解引用，对指向的数据进行编码，如果是 nil，则编码为 null
// [Min] 只支持对可导出的字段的编码
func Marshal(v interface{}) ([]byte, error) {
	e := &encodeState{}
	err := e.marshal(v, encOpts{escapeHTML: true})
	if err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// MarshalIndent is like Marshal but applies Indent to format the output.
// Each JSON element in the output will begin on a new line beginning with prefix
// followed by one or more copies of indent according to the indentation nesting.
// [Min] 编码为按层级展开带缩进的 JSON 字符串
func MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	b, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = Indent(&buf, b, prefix, indent)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// HTMLEscape appends to dst the JSON-encoded src with <, >, &, U+2028 and U+2029
// characters inside string literals changed to \u003c, \u003e, \u0026, \u2028, \u2029
// so that the JSON will be safe to embed inside HTML <script> tags.
// For historical reasons, web browsers don't honor standard HTML
// escaping within <script> tags, so an alternative JSON encoding must
// be used.
// [Min] 对于 html <script> 标签包含的 JSON 字符串，需要对以下5个字符进行如下转义
// [Min] <, >, &, U+2028 and U+2029 => \u003c, \u003e, \u0026, \u2028, \u2029
// [Min] 详细分析参考 json.compact 函数
func HTMLEscape(dst *bytes.Buffer, src []byte) {
	// The characters can only appear in string literals,
	// so just scan the string one byte at a time.
	start := 0
	for i, c := range src {
		if c == '<' || c == '>' || c == '&' {
			if start < i {
				dst.Write(src[start:i])
			}
			dst.WriteString(`\u00`)
			dst.WriteByte(hex[c>>4])
			dst.WriteByte(hex[c&0xF])
			start = i + 1
		}
		// Convert U+2028 and U+2029 (E2 80 A8 and E2 80 A9).
		if c == 0xE2 && i+2 < len(src) && src[i+1] == 0x80 && src[i+2]&^1 == 0xA8 {
			if start < i {
				dst.Write(src[start:i])
			}
			dst.WriteString(`\u202`)
			dst.WriteByte(hex[src[i+2]&0xF])
			start = i + 3
		}
	}
	if start < len(src) {
		dst.Write(src[start:])
	}
}

// Marshaler is the interface implemented by types that
// can marshal themselves into valid JSON.
// [Min] Marshaler 接口
// [Min] 某一类型数据可以通过MarshalJSON方法编码为 JSON 字符串
type Marshaler interface {
	MarshalJSON() ([]byte, error)
}

// An UnsupportedTypeError is returned by Marshal when attempting
// to encode an unsupported value type.
type UnsupportedTypeError struct {
	Type reflect.Type
}

func (e *UnsupportedTypeError) Error() string {
	return "json: unsupported type: " + e.Type.String()
}

type UnsupportedValueError struct {
	Value reflect.Value
	Str   string
}

func (e *UnsupportedValueError) Error() string {
	return "json: unsupported value: " + e.Str
}

// Before Go 1.2, an InvalidUTF8Error was returned by Marshal when
// attempting to encode a string value with invalid UTF-8 sequences.
// As of Go 1.2, Marshal instead coerces the string to valid UTF-8 by
// replacing invalid bytes with the Unicode replacement rune U+FFFD.
//
// Deprecated: No longer used; kept for compatibility.
type InvalidUTF8Error struct {
	S string // the whole string value that caused the error
}

func (e *InvalidUTF8Error) Error() string {
	return "json: invalid UTF-8 in string: " + strconv.Quote(e.S)
}

type MarshalerError struct {
	Type reflect.Type
	Err  error
}

func (e *MarshalerError) Error() string {
	return "json: error calling MarshalJSON for type " + e.Type.String() + ": " + e.Err.Error()
}

var hex = "0123456789abcdef"

// An encodeState encodes JSON into a bytes.Buffer.
type encodeState struct {
	// [Min] 用来存 json 字符串的 buffer
	bytes.Buffer          // accumulated output
	scratch      [64]byte // [Min] 用于数字编码
}

var encodeStatePool sync.Pool

// [Min] 新建一个 encodeState
func newEncodeState() *encodeState {
	if v := encodeStatePool.Get(); v != nil {
		e := v.(*encodeState)
		e.Reset()
		return e
	}
	return new(encodeState)
}

// [Min] 根据 opts 将 v 编码为 json 字符串写入 e 中
func (e *encodeState) marshal(v interface{}, opts encOpts) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(runtime.Error); ok {
				panic(r)
			}
			if s, ok := r.(string); ok {
				panic(s)
			}
			err = r.(error)
		}
	}()
	// [Min] 调用reflectValue开始编码
	e.reflectValue(reflect.ValueOf(v), opts)
	return nil
}

func (e *encodeState) error(err error) {
	panic(err)
}

// [Min] 根据 v 的具体类型判断是否为空值，json 串 omitempty 的情况
func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		// [Min] 数组，map，切片，字符串，长度为0时表示空
		return v.Len() == 0
	case reflect.Bool:
		// [Min] 布尔类型，假为空
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// [Min] 符号整型，数值为0表示空
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		// [Min] 无符号整型，数值为0表示空
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		// [Min] 浮点型，数值为0表示空
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		// [Min] 接口，指针类型，nil 表示空
		return v.IsNil()
	}
	return false
}

// [Min] 根据 value 获得对应类型的 encoderFunc 并执行
func (e *encodeState) reflectValue(v reflect.Value, opts encOpts) {
	valueEncoder(v)(e, v, opts)
}

type encOpts struct {
	// quoted causes primitive fields to be encoded inside JSON strings.
	quoted bool
	// escapeHTML causes '<', '>', and '&' to be escaped in JSON strings.
	escapeHTML bool
}

type encoderFunc func(e *encodeState, v reflect.Value, opts encOpts)

var encoderCache sync.Map // map[reflect.Type]encoderFunc

// [Min] 根据 value 的类型返回 encoderFunc
func valueEncoder(v reflect.Value) encoderFunc {
	if !v.IsValid() {
		return invalidValueEncoder
	}
	return typeEncoder(v.Type())
}

// [Min] 获取相应 type 的 encoderFunc
func typeEncoder(t reflect.Type) encoderFunc {
	// [Min] 先尝试从 encoderCache 中加载，成功了，直接返回
	if fi, ok := encoderCache.Load(t); ok {
		return fi.(encoderFunc)
	}

	// To deal with recursive types, populate the map with an
	// indirect func before we build it. This type waits on the
	// real func (f) to be ready and then calls it. This indirect
	// func is only used for recursive types.
	var (
		wg sync.WaitGroup
		f  encoderFunc
	)
	wg.Add(1)
	// [Min] 如果 t 在 encoderCache 中，loaded 返回为真，fi 即为 encoderFunc
	// [Min] 如果 t 不在 encoderCache 中，loaded 返回为假，将以下闭包函数注册为类型 t 的 encoderFunc，存入 encoderCache 中
	// func(e *encodeState, v reflect.Value, opts encOpts) {
	// 	wg.Wait()
	// 	f(e, v, opts)
	// }
	// [Min] 注意，此时的 f 还只是一个零值 nil，但由于整个 encoderFunc 是闭包，所以当该函数实际执行前 f 的值仍然可变
	// [Min] 后续注册完后，会设置该 f 的值，从而在其调用的时候能够获得正确的取值
	fi, loaded := encoderCache.LoadOrStore(t, encoderFunc(func(e *encodeState, v reflect.Value, opts encOpts) {
		wg.Wait()
		f(e, v, opts)
	}))
	if loaded {
		return fi.(encoderFunc)
	}

	// Compute the real encoder and replace the indirect func with it.
	// [Min] 将修改闭包中的 f 为真正的该类型的 encoderFunc
	f = newTypeEncoder(t, true)
	// [Min] 修改完 f 后再放开 wg，从而使得 f 一定是在修正后才执行的
	wg.Done()
	// [Min] 将 f 存入 encoderCache 中
	encoderCache.Store(t, f)
	return f
}

var (
	marshalerType     = reflect.TypeOf(new(Marshaler)).Elem()
	textMarshalerType = reflect.TypeOf(new(encoding.TextMarshaler)).Elem()
)

// newTypeEncoder constructs an encoderFunc for a type.
// The returned encoder only checks CanAddr when allowAddr is true.
func newTypeEncoder(t reflect.Type, allowAddr bool) encoderFunc {
	// [Min] 类型 t 是否实现了 marshaler interface，是，直接返回 marshalerEncoder
	if t.Implements(marshalerType) {
		return marshalerEncoder
	}
	// [Min] t.Kind()会获取 t 的底层类型，如 type A string 之类的会返回 string
	// [Min] 如果 t 本身不是指针，并且允许自动解引用地址
	// [Min] 尝试看指向 t 类型的指针是否实现了 marshaler interface
	// [Min] 如果是，返回可寻址优先的条件 encoder，优先addrMarshalerEncoder，其次构造一个不可寻址的 encoderFunc
	if t.Kind() != reflect.Ptr && allowAddr {
		if reflect.PtrTo(t).Implements(marshalerType) {
			return newCondAddrEncoder(addrMarshalerEncoder, newTypeEncoder(t, false))
		}
	}

	// [Min] 如果 t 实现了 TextMarshaler 接口，返回 textMarshalerEncoder
	if t.Implements(textMarshalerType) {
		return textMarshalerEncoder
	}
	// [Min] 如果 t 本身不是指针，并且允许自动解引用地址
	// [Min] 尝试看指向 t 类型的指针是否实现了 TextMarshaler interface
	// [Min] 如果是，返回可寻址优先的条件 encoder，优先addrTextMarshalerEncoder，其次构造一个不可寻址的 encoderFunc
	if t.Kind() != reflect.Ptr && allowAddr {
		if reflect.PtrTo(t).Implements(textMarshalerType) {
			return newCondAddrEncoder(addrTextMarshalerEncoder, newTypeEncoder(t, false))
		}
	}

	// [Min] 既没有实现 Marshaler 又没有实现 TextMarshaler 的类型
	switch t.Kind() {
	case reflect.Bool:
		// [Min] 布尔型数据编码函数boolEncoder
		return boolEncoder
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// [Min] 整型数据编码函数intEncoder
		return intEncoder
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		// [Min] 无符号整型数据编码函数uintEncoder
		return uintEncoder
	case reflect.Float32:
		// [Min] 32位浮点型数据编码函数float32Encoder
		return float32Encoder
	case reflect.Float64:
		// [Min] 64位浮点型数据编码函数float64Encoder
		return float64Encoder
	case reflect.String:
		// [Min] 字符串型数据编码函数stringEncoder
		return stringEncoder
	case reflect.Interface:
		// [Min] 接口类型数据编码函数interfaceEncoder
		return interfaceEncoder
	case reflect.Struct:
		// [Min] 结构体类型数据编码函数newStructEncoder(t)
		return newStructEncoder(t)
	case reflect.Map:
		return newMapEncoder(t)
	case reflect.Slice:
		return newSliceEncoder(t)
	case reflect.Array:
		return newArrayEncoder(t)
	case reflect.Ptr:
		return newPtrEncoder(t)
	default:
		return unsupportedTypeEncoder
	}
}

func invalidValueEncoder(e *encodeState, v reflect.Value, _ encOpts) {
	e.WriteString("null")
}

// [Min] t 实现了 marshaler，调用MarshalJSON编码
func marshalerEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	// [Min] 如果 v 的类型是指针，且是 nil，则写入 null
	if v.Kind() == reflect.Ptr && v.IsNil() {
		e.WriteString("null")
		return
	}
	// [Min] 类型断言Marshaler
	m, ok := v.Interface().(Marshaler)
	if !ok {
		e.WriteString("null") // [Min] ？？？why null ？
		return
	}
	b, err := m.MarshalJSON()
	if err == nil {
		// copy JSON into buffer, checking validity.
		// [Min] 将 json 串压缩写入 e 中
		err = compact(&e.Buffer, b, opts.escapeHTML)
	}
	if err != nil {
		e.error(&MarshalerError{v.Type(), err})
	}
}

// [Min] 可寻址的 t 且实现了 marshaler interface，调用 MarshalJSON 方法编码
// [Min] 注意，忽略了encOpts
func addrMarshalerEncoder(e *encodeState, v reflect.Value, _ encOpts) {
	// [Min] 先获取指向该 value 的地址（相当于 v 存储的实际的值）
	va := v.Addr()
	// [Min] 如果是 nil，对应的在 json 中写入 null
	if va.IsNil() {
		e.WriteString("null")
		return
	}
	// [Min] va.Interface() <=> var i interface{} = va
	// [Min] 此处就是类型断言，从而 m 可以调用方法MarshalJSON
	m := va.Interface().(Marshaler)
	b, err := m.MarshalJSON()
	if err == nil {
		// copy JSON into buffer, checking validity.
		// [Min] 将 json 串压缩写入 e 中
		err = compact(&e.Buffer, b, true)
	}
	if err != nil {
		e.error(&MarshalerError{v.Type(), err})
	}
}

// [Min] t 实现了 TextMarshaler 接口，调用 MarshalText
func textMarshalerEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	// [Min] 如果 v 的类型是指针，且是 nil，直接写入 null
	if v.Kind() == reflect.Ptr && v.IsNil() {
		e.WriteString("null")
		return
	}
	// [Min] 类型断言，调用MarshalText
	m := v.Interface().(encoding.TextMarshaler)
	b, err := m.MarshalText()
	if err != nil {
		e.error(&MarshalerError{v.Type(), err})
	}
	// [Min] 调用 stringBytes 对 json 串进行必要的转义再写入 b
	e.stringBytes(b, opts.escapeHTML)
}

// [Min] 可寻址的 t 且实现了 TextMarshaler interface，调用 MarshalJSON 方法编码
// [Min] 和 textMarshalerEncoder 类似，多了一步寻址的调用
func addrTextMarshalerEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	va := v.Addr()
	if va.IsNil() {
		e.WriteString("null")
		return
	}
	m := va.Interface().(encoding.TextMarshaler)
	b, err := m.MarshalText()
	if err != nil {
		e.error(&MarshalerError{v.Type(), err})
	}
	e.stringBytes(b, opts.escapeHTML)
}

// [Min] 布尔类型数据编码
func boolEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	// [Min] 是否需要写入引号
	if opts.quoted {
		e.WriteByte('"')
	}
	// [Min] 根据真假写入 true，false
	if v.Bool() {
		e.WriteString("true")
	} else {
		e.WriteString("false")
	}
	if opts.quoted {
		e.WriteByte('"')
	}
}

// [Min] int类型数据编码
func intEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	// [Min] 将 v 的十进制数值对应的字符串写入 scratch 中，并返回
	b := strconv.AppendInt(e.scratch[:0], v.Int(), 10)
	// [Min] 按需写入引号
	if opts.quoted {
		e.WriteByte('"')
	}
	// [Min] 将数值字符串写入 e
	e.Write(b)
	if opts.quoted {
		e.WriteByte('"')
	}
}

// [Min] uint 类型数据编码，和intEncoder类似
func uintEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	b := strconv.AppendUint(e.scratch[:0], v.Uint(), 10)
	if opts.quoted {
		e.WriteByte('"')
	}
	e.Write(b)
	if opts.quoted {
		e.WriteByte('"')
	}
}

type floatEncoder int // number of bits

// [Min] 浮点型数据编码
func (bits floatEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	f := v.Float()
	if math.IsInf(f, 0) || math.IsNaN(f) {
		e.error(&UnsupportedValueError{v, strconv.FormatFloat(f, 'g', -1, int(bits))})
	}

	// Convert as if by ES6 number to string conversion.
	// This matches most other JSON generators.
	// See golang.org/issue/6384 and golang.org/issue/14135.
	// Like fmt %g, but the exponent cutoffs are different
	// and exponents themselves are not padded to two digits.
	b := e.scratch[:0]
	abs := math.Abs(f)
	fmt := byte('f')
	// Note: Must use float32 comparisons for underlying float32 value to get precise cutoffs right.
	if abs != 0 {
		if bits == 64 && (abs < 1e-6 || abs >= 1e21) || bits == 32 && (float32(abs) < 1e-6 || float32(abs) >= 1e21) {
			fmt = 'e'
		}
	}
	b = strconv.AppendFloat(b, f, fmt, -1, int(bits))
	if fmt == 'e' {
		// clean up e-09 to e-9
		n := len(b)
		if n >= 4 && b[n-4] == 'e' && b[n-3] == '-' && b[n-2] == '0' {
			b[n-2] = b[n-1]
			b = b[:n-1]
		}
	}

	if opts.quoted {
		e.WriteByte('"')
	}
	e.Write(b)
	if opts.quoted {
		e.WriteByte('"')
	}
}

var (
	float32Encoder = (floatEncoder(32)).encode
	float64Encoder = (floatEncoder(64)).encode
)

// [Min] 字符串型数据编码
func stringEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	// [Min] 如果是代表数值的字符串（v 的类型为 Number）
	// 	// A Number represents a JSON number literal.
	// type Number string
	if v.Type() == numberType {
		numStr := v.String()
		// In Go1.5 the empty string encodes to "0", while this is not a valid number literal
		// we keep compatibility so check validity after this.
		if numStr == "" {
			numStr = "0" // Number's zero-val
		}
		// [Min] 判断是否为有效数值字符串
		if !isValidNumber(numStr) {
			e.error(fmt.Errorf("json: invalid number literal %q", numStr))
		}
		e.WriteString(numStr)
		return
	}
	if opts.quoted {
		// [Min] ???
		sb, err := Marshal(v.String())
		if err != nil {
			e.error(err)
		}
		e.string(string(sb), opts.escapeHTML)
	} else {
		e.string(v.String(), opts.escapeHTML)
	}
}

// [Min] 接口类型数据编码
func interfaceEncoder(e *encodeState, v reflect.Value, opts encOpts) {
	// [Min] 如果是 nil，直接写入 null，
	// [Min] 否则继续对该接口包含的 value 进行编码
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	e.reflectValue(v.Elem(), opts)
}

func unsupportedTypeEncoder(e *encodeState, v reflect.Value, _ encOpts) {
	e.error(&UnsupportedTypeError{v.Type()})
}

// [Min] 结构体字段encoder
type structEncoder struct {
	// [Min] 该结构体中所有需要编码的字段信息（已扩展获取了所有匿名字段中的有效字段）
	fields []field
	// [Min] fields 中每一字段对应的 encoderFunc
	fieldEncs []encoderFunc
}

// [Min] 结构体类型字段编码
func (se *structEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	e.WriteByte('{')
	first := true
	for i, f := range se.fields {
		// [Min] 根据字段索引结构，调用fieldByIndex获取字段值，同时会检查值是否有效
		fv := fieldByIndex(v, f.index)
		// [Min] 忽略无效值和omitEmpty的情况
		if !fv.IsValid() || f.omitEmpty && isEmptyValue(fv) {
			continue
		}
		// [Min] 字段与字段之间用','分隔
		if first {
			first = false
		} else {
			e.WriteByte(',')
		}
		// [Min] 按字段的 quoted 属性，写入字段名:字段值
		e.string(f.name, opts.escapeHTML)
		e.WriteByte(':')
		opts.quoted = f.quoted
		// [Min] 调用字段对应的 encoderFunc
		se.fieldEncs[i](e, fv, opts)
	}
	e.WriteByte('}')
}

// [Min] t 为结构体类型，返回该特定类型的 encoderFunc
func newStructEncoder(t reflect.Type) encoderFunc {
	// [Min] 获取该类型 t 下所有需要编码的字段信息
	fields := cachedTypeFields(t)
	se := &structEncoder{
		fields:    fields,
		fieldEncs: make([]encoderFunc, len(fields)),
	}
	// [Min] 调用typeByIndex获取每一个待编码字段的类型，
	// [Min] 再根据该类型调用typeEncoder获取对应的 encoderFunc
	// [Min] 存入structEncoder
	for i, f := range fields {
		se.fieldEncs[i] = typeEncoder(typeByIndex(t, f.index))
	}
	return se.encode
}

// [Min] map类型 encoder
type mapEncoder struct {
	elemEnc encoderFunc
}

// [Min] map类型字段编码
func (me *mapEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	e.WriteByte('{')

	// Extract and sort the keys.
	// [Min] 获取 map 中的 key，并 key 必须是 string，整型，无符号整型，指针类型，实现了 TextMarshaler 接口的类型中的一种
	keys := v.MapKeys()
	sv := make([]reflectWithString, len(keys))
	for i, v := range keys {
		sv[i].v = v
		// [Min] 获得 key 对应的字符串，用作 json 字段名
		if err := sv[i].resolve(); err != nil {
			e.error(&MarshalerError{v.Type(), err})
		}
	}
	// [Min] 按 key 对应的字符串排序
	sort.Slice(sv, func(i, j int) bool { return sv[i].s < sv[j].s })

	// [Min] 写入键值对，以','分隔
	for i, kv := range sv {
		if i > 0 {
			e.WriteByte(',')
		}
		e.string(kv.s, opts.escapeHTML)
		e.WriteByte(':')
		me.elemEnc(e, v.MapIndex(kv.v), opts)
	}
	e.WriteByte('}')
}

// [Min] t 为 map 类型，返回该 map 类型的 encoderFunc
func newMapEncoder(t reflect.Type) encoderFunc {
	// [Min] map key 的类型必须为以下列出的类型或者实现了TextMarshaler接口的类型
	switch t.Key().Kind() {
	case reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
	default:
		if !t.Key().Implements(textMarshalerType) {
			return unsupportedTypeEncoder
		}
	}
	// [Min] t.Elem()获取 map 元素的类型，再调用 typeEncoder，获得该具体类型的 encoderFunc
	me := &mapEncoder{typeEncoder(t.Elem())}
	return me.encode
}

// [Min] byte slice 类型数据编码
func encodeByteSlice(e *encodeState, v reflect.Value, _ encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	// [Min] 获得字节流，以 base64编码写入
	s := v.Bytes()
	e.WriteByte('"')
	if len(s) < 1024 {
		// for small buffers, using Encode directly is much faster.
		dst := make([]byte, base64.StdEncoding.EncodedLen(len(s)))
		base64.StdEncoding.Encode(dst, s)
		e.Write(dst)
	} else {
		// for large buffers, avoid unnecessary extra temporary
		// buffer space.
		enc := base64.NewEncoder(base64.StdEncoding, e)
		enc.Write(s)
		enc.Close()
	}
	e.WriteByte('"')
}

// sliceEncoder just wraps an arrayEncoder, checking to make sure the value isn't nil.
// [Min] slice encoder
type sliceEncoder struct {
	arrayEnc encoderFunc
}

// [Min] slice 类型数据编码
func (se *sliceEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	se.arrayEnc(e, v, opts)
}

// [Min] t 为 slice 类型，返回该类型对应的 encoderFunc
func newSliceEncoder(t reflect.Type) encoderFunc {
	// Byte slices get special treatment; arrays don't.
	// [Min] 如果是 byte slice，且没有实现 Marshaler，TextMarshaler 接口，则返回encodeByteSlice
	// [Min] 其余的按 json 数组编码处理
	if t.Elem().Kind() == reflect.Uint8 {
		p := reflect.PtrTo(t.Elem())
		if !p.Implements(marshalerType) && !p.Implements(textMarshalerType) {
			return encodeByteSlice
		}
	}
	enc := &sliceEncoder{newArrayEncoder(t)}
	return enc.encode
}

// [Min] json 数组 encoder
type arrayEncoder struct {
	elemEnc encoderFunc
}

// [Min] 对每一个元素进行编码，以','分隔，外套[]
func (ae *arrayEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	e.WriteByte('[')
	n := v.Len()
	for i := 0; i < n; i++ {
		if i > 0 {
			e.WriteByte(',')
		}
		ae.elemEnc(e, v.Index(i), opts)
	}
	e.WriteByte(']')
}

// [Min] t 为非字节 slice，返回该类型的 encoderFunc
func newArrayEncoder(t reflect.Type) encoderFunc {
	// [Min] 通过typeEncoder返回元素对应的 encoderFunc
	enc := &arrayEncoder{typeEncoder(t.Elem())}
	return enc.encode
}

// [Min] 指针 encoder
type ptrEncoder struct {
	elemEnc encoderFunc
}

// [Min] 对指针指向的数据编码
func (pe *ptrEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.IsNil() {
		e.WriteString("null")
		return
	}
	pe.elemEnc(e, v.Elem(), opts)
}

// [Min] t 为指针，t.Elem()获得指向的类型，调用typeEncoder构造该类型对应的 encoderFunc
func newPtrEncoder(t reflect.Type) encoderFunc {
	enc := &ptrEncoder{typeEncoder(t.Elem())}
	return enc.encode
}

// [Min] 可寻址优先的条件 encoder
type condAddrEncoder struct {
	canAddrEnc, elseEnc encoderFunc
}

// [Min] 如果 v 可寻址，则调用 ce 中的 canAddrEnc ，否则调用 elseEnc
func (ce *condAddrEncoder) encode(e *encodeState, v reflect.Value, opts encOpts) {
	if v.CanAddr() {
		ce.canAddrEnc(e, v, opts)
	} else {
		ce.elseEnc(e, v, opts)
	}
}

// newCondAddrEncoder returns an encoder that checks whether its value
// CanAddr and delegates to canAddrEnc if so, else to elseEnc.
// [Min] 生成一个可寻址优先的条件 encoder
// [Min] 结构中存了两个 encoderFunc，canAddrEnc 和 elseEnc
// [Min] 当编码对象 v 可寻址时，调用前者进行编码，否则调用后者
func newCondAddrEncoder(canAddrEnc, elseEnc encoderFunc) encoderFunc {
	enc := &condAddrEncoder{canAddrEnc: canAddrEnc, elseEnc: elseEnc}
	return enc.encode
}

// [Min] 判断 json tag name 是否有效
func isValidTag(s string) bool {
	// [Min] 空无效
	if s == "" {
		return false
	}
	for _, c := range s {
		switch {
		// [Min] 有效的特殊字符
		case strings.ContainsRune("!#$%&()*+-./:<=>?@[]^_{|}~ ", c):
			// Backslash and quote chars are reserved, but
			// otherwise any punctuation chars are allowed
			// in a tag name.
		// [Min] 除去上述有效特殊字符，其他任何非字母，非数字都是无效的
		default:
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) {
				return false
			}
		}
	}
	return true
}

// [Min] 根据字段索引结构，获取该字段值
func fieldByIndex(v reflect.Value, index []int) reflect.Value {
	for _, i := range index {
		if v.Kind() == reflect.Ptr {
			if v.IsNil() {
				return reflect.Value{}
			}
			v = v.Elem()
		}
		v = v.Field(i)
	}
	return v
}

// [Min] 根据字段索引结构，获取该字段的类型
func typeByIndex(t reflect.Type, index []int) reflect.Type {
	for _, i := range index {
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		t = t.Field(i).Type
	}
	return t
}

type reflectWithString struct {
	v reflect.Value
	s string
}

// [Min] 用于将 map 的 key 转为 string 型数据
func (w *reflectWithString) resolve() error {
	// [Min] 如果本身就是 string，直接调用 String() 即可获得真正的字符串值
	if w.v.Kind() == reflect.String {
		w.s = w.v.String()
		return nil
	}
	// [Min] 如果v 实现了TextMarshaler接口，调用MarshalText即可
	if tm, ok := w.v.Interface().(encoding.TextMarshaler); ok {
		buf, err := tm.MarshalText()
		w.s = string(buf)
		return err
	}
	switch w.v.Kind() {
	// [Min] 如果是整型数据，则转为对应的十进制数值字符串
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		w.s = strconv.FormatInt(w.v.Int(), 10)
		return nil
	// [Min] 如果是无符号整型数据或指针，则转为对应的十进制数值字符串
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		w.s = strconv.FormatUint(w.v.Uint(), 10)
		return nil
	}
	panic("unexpected map key type")
}

// NOTE: keep in sync with stringBytes below.
// [Min] 和stringBytes类似，用于写入 string
func (e *encodeState) string(s string, escapeHTML bool) {
	e.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		if b := s[i]; b < utf8.RuneSelf {
			if htmlSafeSet[b] || (!escapeHTML && safeSet[b]) {
				i++
				continue
			}
			if start < i {
				e.WriteString(s[start:i])
			}
			switch b {
			case '\\', '"':
				e.WriteByte('\\')
				e.WriteByte(b)
			case '\n':
				e.WriteByte('\\')
				e.WriteByte('n')
			case '\r':
				e.WriteByte('\\')
				e.WriteByte('r')
			case '\t':
				e.WriteByte('\\')
				e.WriteByte('t')
			default:
				// This encodes bytes < 0x20 except for \t, \n and \r.
				// If escapeHTML is set, it also escapes <, >, and &
				// because they can lead to security holes when
				// user-controlled strings are rendered into JSON
				// and served to some browsers.
				e.WriteString(`\u00`)
				e.WriteByte(hex[b>>4])
				e.WriteByte(hex[b&0xF])
			}
			i++
			start = i
			continue
		}
		c, size := utf8.DecodeRuneInString(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteString(`\ufffd`)
			i += size
			start = i
			continue
		}
		// U+2028 is LINE SEPARATOR.
		// U+2029 is PARAGRAPH SEPARATOR.
		// They are both technically valid characters in JSON strings,
		// but don't work in JSONP, which has to be evaluated as JavaScript,
		// and can lead to security holes there. It is valid JSON to
		// escape them, so we do so unconditionally.
		// See http://timelessrepo.com/json-isnt-a-javascript-subset for discussion.
		if c == '\u2028' || c == '\u2029' {
			if start < i {
				e.WriteString(s[start:i])
			}
			e.WriteString(`\u202`)
			e.WriteByte(hex[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		e.WriteString(s[start:])
	}
	e.WriteByte('"')
}

// NOTE: keep in sync with string above.
// [Min] 写入字符串并以双引号括起来
func (e *encodeState) stringBytes(s []byte, escapeHTML bool) {
	e.WriteByte('"')
	// [Min] start 为下一次写入的数据在 s 中的开始位置
	// [Min] 当当前第 i 个字符不能直接写入时，此时会一次性将之前积累的数据[start,i)写入
	start := 0
	for i := 0; i < len(s); {
		// [Min] 当前字符为utf8单字节，
		if b := s[i]; b < utf8.RuneSelf {
			// [Min] 如果该字符属于 html 安全字符集，或者是非 html 模式的安全字符集
			// [Min] 说明该字符可以直接写入，继续找不能直接写入的字符
			if htmlSafeSet[b] || (!escapeHTML && safeSet[b]) {
				i++
				continue
			}
			// [Min] 逻辑执行到这里，说明对于该 utf8 单字节字符来说，需要转义不能直接写入
			// [Min] 先将之前累积的可以直接写入的写入 e
			if start < i {
				e.Write(s[start:i])
			}
			// [Min] 根据不同的字符写入对应的转义字符
			switch b {
			case '\\', '"':
				e.WriteByte('\\')
				e.WriteByte(b)
			case '\n':
				e.WriteByte('\\')
				e.WriteByte('n')
			case '\r':
				e.WriteByte('\\')
				e.WriteByte('r')
			case '\t':
				e.WriteByte('\\')
				e.WriteByte('t')
			default:
				// This encodes bytes < 0x20 except for \t, \n and \r.
				// If escapeHTML is set, it also escapes <, >, and &
				// because they can lead to security holes when
				// user-controlled strings are rendered into JSON
				// and served to some browsers.
				e.WriteString(`\u00`)
				e.WriteByte(hex[b>>4])
				e.WriteByte(hex[b&0xF])
			}
			i++
			// [Min] 该转义字符的下一个字符为下一组写入数据的 start 字符
			start = i
			continue
		}
		// [Min] 非 utf8 单字节情况，先解析出该 unicode
		// [Min] 如果无法解析出有效的 unicode 字符，会返回RuneError且 size 为1，
		// [Min] 则将该字符在 json 串中以 \ufffd 替代
		c, size := utf8.DecodeRune(s[i:])
		if c == utf8.RuneError && size == 1 {
			if start < i {
				e.Write(s[start:i])
			}
			e.WriteString(`\ufffd`)
			i += size
			start = i
			continue
		}
		// U+2028 is LINE SEPARATOR.
		// U+2029 is PARAGRAPH SEPARATOR.
		// They are both technically valid characters in JSON strings,
		// but don't work in JSONP, which has to be evaluated as JavaScript,
		// and can lead to security holes there. It is valid JSON to
		// escape them, so we do so unconditionally.
		// See http://timelessrepo.com/json-isnt-a-javascript-subset for discussion.
		// [Min] 解析出来了，且对应的 unicode 字符是\u2028或\u2029，
		// [Min] 则先将累积的写入，再写入\u2028或\u2029
		// [Min] 其他多字节 utf8 字符可以直接写，继续循环找下一个不能直接写的字符
		if c == '\u2028' || c == '\u2029' {
			if start < i {
				e.Write(s[start:i])
			}
			e.WriteString(`\u202`)
			e.WriteByte(hex[c&0xF])
			i += size
			start = i
			continue
		}
		i += size
	}
	// [Min] 写入最后一部分
	if start < len(s) {
		e.Write(s[start:])
	}
	e.WriteByte('"')
}

// A field represents a single field found in a struct.
// [Min] 记录结构体中的一个字段的信息
type field struct {
	// [Min] 字段名字符串
	name string
	// [Min] 字段名字节流
	nameBytes []byte // []byte(name)
	// [Min] 用来比较其他字段名是否和该字段名一致的函数
	equalFold func(s, t []byte) bool // bytes.EqualFold or equivalent

	// [Min] 是否有 tag
	tag bool
	// [Min] 该字段所处的索引结构，index 的长度代表该字段的内嵌层次
	// [Min] 如果该字段位于顶层结构中，则 index 为长度为1的切片，index[0] 为该字段在该结构中的索引
	// [Min] 如果该字段属于一个内嵌的匿名字段，则 index 包含了该内嵌字段的索引结构 + 该字段在该内嵌结构中的索引，依次向上递推，直到顶层
	index []int
	// [Min] 该字段的类型
	typ reflect.Type
	// [Min] tag 中是否含有 omitempty
	omitEmpty bool
	// [Min] 该字段的值是否可以在 json 串中用引号括起来
	quoted bool
}

// [Min] 按 name 更新 nameBytes，并获取用于与该字段比较字段名的比较函数
func fillField(f field) field {
	f.nameBytes = []byte(f.name)
	f.equalFold = foldFunc(f.nameBytes)
	return f
}

// byIndex sorts field by index sequence.
// [Min] 按字段的索引结构排序
// [Min] 层次深的在后，同层的按字段索引升序排序
type byIndex []field

func (x byIndex) Len() int { return len(x) }

func (x byIndex) Swap(i, j int) { x[i], x[j] = x[j], x[i] }

func (x byIndex) Less(i, j int) bool {
	for k, xik := range x[i].index {
		// [Min] 如果 k 大于等于 j 字段的层次，（理应不在这里出现）
		// [Min] 说明 i 字段的层次大于 j 字段，i 需在 j 后面，返回 false
		if k >= len(x[j].index) {
			return false
		}
		// [Min] 如果索引结构中有一个索引不同，说明这两个字段分属两个分支，
		// [Min] 按分支先后排序
		if xik != x[j].index[k] {
			return xik < x[j].index[k]
		}
	}
	// [Min] 如果 i 的索引结构为 j 的索引结构的"prefix"，说明 j 的层次至少和 i 相同，可能更深
	return len(x[i].index) < len(x[j].index)
}

// typeFields returns a list of fields that JSON should recognize for the given type.
// The algorithm is breadth-first search over the set of structs to include - the top struct
// and then any reachable anonymous structs.
// [Min] 返回类型 t 中需要编码为 JSON 串的字段，搜索以广度优先，返回结构按字段索引结构排序
func typeFields(t reflect.Type) []field {
	// Anonymous fields to explore at the current level and the next.
	// [Min] 用来记录匿名字段，current 表示当前层次包含的匿名字段，next 表示下一层包含的匿名字段
	// [Min] 起始 next 为最外层类型，也当成一个匿名字段来开启层次扫描
	current := []field{}
	next := []field{{typ: t}}

	// Count of queued names for current level and the next.
	// [Min] count 用来记录当前层中需要编码的某一类型字段的数量
	// [Min] nextCount 用来记录下一层中需要编码的某一类型字段的数量
	count := map[reflect.Type]int{}
	nextCount := map[reflect.Type]int{}

	// Types already visited at an earlier level.
	// [Min] visited 用来记录该类型的字段是否已经在之前层次中遇到过
	visited := map[reflect.Type]bool{}

	// Fields found.
	var fields []field

	// [Min] 只要还有下一层匿名字段，且符合编码条件，继续循环
	// [Min] next 会在当前层处理完后进行赋值
	for len(next) > 0 {
		current, next = next, current[:0]
		count, nextCount = nextCount, map[reflect.Type]int{}

		// [Min] 对当前层每一个匿名类型进行处理，f 为某一类型的匿名字段
		for _, f := range current {
			// [Min] 如果该类型已经在之前的层次中出现过，则跳过此类型
			if visited[f.typ] {
				continue
			}
			// [Min] 标记该类型为 visited
			visited[f.typ] = true

			// Scan f.typ for fields to include.
			// [Min] 对该类型中的每一个字段进行处理
			for i := 0; i < f.typ.NumField(); i++ {
				sf := f.typ.Field(i)
				// [Min] 首先根据导出规则，检查该字段是否需要忽略：
				// [Min] 匿名的字段，直接忽略不可导出的非结构体类型字段，如匿名的 string，int 等
				// [Min] 非匿名字段，直接忽略不可导出的字段

				// [Min] PkgPath 用来记录不可导出的字段的对应的 package 路径
				// [Min] 为空，说明可导出
				isUnexported := sf.PkgPath != ""
				if sf.Anonymous {
					// [Min] 如果是一个匿名字段，获取他对应的类型
					t := sf.Type
					// [Min] 如果他是一个指针，获取他指向的那个类型
					if t.Kind() == reflect.Ptr {
						t = t.Elem()
					}
					// [Min] 如果该字段不可导出，且不是结构体类型，忽略，继续下一个字段的处理
					if isUnexported && t.Kind() != reflect.Struct {
						// Ignore embedded fields of unexported non-struct types.
						continue
					}
					// [Min] 注意此处不能忽略不可导出的结构体类型，因为字段可能是可导出的
					// [Min] 而又因为该不可导出的结构体类型是匿名的，导致它们包含的可导出的字段是可导出的
					// Do not ignore embedded fields of unexported struct types
					// since they may have exported fields.
				} else if isUnexported {
					// [Min] 非匿名的不可导出字段，直接忽略
					// Ignore unexported non-embedded fields.
					continue
				}
				// [Min] 获取该字段对应的 json tag，如果是'-'，忽略该字段
				tag := sf.Tag.Get("json")
				if tag == "-" {
					continue
				}
				// [Min] 解析 tag，获得 json 编码字段名和选项
				name, opts := parseTag(tag)
				// [Min] 如果 name 无效，置空
				if !isValidTag(name) {
					name = ""
				}
				// [Min] 记录下该字段的索引
				index := make([]int, len(f.index)+1)
				copy(index, f.index)
				index[len(f.index)] = i

				ft := sf.Type
				// [Min] 对指针字段解引用
				if ft.Name() == "" && ft.Kind() == reflect.Ptr {
					// Follow pointer.
					ft = ft.Elem()
				}

				// Only strings, floats, integers, and booleans can be quoted.
				quoted := false
				// [Min] 如果 tag 含有 string 选项，且该字段类型为strings, floats, integers, booleans中一种，
				// [Min] 编码时会加引号
				if opts.Contains("string") {
					switch ft.Kind() {
					case reflect.Bool,
						reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
						reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
						reflect.Float32, reflect.Float64,
						reflect.String:
						quoted = true
					}
				}

				// Record found field and index sequence.
				// [Min] 当 tag name 有效，
				// [Min] 或者该子字段不是匿名字段（此时已经排除了非匿名的不可导字段）
				// [Min] 或者该子字段不是结构体类型
				// [Min] 该字段需要在 json 串中编码（可能为一个结构体，需要在 json 串中显示的对其 key 进行编码显示）
				if name != "" || !sf.Anonymous || ft.Kind() != reflect.Struct {
					tagged := name != ""
					// [Min] 如果没有有效的 tag name，使用结构体中的字段名作为 json 字段名
					if name == "" {
						name = sf.Name
					}
					// [Min] 构造 filed，添加到返回的 fileds 中
					fields = append(fields, fillField(field{
						name:      name,
						tag:       tagged,
						index:     index,
						typ:       ft,
						omitEmpty: opts.Contains("omitempty"),
						quoted:    quoted,
					}))
					if count[f.typ] > 1 {
						// If there were multiple instances, add a second,
						// so that the annihilation code will see a duplicate.
						// It only cares about the distinction between 1 or 2,
						// so don't bother generating any more copies.
						fields = append(fields, fields[len(fields)-1])
					}
					continue
				}

				// [Min] 剩下的是那些既没有有效 tag，又是匿名的结构体的字段，需要进行下一层扫描
				// [Min] 将其写入下一层扫描的匿名字段切片中，继续下一层扫描
				// [Min] 由于 ft 是对指针解引用后的类型，所以对于同一结构中包含的匿名字段如 A 和 *A 来说，
				// [Min] 我们只需要扫描一次就可以了（ json 编码的结构是一样的），再由 count 来
				// Record new anonymous struct to explore in next round.
				nextCount[ft]++
				if nextCount[ft] == 1 {
					// [Min] 以类型的名字作为匿名字段名，保留当前的索引结构（内嵌层次+字段层次索引），
					// [Min] 后续对于以该类型为匿名字段的子字段，在此 index 的基础上来建立索引结构
					next = append(next, fillField(field{name: ft.Name(), index: index, typ: ft}))
				}
			}
		}
	}

	sort.Slice(fields, func(i, j int) bool {
		x := fields
		// sort field by name, breaking ties with depth, then
		// breaking ties with "name came from json tag", then
		// breaking ties with index sequence.
		// [Min] 先按 json 字段名升序排序
		if x[i].name != x[j].name {
			return x[i].name < x[j].name
		}
		// [Min] 对于同名的字段，按该字段的层次升序排序
		if len(x[i].index) != len(x[j].index) {
			return len(x[i].index) < len(x[j].index)
		}
		// [Min] 如果层次也相同，有有效 tag 的字段排在前面
		if x[i].tag != x[j].tag {
			return x[i].tag
		}
		// [Min] 如果都有有效 tag，按索引结构排
		return byIndex(x).Less(i, j)
	})

	// Delete all fields that are hidden by the Go rules for embedded fields,
	// except that fields with JSON tags are promoted.

	// The fields are sorted in primary order of name, secondary order
	// of field index length. Loop over names; for each name, delete
	// hidden fields by choosing the one dominant field that survives.
	out := fields[:0]
	for advance, i := 0, 0; i < len(fields); i += advance {
		// One iteration per name.
		// Find the sequence of fields with the name of this first field.
		fi := fields[i]
		name := fi.name
		// [Min] 获取下一个拥有不同 json 字段名的索引的增量 advance
		for advance = 1; i+advance < len(fields); advance++ {
			fj := fields[i+advance]
			if fj.name != name {
				break
			}
		}
		// [Min] 如果没有同名字段，直接写入 out
		if advance == 1 { // Only one field with this name
			out = append(out, fi)
			continue
		}
		// [Min] 对同名字段进行处理，获取一个优先级最高的字段，写入 out
		dominant, ok := dominantField(fields[i : i+advance])
		if ok {
			out = append(out, dominant)
		}
	}

	fields = out
	// [Min] 最后按索引结构排序返回（之前名字优先，用于同名字段的筛选）
	sort.Sort(byIndex(fields))

	return fields
}

// dominantField looks through the fields, all of which are known to
// have the same name, to find the single field that dominates the
// others using Go's embedding rules, modified by the presence of
// JSON tags. If there are multiple top-level fields, the boolean
// will be false: This condition is an error in Go and we skip all
// the fields.
// [Min] 在同名按层次按 tag 优先按索引结构排序的字段中，挑选优先级最高的字段返回
func dominantField(fields []field) (field, bool) {
	// The fields are sorted in increasing index-length order. The winner
	// must therefore be one with the shortest index length. Drop all
	// longer entries, which is easy: just truncate the slice.
	// [Min] 获取第一个字段的层次（最低层），胜出者必须为同层次字段
	length := len(fields[0].index)
	tagged := -1 // Index of first tagged field.
	for i, f := range fields {
		// [Min] 选出同层次字段
		if len(f.index) > length {
			fields = fields[:i]
			break
		}
		if f.tag {
			// [Min] 如果同层中有不止一个 tag name 相同的字段，返回空
			if tagged >= 0 {
				// Multiple tagged fields at the same level: conflict.
				// Return no field.
				return field{}, false
			}
			// [Min] 记录下同层中第一个 tagged 的字段索引
			tagged = i
		}
	}
	// [Min] 同层同名只有一个 tagged 字段，返回该字段
	if tagged >= 0 {
		return fields[tagged], true
	}
	// All remaining fields have the same length. If there's more than one,
	// we have a conflict (two fields named "X" at the same level) and we
	// return no field.
	// [Min] 同层，同名，且都没有有效 tag 的字段多余1个，无法确定优先级，返回空
	if len(fields) > 1 {
		return field{}, false
	}
	// [Min] 最低层只有一个字段，返回该字段
	return fields[0], true
}

var fieldCache struct {
	value atomic.Value // map[reflect.Type][]field
	mu    sync.Mutex   // used only by writers
}

// cachedTypeFields is like typeFields but uses a cache to avoid repeated work.
// [Min] 返回类型 t 中的字段，优先从fieldCache中搜索
func cachedTypeFields(t reflect.Type) []field {
	m, _ := fieldCache.value.Load().(map[reflect.Type][]field)
	f := m[t]
	if f != nil {
		return f
	}

	// Compute fields without lock.
	// Might duplicate effort but won't hold other computations back.
	// [Min] 调用 typeFields 返回需要编码的字段信息
	f = typeFields(t)
	if f == nil {
		f = []field{}
	}

	// [Min] 将刚获得的 t 类型对应的需要编码的字段信息存入fieldCache中
	fieldCache.mu.Lock()
	m, _ = fieldCache.value.Load().(map[reflect.Type][]field)
	// [Min] 深度拷贝原来的 map
	newM := make(map[reflect.Type][]field, len(m)+1)
	for k, v := range m {
		newM[k] = v
	}
	newM[t] = f
	fieldCache.value.Store(newM)
	fieldCache.mu.Unlock()
	return f
}
