// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package bufio implements buffered I/O. It wraps an io.Reader or io.Writer
// object, creating another object (Reader or Writer) that also implements
// the interface but provides buffering and some help for textual I/O.
package bufio

import (
	"bytes"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	defaultBufSize = 4096 //[Min]4k
)

var (
	ErrInvalidUnreadByte = errors.New("bufio: invalid use of UnreadByte")
	ErrInvalidUnreadRune = errors.New("bufio: invalid use of UnreadRune")
	ErrBufferFull        = errors.New("bufio: buffer full")
	ErrNegativeCount     = errors.New("bufio: negative count")
)

// Buffered input.

// Reader implements buffering for an io.Reader object.
type Reader struct {
	buf  []byte    //[Min] 缓存内容的slice
	rd   io.Reader // reader provided by the client [Min] 一般是调用方传入的一个被赋值过的接口
	r, w int       // buf read and write positions
	/* [Min] r是当前buf中有效数据的起始位，w是下一次调用底层read后要将数据写入到buf中的起始位置，
	也就是说，buf[r:w]即为当前有效数据（已经读到的还没返回给客户的数据）的范围
	*/
	err          error
	lastByte     int //[Min] 当前状态下上一次返回客户的最后一个byte
	lastRuneSize int //[Min] 当前状态下上一次返回客户的最后一个rune字符对应的utf8字符的字节数
}

const minReadBufferSize = 16
const maxConsecutiveEmptyReads = 100

// NewReaderSize returns a new Reader whose buffer has at least the specified
// size. If the argument io.Reader is already a Reader with large enough
// size, it returns the underlying Reader.
// [Min]
func NewReaderSize(rd io.Reader, size int) *Reader {
	// Is it already a Reader?
	b, ok := rd.(*Reader) //[Min] 类型断言，判断是否已经是bufio.Reader了，如果buf长度也够，则直接返回当前的*Reader
	if ok && len(b.buf) >= size {
		return b
	}
	if size < minReadBufferSize {
		size = minReadBufferSize // [Min] 最小buf长度为16
	}
	r := new(Reader)
	r.reset(make([]byte, size), rd) //[Min] 初始化新建的Reader并返回
	return r
}

// NewReader returns a new Reader whose buffer has the default size.
// [Min] 返回一个*bufio.Reader对象，bufsize为默认的4K
func NewReader(rd io.Reader) *Reader {
	return NewReaderSize(rd, defaultBufSize)
}

// Size returns the size of the underlying buffer in bytes.
// [Min]返回buf的大小
func (r *Reader) Size() int { return len(r.buf) }

// Reset discards any buffered data, resets all state, and switches
// the buffered reader to read from r.
// [Min] 重置Reader，把rd指向r
func (b *Reader) Reset(r io.Reader) {
	b.reset(b.buf, r)
}

func (b *Reader) reset(buf []byte, r io.Reader) {
	*b = Reader{
		buf:          buf,
		rd:           r,
		lastByte:     -1,
		lastRuneSize: -1,
	}
}

var errNegativeRead = errors.New("bufio: reader returned negative count from Read")

// fill reads a new chunk into the buffer.
// [Min] 填充当前buf，fill会先把现有的buf内容移到buf的头部（如果有的话），再最多尝试100次读取，直到读到数据写入后续的空白buf中
func (b *Reader) fill() {
	// Slide existing data to beginning.
	if b.r > 0 {
		copy(b.buf, b.buf[b.r:b.w])
		b.w -= b.r
		b.r = 0
	}

	if b.w >= len(b.buf) {
		panic("bufio: tried to fill full buffer")
	}

	// Read new data: try a limited number of times.
	for i := maxConsecutiveEmptyReads; i > 0; i-- {
		n, err := b.rd.Read(b.buf[b.w:])
		if n < 0 {
			panic(errNegativeRead)
		}
		b.w += n
		if err != nil {
			b.err = err
			return
		}
		if n > 0 {
			return
		}
	}
	b.err = io.ErrNoProgress
}

// [Min] 返回当前Reader中的err并置nil
func (b *Reader) readErr() error {
	err := b.err
	b.err = nil
	return err
}

// Peek returns the next n bytes without advancing the reader. The bytes stop
// being valid at the next read call. If Peek returns fewer than n bytes, it
// also returns an error explaining why the read is short. The error is
// ErrBufferFull if n is larger than b's buffer size.
// [Min] 预读后续n位，ErrBufferFull并不是指整个buf满了，而是要告知客户我已经尽力最大努力，这是我当前所有的缓存数据
func (b *Reader) Peek(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrNegativeCount
	}
	/* [Min] 如果当前buf中现有的数据少于n，且buf还没填满，则尝试fill进行填充
	所以这之后的buf要么就是满的，要么就是已缓存了客户所有的数据，要么就是出错了
	*/
	for b.w-b.r < n && b.w-b.r < len(b.buf) && b.err == nil {
		b.fill() // b.w-b.r < len(b.buf) => buffer is not full
	}
	/* [Min]
	如果n大于整个buf的长度，则返回当前所有的缓存，并告诉已经返回了所有的缓存
	*/
	if n > len(b.buf) {
		return b.buf[b.r:b.w], ErrBufferFull
	}
	/* [Min]
	如果n小于整个buf长度但却大于现有的有效缓存长度，则返回现有的缓存，并告知已返回了所有
	*/
	// 0 <= n <= len(b.buf)
	var err error
	if avail := b.w - b.r; avail < n {
		// not enough data in buffer
		n = avail
		err = b.readErr()
		if err == nil {
			err = ErrBufferFull
		}
	}
	return b.buf[b.r : b.r+n], err
}

// Discard skips the next n bytes, returning the number of bytes discarded.
//
// If Discard skips fewer than n bytes, it also returns an error.
// If 0 <= n <= b.Buffered(), Discard is guaranteed to succeed without
// reading from the underlying io.Reader.
/* [Min]
当当前缓存的长度满足客户想要跳过的长度时，discard总能成功执行，反之有可能只能跳过少于等于客户需求的长度，
因为这需要再次或者多次继续缓存数据，碰到错误的时候就会停止继续跳过。比如已经缓存完所有客户的数据还没跳完。
*/
func (b *Reader) Discard(n int) (discarded int, err error) {
	if n < 0 {
		return 0, ErrNegativeCount
	}
	if n == 0 {
		return
	}
	/* [Min]
	remain 理解为在客户的需求下总共还剩下多少没有跳过的
	*/
	remain := n
	for {
		/* [Min]
		skip 理解为单次buf中需要跳过的长度，所以要先判断当前现有缓存的长度，如果不够还剩下没跳过的，
		则要再调用fill，从下一次的缓存数据中继续检查和跳过，直到最后一次的缓存足够满足剩下没跳过的，
		或者当错误状态不为nil的时候，再返回总共跳过的长度和error
		*/
		skip := b.Buffered()
		if skip == 0 {
			b.fill()
			skip = b.Buffered()
		}
		if skip > remain {
			skip = remain
		}
		b.r += skip
		remain -= skip
		if remain == 0 {
			return n, nil
		}
		if b.err != nil {
			return n - remain, b.readErr()
		}
	}
}

// Read reads data into p.
// It returns the number of bytes read into p.
// The bytes are taken from at most one Read on the underlying Reader,
// hence n may be less than len(p).
// At EOF, the count will be zero and err will be io.EOF.
/* [Min]
当缓存中没有有效数据的时候（r=w），则只调用一次底层read，所以如果当p的大小超过一次read的最大长度时，
该方法读取到的数据可能小于p的长度
当缓存中有有效数据时（r<w），则尽可能多的从有效数据中拷贝到p中，所以和上一种情况一样也存在n<p的情况
*/
func (b *Reader) Read(p []byte) (n int, err error) {
	n = len(p)
	if n == 0 {
		return 0, b.readErr()
	}
	if b.r == b.w {
		/* [Min]
		当前缓存无有效数据的时候
		*/
		if b.err != nil {
			return 0, b.readErr()
		}
		if len(p) >= len(b.buf) {
			/* [Min]
			如果客户的容器长度大于整个buf的长度，则直接读取到客户的容器中，不经过buf
			*/
			// Large read, empty buffer.
			// Read directly into p to avoid copy.
			n, b.err = b.rd.Read(p)
			if n < 0 {
				panic(errNegativeRead)
			}
			if n > 0 {
				/* [Min]
				因为没有经过buf，所以当读取到数据的时候，要在这个时候记录，以备后用
				*/
				b.lastByte = int(p[n-1])
				b.lastRuneSize = -1
			}
			return n, b.readErr()
		}
		// One read.
		// Do not use b.fill, which will loop.

		/* [Min]
		缓存容量比较大时，读一次数据，装载有效数据至缓存
		*/
		b.r = 0
		b.w = 0
		n, b.err = b.rd.Read(b.buf)
		if n < 0 {
			panic(errNegativeRead)
		}
		if n == 0 {
			return 0, b.readErr()
		}
		b.w += n
	}
	/* [Min]
	当缓存中有有效数据的时候，尽可能多的从有效数据中返回，也就是说当p比较小时只返回了部分缓存中的数据
	*/
	// copy as much as we can
	n = copy(p, b.buf[b.r:b.w])
	b.r += n
	b.lastByte = int(b.buf[b.r-1])
	b.lastRuneSize = -1
	return n, nil
}

// ReadByte reads and returns a single byte.
// If no byte is available, returns an error.
// [Min] 返回一个byte
func (b *Reader) ReadByte() (byte, error) {
	b.lastRuneSize = -1
	/* [Min]
	无有效数据时，先对buf进行一次填充
	*/
	for b.r == b.w {
		if b.err != nil {
			return 0, b.readErr()
		}
		b.fill() // buffer is empty
	}
	c := b.buf[b.r]
	b.r++
	b.lastByte = int(c)
	return c, nil
}

// UnreadByte unreads the last byte. Only the most recently read byte can be unread.
/* [Min]
回退一个byte的前提是：
1. 上一个返回给客户的byte必须记录在案
2. r必须可以减1或者r=w=0
r可以减一,说明可以向左扩充当前缓存的有效范围用来装载需要回退的byte，而不会引起后续已读byte的丢失，
因为如果通过整体右移的方法([r+1,w+1]),可能会引起丢失
r=w=0,说明目前没有任何有效数据，可以用r来重载该字符，w+1为下次写入位置（不会越界）
*/
func (b *Reader) UnreadByte() error {
	if b.lastByte < 0 || b.r == 0 && b.w > 0 {
		return ErrInvalidUnreadByte
	}
	// b.r > 0 || b.w == 0
	if b.r > 0 {
		b.r--
	} else {
		// b.r == 0 && b.w == 0
		b.w = 1
	}
	b.buf[b.r] = byte(b.lastByte) // [Min] 重置有效范围的起始位置为该byte
	b.lastByte = -1               // [Min] 用户不能连续回退
	b.lastRuneSize = -1
	return nil
}

// ReadRune reads a single UTF-8 encoded Unicode character and returns the
// rune and its size in bytes. If the encoded rune is invalid, it consumes one byte
// and returns unicode.ReplacementChar (U+FFFD) with a size of 1.
// [Min] 读取一个utf-8字符，返回该字符对应的rune，utf-8字符所占的字节长度（注意不是返回rune的长度），error，
func (b *Reader) ReadRune() (r rune, size int, err error) {
	/* [Min]
	循环是为了尽最大可能去排除因截断而引起的解析失败的情况，如果恰巧是因截断造成的且无法填充后续数据进缓存，则自认倒霉
	!utf8.FullRune(b.buf[b.r:b.w]) - 无法从当前有效范围的开头解析出一个有效的utf8码
	b.r+utf8.UTFMax > b.w  - 有效范围小于utf-8码的最大长度，说明这个无法解析的问题可能是截断造成的
	b.w-b.r < len(b.buf) - 当前buf容量还有余，可以继续用来填充后续数据
	循环结束的几种情况：
	1. 当前有效范围足够容纳一个utf8，不会因为截断造成解析失败
	2. 能成功解析第一个utf8
	3. 当前状态有问题
	4. buf已满，无法填充
	*/
	for b.r+utf8.UTFMax > b.w && !utf8.FullRune(b.buf[b.r:b.w]) && b.err == nil && b.w-b.r < len(b.buf) {
		b.fill() // b.w-b.r < len(buf) => buffer is not full
	}
	b.lastRuneSize = -1
	if b.r == b.w { // [Min] 无有效数据，返回零值
		return 0, 0, b.readErr()
	}
	r, size = rune(b.buf[b.r]), 1
	if r >= utf8.RuneSelf {
		r, size = utf8.DecodeRune(b.buf[b.r:b.w])
		/* [Min]
		通过第一个字节来判断是否是多字节的utf8码，是的话就尝试解析第一个字符，
		如果有错也不管了，就直接返回unicode.ReplacementChar (U+FFFD)，1
		*/
	}
	b.r += size
	b.lastByte = int(b.buf[b.r-1])
	b.lastRuneSize = size // [Min] 记录该字符对应的utf8码的字节长度
	return r, size, nil
}

// UnreadRune unreads the last rune. If the most recent read operation on
// the buffer was not a ReadRune, UnreadRune returns an error.  (In this
// regard it is stricter than UnreadByte, which will unread the last byte
// from any read operation.)
/* [Min]
回退上一个读取的rune字符，回退条件比回退字节更严格，
必须上一次为读取rune，也就是说lastRuneSize要不为-1，
且r至少可以减去lastRuneSize，用来重载该字符
*/
func (b *Reader) UnreadRune() error {
	if b.lastRuneSize < 0 || b.r < b.lastRuneSize {
		return ErrInvalidUnreadRune
	}
	b.r -= b.lastRuneSize
	b.lastByte = -1
	b.lastRuneSize = -1
	return nil
}

// Buffered returns the number of bytes that can be read from the current buffer.
// [Min] 返回当前buf中有效数据的长度
func (b *Reader) Buffered() int { return b.w - b.r }

// ReadSlice reads until the first occurrence of delim in the input,
// returning a slice pointing at the bytes in the buffer.
// The bytes stop being valid at the next read.
// If ReadSlice encounters an error before finding a delimiter,
// it returns all the data in the buffer and the error itself (often io.EOF).
// ReadSlice fails with error ErrBufferFull if the buffer fills without a delim.
// Because the data returned from ReadSlice will be overwritten
// by the next I/O operation, most clients should use
// ReadBytes or ReadString instead.
// ReadSlice returns err != nil if and only if line does not end in delim.
/* [Min]
1. 根据delim读取buf，返回指向该buf中满足条件的新的slice，也就是说具备修改buf对应部分数据的能力，
2. 当该段buf被改动时，会影响到之前获取的slice，所以要慎用，最好用ReadBytes或者ReadString替代
3. 搜索的范围最多撑满整个buf容量，即调用fill之后充满buf的数据
*/
func (b *Reader) ReadSlice(delim byte) (line []byte, err error) {
	for {
		// Search buffer.
		/* [Min]
		当前有效数据中找到标识符，则返回指向buf中该段内容的slice（包括delim本身）
		*/
		if i := bytes.IndexByte(b.buf[b.r:b.w], delim); i >= 0 {
			line = b.buf[b.r : b.r+i+1]
			b.r += i + 1
			break
		}

		// Pending error?
		/* [Min]
		当前有效数据中没找到标识符，且有错误，则返回整个有效数据区和当前的错误
		*/
		if b.err != nil {
			line = b.buf[b.r:b.w]
			b.r = b.w
			err = b.readErr()
			break
		}

		// Buffer full?
		/* [Min]
		整个buf已满，则返回整个buf，并告知已返回整个buf，如要继续搜索，需要客户继续readslice读取操作
		*/
		if b.Buffered() >= len(b.buf) {
			b.r = b.w
			line = b.buf
			err = ErrBufferFull
			break
		}

		/* [Min]
		如果buf没满也没有错误，则填充buf，继续搜索标识符
		*/
		b.fill() // buffer is not full
	}

	// Handle last byte, if any. [Min] 记录lastbyte
	if i := len(line) - 1; i >= 0 {
		b.lastByte = int(line[i])
		b.lastRuneSize = -1
	}

	return
}

// ReadLine is a low-level line-reading primitive. Most callers should use
// ReadBytes('\n') or ReadString('\n') instead or use a Scanner.
//
// ReadLine tries to return a single line, not including the end-of-line bytes.
// If the line was too long for the buffer then isPrefix is set and the
// beginning of the line is returned. The rest of the line will be returned
// from future calls. isPrefix will be false when returning the last fragment
// of the line. The returned buffer is only valid until the next call to
// ReadLine. ReadLine either returns a non-nil line or it returns an error,
// never both.
//
// The text returned from ReadLine does not include the line end ("\r\n" or "\n").
// No indication or error is given if the input ends without a final line end.
// Calling UnreadByte after ReadLine will always unread the last byte read
// (possibly a character belonging to the line end) even if that byte is not
// part of the line returned by ReadLine.
/* [Min]
1. ReadLine 是通过 ReadSlice 实现的，所以readslice的缺点readline都有
2. 返回的是去掉换行符后的指向buf对应部分的slice，需要及时尽快处理
3. 用户通过prefix来判断是否该行还在继续，若是则继续调用readline
4. 因为不返回换行符，而换行符实际上是已读字节，所以在Readline之后调用UnreadByte，很可能无法达到用户想要的效果，
    因为实际上你可能只回退了一个\n,而用户想回退的却是他所获得的line中的最后一个字节（非\r\n）
*/
func (b *Reader) ReadLine() (line []byte, isPrefix bool, err error) {
	line, err = b.ReadSlice('\n') // [Min] 调用readslice查看换行符\n
	// [Min] 返回了数据但是没有找到\n
	if err == ErrBufferFull {
		// Handle the case where "\r\n" straddles the buffer.
		// [Min]  先考虑特殊情况 \r\n 中的\n正好被buf截断
		if len(line) > 0 && line[len(line)-1] == '\r' {
			// Put the '\r' back on buf and drop it from line.
			// Let the next call to ReadLine check for "\r\n".
			/* [Min]
			若是\r\n被截断，且r可以退回，则回退\r至buf中，用于下次判断是否是换行符\r\n
			注意这里另一个可回退的条件r=w=0并不满足，因为已经返回了至少一个有效数据\r,所以w不可能为0
			*/
			if b.r == 0 {
				// should be unreachable
				panic("bufio: tried to rewind past start of buffer")
			}
			b.r--
			line = line[:len(line)-1] // [Min] 这个返回给客户的数据去除\r
		}
		return line, true, nil // [Min] 返回prefix = true，告知用户继续readline
	}

	// [Min] 调用readslice没有任何返回的情况
	if len(line) == 0 {
		if err != nil {
			line = nil
		}
		return
	}
	err = nil

	// [Min] 调用readslice且找到\n的情况，去掉\n或者\r\n返回用户，prefix为false
	if line[len(line)-1] == '\n' {
		drop := 1
		if len(line) > 1 && line[len(line)-2] == '\r' {
			drop = 2
		}
		line = line[:len(line)-drop]
	}
	return
}

// ReadBytes reads until the first occurrence of delim in the input,
// returning a slice containing the data up to and including the delimiter.
// If ReadBytes encounters an error before finding a delimiter,
// it returns the data read before the error and the error itself (often io.EOF).
// ReadBytes returns err != nil if and only if the returned data does not end in
// delim.
// For simple uses, a Scanner may be more convenient.
/* [Min]
ReadBytes 是高阶版ReadSlice，会返回直到 delim的内容，不用用户一次一次的反复调用，
且返回的不是指向buf的slice，而是一份拷贝的slice
*/
func (b *Reader) ReadBytes(delim byte) ([]byte, error) {
	// Use ReadSlice to look for array,
	// accumulating full buffers.
	var frag []byte
	var full [][]byte
	var err error
	for {
		var e error
		frag, e = b.ReadSlice(delim)
		if e == nil { // got final fragment [Min] 找到了，跳出循环不用继续readslice
			break
		}
		if e != ErrBufferFull { // unexpected error [Min] 报了不是没找到的错，也跳出循环
			err = e
			break
		}

		// Make a copy of the buffer.
		/* [Min]
		full中存了每个当前返回slice里面内容的副本，不仅仅是slice的副本
		这里必须先新建一个[]byte来存储当前返回的但并没有找到标识符的slice，
		不能直接把frag添加到full[][]byte中，因为下次readslice会覆盖frag指向的缓存
		或者建一个一维的full[]byte,直接把元素append进去,full = append(full, buf...)
		*/
		buf := make([]byte, len(frag))
		copy(buf, frag) // [Min] copy(s2,s1)是按元素一个一个拷贝，相当于会拷贝底层数组，不是单纯的slice赋值（共享底层数组）
		full = append(full, buf)
	}

	// Allocate new buffer to hold the full pieces and the fragment.
	// [Min] 拼装整行信息
	n := 0
	for i := range full {
		n += len(full[i])
	}
	n += len(frag)

	// Copy full pieces and fragment in.
	buf := make([]byte, n)
	n = 0
	for i := range full {
		n += copy(buf[n:], full[i])
	}
	copy(buf[n:], frag)
	return buf, err
}

// ReadString reads until the first occurrence of delim in the input,
// returning a string containing the data up to and including the delimiter.
// If ReadString encounters an error before finding a delimiter,
// it returns the data read before the error and the error itself (often io.EOF).
// ReadString returns err != nil if and only if the returned data does not end in
// delim.
// For simple uses, a Scanner may be more convenient.
// [Min] ReadBytes套了个壳，只是返回的是string，不是slice，其他都一样
func (b *Reader) ReadString(delim byte) (string, error) {
	bytes, err := b.ReadBytes(delim)
	return string(bytes), err
}

// WriteTo implements io.WriterTo.
// This may make multiple calls to the Read method of the underlying Reader.
/* [Min]
1. 先把已读到的缓存写入w中
2. rd是否实现了WriterTo接口，是则直接调用rd本身的WriteTo方法写入w
3. rd没实现WriterTo接口，但是w实现了ReaderFrom接口，则调用w的ReadFrom方法写入rd的内容
4. 以上都没有实现，则不断通过fill读取rd的数据到buf，然后通过writeBuf将数据从buf中写入w，直到rd中数据结束
*/
func (b *Reader) WriteTo(w io.Writer) (n int64, err error) {
	n, err = b.writeBuf(w)
	if err != nil {
		return
	}

	if r, ok := b.rd.(io.WriterTo); ok {
		m, err := r.WriteTo(w)
		n += m
		return n, err
	}

	if w, ok := w.(io.ReaderFrom); ok {
		m, err := w.ReadFrom(b.rd)
		n += m
		return n, err
	}

	if b.w-b.r < len(b.buf) {
		b.fill() // buffer not full
	}

	for b.r < b.w {
		// b.r < b.w => buffer is not empty
		m, err := b.writeBuf(w)
		n += m
		if err != nil {
			return n, err
		}
		b.fill() // buffer is empty
	}

	if b.err == io.EOF {
		b.err = nil
	}

	return n, b.readErr()
}

var errNegativeWrite = errors.New("bufio: writer returned negative count from Write")

// writeBuf writes the Reader's buffer to the writer.
// [Min] writeBuf直接把当前buf中的有效数据写入w中，返回写入字节数，并更新有效范围（写了就失效，相当于读走了）
func (b *Reader) writeBuf(w io.Writer) (int64, error) {
	n, err := w.Write(b.buf[b.r:b.w])
	if n < 0 {
		panic(errNegativeWrite)
	}
	b.r += n
	return int64(n), err
}

// buffered output

// Writer implements buffering for an io.Writer object.
// If an error occurs writing to a Writer, no more data will be
// accepted and all subsequent writes, and Flush, will return the error.
// After all data has been written, the client should call the
// Flush method to guarantee all data has been forwarded to
// the underlying io.Writer.
type Writer struct {
	err error
	buf []byte
	n   int // [Min] buf中已写入数据的长度
	wr  io.Writer
}

// NewWriterSize returns a new Writer whose buffer has at least the specified
// size. If the argument io.Writer is already a Writer with large enough
// size, it returns the underlying Writer.
// [Min] 和NewReaderSize一致
func NewWriterSize(w io.Writer, size int) *Writer {
	// Is it already a Writer?
	b, ok := w.(*Writer)
	if ok && len(b.buf) >= size {
		return b
	}
	if size <= 0 {
		size = defaultBufSize
	}
	return &Writer{
		buf: make([]byte, size),
		wr:  w,
	}
}

// NewWriter returns a new Writer whose buffer has the default size.
// [Min] 和NewReader一致
func NewWriter(w io.Writer) *Writer {
	return NewWriterSize(w, defaultBufSize)
}

// Size returns the size of the underlying buffer in bytes.
func (b *Writer) Size() int { return len(b.buf) }

// Reset discards any unflushed buffered data, clears any error, and
// resets b to write its output to w.
func (b *Writer) Reset(w io.Writer) {
	b.err = nil
	b.n = 0
	b.wr = w
}

// Flush writes any buffered data to the underlying io.Writer.
/* [Min]
尽量多地把当前buf中的内容写到writer中，
如果报错了，则将未写入的部分保存在buf中，否则逻辑清空buf（置n为0）
*/
func (b *Writer) Flush() error {
	if b.err != nil {
		return b.err
	}
	if b.n == 0 {
		return nil
	}
	n, err := b.wr.Write(b.buf[0:b.n])
	if n < b.n && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		if n > 0 && n < b.n {
			copy(b.buf[0:b.n-n], b.buf[n:b.n])
		}
		b.n -= n
		b.err = err
		return err
	}
	b.n = 0
	return nil
}

// Available returns how many bytes are unused in the buffer.
// [Min] buf的剩余空间
func (b *Writer) Available() int { return len(b.buf) - b.n }

// Buffered returns the number of bytes that have been written into the current buffer.
// [Min] 已有多少数据写入了buf中
func (b *Writer) Buffered() int { return b.n }

// Write writes the contents of p into the buffer.
// It returns the number of bytes written.
// If nn < len(p), it also returns an error explaining
// why the write is short.
/* [Min]
注意是从p写入buf再写入b.wr，返回总共写入的字节数，正常情况下是buf满了再推送入b.wr
 所以最终有可能p的数据大部分写入了wr，还有一段尾巴留在了buf中，需要再次Flush()才能完全写入
*/
func (b *Writer) Write(p []byte) (nn int, err error) {

	/* [Min]

	当buf的剩余容量可以满足最后一次写入的长度，或有错误的时候跳出循环
	若buf为空，则跳过buf直接尝试将数据写到wr中，将剩余的数据记为新的输入p，再次循环
	若buf里有尚未写出的数据，则用p填充后续buf空间，将这些数据一起写入wr，记剩余p，再次循环
	跳出循环后且之前都写入成功，则将最后一部分数据写入buf
	*/
	for len(p) > b.Available() && b.err == nil {
		var n int
		if b.Buffered() == 0 {
			// Large write, empty buffer.
			// Write directly from p to avoid copy.
			n, b.err = b.wr.Write(p)
		} else {
			n = copy(b.buf[b.n:], p)
			b.n += n
			b.Flush()
		}
		nn += n
		p = p[n:]
	}
	if b.err != nil {
		return nn, b.err
	}
	n := copy(b.buf[b.n:], p)
	b.n += n
	nn += n
	return nn, nil
}

// WriteByte writes a single byte.
/* [Min]
写入一个byte，当buf已满，先推送buf，若失败，则报错，若成功，则buf又有了剩余容量，往下继续
当有剩余容量时，写入该字节
*/
func (b *Writer) WriteByte(c byte) error {
	if b.err != nil {
		return b.err
	}
	if b.Available() <= 0 && b.Flush() != nil {
		return b.err
	}
	b.buf[b.n] = c
	b.n++
	return nil
}

// WriteRune writes a single Unicode code point, returning
// the number of bytes written and any error.
// [Min] 向buf中写入一个rune字符对应的utf8字符，返回该utf8字符的字节数
func (b *Writer) WriteRune(r rune) (size int, err error) {
	// [Min] 单字节直接调用WriteByte写入
	if r < utf8.RuneSelf {
		err = b.WriteByte(byte(r))
		if err != nil {
			return 0, err
		}
		return 1, nil
	}
	if b.err != nil {
		return 0, b.err
	}
	/* [Min]
	多字节情况，
	1. 先检查剩余容量是否能容纳一个utf8码的最大长度，若不能，则先Flush写出当前buf中的数据
	2. 再检查容量，还不够，则调用WriteString（一般不会发生，除非buf的长度小于4）
	3. 够容纳之后，再将rune字符转为utf8格式写入buf中，size为该rune字符对应的utf8字符所占字节数
	*/
	n := b.Available()
	if n < utf8.UTFMax {
		if b.Flush(); b.err != nil {
			return 0, b.err
		}
		n = b.Available()
		if n < utf8.UTFMax {
			// Can only happen if buffer is silly small.
			return b.WriteString(string(r))
		}
	}
	size = utf8.EncodeRune(b.buf[b.n:], r)
	b.n += size
	return size, nil
}

// WriteString writes a string.
// It returns the number of bytes written.
// If the count is less than len(s), it also returns an error explaining
// why the write is short.
// [Min] 和Write(p []byte)类似，少了len(s)大于buf总长且buf为空时直接写入的特殊情况
func (b *Writer) WriteString(s string) (int, error) {
	nn := 0
	for len(s) > b.Available() && b.err == nil {
		n := copy(b.buf[b.n:], s)
		b.n += n
		nn += n
		s = s[n:]
		b.Flush()
	}
	if b.err != nil {
		return nn, b.err
	}
	n := copy(b.buf[b.n:], s)
	b.n += n
	nn += n
	return nn, nil
}

// ReadFrom implements io.ReaderFrom.
/* [Min]
1. wr是否已经实现了ReaderFrom，是则直接调用wr自身的ReadFrom方法写入
2. 否，则循环直至r的结尾，或读r时有任何错误：
	   从r中读取数据至buf，从buf中写入wr
3. 返回成功写入字节数
*/
func (b *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	if b.Buffered() == 0 {
		if w, ok := b.wr.(io.ReaderFrom); ok {
			return w.ReadFrom(r)
		}
	}
	var m int
	for {
		if b.Available() == 0 {
			if err1 := b.Flush(); err1 != nil {
				return n, err1
			}
		}
		nr := 0
		for nr < maxConsecutiveEmptyReads {
			m, err = r.Read(b.buf[b.n:])
			if m != 0 || err != nil {
				break
			}
			nr++
		}
		if nr == maxConsecutiveEmptyReads {
			return n, io.ErrNoProgress
		}
		b.n += m
		n += int64(m)
		if err != nil {
			break
		}
	}
	if err == io.EOF {
		// If we filled the buffer exactly, flush preemptively.
		if b.Available() == 0 {
			err = b.Flush()
		} else {
			err = nil
		}
	}
	return n, err
}

// buffered input and output

// ReadWriter stores pointers to a Reader and a Writer.
// It implements io.ReadWriter.
type ReadWriter struct {
	*Reader
	*Writer
}

// NewReadWriter allocates a new ReadWriter that dispatches to r and w.
func NewReadWriter(r *Reader, w *Writer) *ReadWriter {
	return &ReadWriter{r, w}
}
