// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package runtime

// This file contains the implementation of Go channels.

// Invariants:
//  At least one of c.sendq and c.recvq is empty,
//  except for the case of an unbuffered channel with a single goroutine
//  blocked on it for both sending and receiving using a select statement,
//  in which case the length of c.sendq and c.recvq is limited only by the
//  size of the select statement.
//
// For buffered channels, also:
//  c.qcount > 0 implies that c.recvq is empty.
//  c.qcount < c.dataqsiz implies that c.sendq is empty.

import (
	"runtime/internal/atomic"
	"unsafe"
)

const (
	maxAlign  = 8
	hchanSize = unsafe.Sizeof(hchan{}) + uintptr(-int(unsafe.Sizeof(hchan{}))&(maxAlign-1))
	debugChan = false
)

type hchan struct {
	qcount   uint           // total data in the queue 当前缓存中数据个数
	dataqsiz uint           // size of the circular queue 缓存大小
	buf      unsafe.Pointer // points to an array of dataqsiz elements 指向缓存数组的指针
	elemsize uint16         // [Min] 单个 channel 元素所占空间的大小
	closed   uint32         // [Min] channel 是否已经关闭（1：关闭，0：打开）
	elemtype *_type         // element type 元素类型
	sendx    uint           // send index
	recvx    uint           // receive index
	recvq    waitq          // list of recv waiters 链表，用于暂存那些等待从该 channel 获取数据的 goroutine（sudog）
	sendq    waitq          // list of send waiters 链表，用于暂存那些等待向该 channel 发送数据的 goroutine（sudog）

	// lock protects all fields in hchan, as well as several
	// fields in sudogs blocked on this channel.
	//
	// Do not change another G's status while holding this lock
	// (in particular, do not ready a G), as this can deadlock
	// with stack shrinking.
	lock mutex
}

type waitq struct {
	first *sudog
	last  *sudog
}

//go:linkname reflect_makechan reflect.makechan
func reflect_makechan(t *chantype, size int) *hchan {
	return makechan(t, size)
}

func makechan64(t *chantype, size int64) *hchan {
	if int64(int(size)) != size {
		panic(plainError("makechan: size out of range"))
	}

	return makechan(t, int(size))
}

// [Min] 创建 hchan 实例，主要是在 heap 上开辟相应的空间（ hchan 本身 + buf）
func makechan(t *chantype, size int) *hchan {
	elem := t.elem

	// compiler checks this but be safe.
	// [Min] buffered channel 最多不能超过 1<<16(65536) 大小
	if elem.size >= 1<<16 {
		throw("makechan: invalid channel element type")
	}
	if hchanSize%maxAlign != 0 || elem.align > maxAlign {
		throw("makechan: bad alignment")
	}

	if size < 0 || uintptr(size) > maxSliceCap(elem.size) || uintptr(size)*elem.size > maxAlloc-hchanSize {
		panic(plainError("makechan: size out of range"))
	}

	// Hchan does not contain pointers interesting for GC when elements stored in buf do not contain pointers.
	// buf points into the same allocation, elemtype is persistent.
	// SudoG's are referenced from their owning thread so they can't be collected.
	// TODO(dvyukov,rlh): Rethink when collector can move allocated objects.
	var c *hchan
	switch {
	case size == 0 || elem.size == 0:
		// [Min] 为非缓存 channel，或者 channel 元素不占大小（如struct{}）的 channel 创建内存空间，
		// 只开辟了 hchan 的大小
		// Queue or element size is zero.
		c = (*hchan)(mallocgc(hchanSize, nil, true))
		// Race detector uses this location for synchronization.
		// [Min] 为 race detecor 考虑，将 buf 指向该 hchan 本身
		c.buf = unsafe.Pointer(c)
	case elem.kind&kindNoPointers != 0:
		// [Min] 元素不是指针类型，同时开辟 hchan + buf 的空间（连续的空间）
		// Elements do not contain pointers.
		// Allocate hchan and buf in one call.
		c = (*hchan)(mallocgc(hchanSize+uintptr(size)*elem.size, nil, true))
		// [Min] 设置 buf 的实际地址
		c.buf = add(unsafe.Pointer(c), hchanSize)
	default:
		// Elements contain pointers.
		// [Min] 元素是指针类型，分开创建 hchan 和 buf 的空间（不一定连续）
		c = new(hchan)
		c.buf = mallocgc(uintptr(size)*elem.size, elem, true)
	}

	c.elemsize = uint16(elem.size)
	c.elemtype = elem
	c.dataqsiz = uint(size)

	if debugChan {
		print("makechan: chan=", c, "; elemsize=", elem.size, "; elemalg=", elem.alg, "; dataqsiz=", size, "\n")
	}
	return c
}

// chanbuf(c, i) is pointer to the i'th slot in the buffer.
// [Min] 获取 buf 中第 i 个元素的地址
func chanbuf(c *hchan, i uint) unsafe.Pointer {
	return add(c.buf, uintptr(i)*uintptr(c.elemsize))
}

// entry point for c <- x from compiled code
//go:nosplit
func chansend1(c *hchan, elem unsafe.Pointer) {
	chansend(c, elem, true, getcallerpc())
}

/*
 * generic single channel send/recv
 * If block is not nil,
 * then the protocol will not
 * sleep but return if it could
 * not complete.
 *
 * sleep can wake up with g.param == nil
 * when a channel involved in the sleep has
 * been closed.  it is easiest to loop and re-run
 * the operation; we'll see that it's now closed.
 */
func chansend(c *hchan, ep unsafe.Pointer, block bool, callerpc uintptr) bool {
	if c == nil {
		if !block {
			return false
		}
		// [Min] send to nil channel，block current goroutine
		gopark(nil, nil, waitReasonChanSendNilChan, traceEvGoStop, 2)
		throw("unreachable")
	}

	if debugChan {
		print("chansend: chan=", c, "\n")
	}

	if raceenabled {
		racereadpc(unsafe.Pointer(c), callerpc, funcPC(chansend))
	}

	// Fast path: check for failed non-blocking operation without acquiring the lock.
	//
	// After observing that the channel is not closed, we observe that the channel is
	// not ready for sending. Each of these observations is a single word-sized read
	// (first c.closed and second c.recvq.first or c.qcount depending on kind of channel).
	// Because a closed channel cannot transition from 'ready for sending' to
	// 'not ready for sending', even if the channel is closed between the two observations,
	// they imply a moment between the two when the channel was both not yet closed
	// and not ready for sending. We behave as if we observed the channel at that moment,
	// and report that the send cannot proceed.
	//
	// It is okay if the reads are reordered here: if we observe that the channel is not
	// ready for sending and then observe that it is not closed, that implies that the
	// channel wasn't closed during the first observation.
	// [Min] channel 没有关闭 &&
	// [Min] （（channel 无缓存 && 当前还没有另一个 goroutine 已经准备从该 channel 中接收数据）||
	// [Min] （channel 有缓存 && 缓存已满））
	// [Min] 此时不认为 channel 处于可以发送数据的状态，返回 false
	if !block && c.closed == 0 && ((c.dataqsiz == 0 && c.recvq.first == nil) ||
		(c.dataqsiz > 0 && c.qcount == c.dataqsiz)) {
		return false
	}

	var t0 int64
	if blockprofilerate > 0 {
		t0 = cputicks()
	}

	// [Min] 申请锁，准备向 channel 发送数据
	lock(&c.lock)

	// [Min] channel 已经关闭了，panic
	if c.closed != 0 {
		unlock(&c.lock)
		panic(plainError("send on closed channel"))
	}

	// [Min] 尝试从等待接收数据的队列中获取一个 goroutine（sudog）
	// [Min] 如果存在这样的 goroutine，则直接向该 sudog 对应的栈空间中用来接收数据的变量写入数据
	if sg := c.recvq.dequeue(); sg != nil {
		// Found a waiting receiver. We pass the value we want to send
		// directly to the receiver, bypassing the channel buffer (if any).
		send(c, sg, ep, func() { unlock(&c.lock) }, 3)
		return true
	}

	// [Min] 当前还没有 goroutine 准备好接受数据
	if c.qcount < c.dataqsiz {
		// [Min] 如果 buf 还有空余的位置，直接向该 buf 中待写入的位置写入数据
		// Space is available in the channel buffer. Enqueue the element to send.
		qp := chanbuf(c, c.sendx)
		if raceenabled {
			raceacquire(qp)
			racerelease(qp)
		}
		typedmemmove(c.elemtype, qp, ep)
		// [Min] 调整下一次的写入位置
		c.sendx++
		if c.sendx == c.dataqsiz {
			c.sendx = 0
		}
		// [Min] 增加 buf 中当前数据量
		c.qcount++
		// [Min] 解锁，完成发送
		unlock(&c.lock)
		return true
	}

	// [Min] buf 中已经没有空余的位置了，此时不能发送，返回 false
	if !block {
		unlock(&c.lock)
		return false
	}

	// Block on the channel. Some receiver will complete our operation for us.
	gp := getg()
	mysg := acquireSudog()
	mysg.releasetime = 0
	if t0 != 0 {
		mysg.releasetime = -1
	}
	// No stack splits between assigning elem and enqueuing mysg
	// on gp.waiting where copystack can find it.
	mysg.elem = ep
	mysg.waitlink = nil
	mysg.g = gp
	mysg.isSelect = false
	mysg.c = c
	gp.waiting = mysg
	gp.param = nil
	c.sendq.enqueue(mysg)
	goparkunlock(&c.lock, waitReasonChanSend, traceEvGoBlockSend, 3)

	// someone woke us up.
	if mysg != gp.waiting {
		throw("G waiting list is corrupted")
	}
	gp.waiting = nil
	if gp.param == nil {
		if c.closed == 0 {
			throw("chansend: spurious wakeup")
		}
		panic(plainError("send on closed channel"))
	}
	gp.param = nil
	if mysg.releasetime > 0 {
		blockevent(mysg.releasetime-t0, 2)
	}
	mysg.c = nil
	releaseSudog(mysg)
	return true
}

// send processes a send operation on an empty channel c.
// The value ep sent by the sender is copied to the receiver sg.
// The receiver is then woken up to go on its merry way.
// Channel c must be empty and locked.  send unlocks c with unlockf.
// sg must already be dequeued from c.
// ep must be non-nil and point to the heap or the caller's stack.
// [Min] 用来向无缓存 channel 或者当前为空的带缓存 channel 发送数据
// [Min] receiver 已经准备完成（sudog 已经从 channel 的 recevq 中弹出）
func send(c *hchan, sg *sudog, ep unsafe.Pointer, unlockf func(), skip int) {
	if raceenabled {
		if c.dataqsiz == 0 {
			racesync(c, sg)
		} else {
			// Pretend we go through the buffer, even though
			// we copy directly. Note that we need to increment
			// the head/tail locations only when raceenabled.
			qp := chanbuf(c, c.recvx)
			raceacquire(qp)
			racerelease(qp)
			raceacquireg(sg.g, qp)
			racereleaseg(sg.g, qp)
			c.recvx++
			if c.recvx == c.dataqsiz {
				c.recvx = 0
			}
			c.sendx = c.recvx // c.sendx = (c.sendx+1) % c.dataqsiz
		}
	}
	// [Min] 如果 sudog 中用于接收数据的 elem 不为 nil，则直接跳过 buf 将数据写入该变量中
	if sg.elem != nil {
		sendDirect(c.elemtype, sg, ep)
		sg.elem = nil
	}
	gp := sg.g
	// [Min] 释放 hchan 的锁
	unlockf()
	gp.param = unsafe.Pointer(sg)
	if sg.releasetime != 0 {
		sg.releasetime = cputicks()
	}
	// [Min] 调用 goready 将该 sudog 对应的 goroutine 置为 ready 状态等待再次执行
	goready(gp, skip+1)
}

// Sends and receives on unbuffered or empty-buffered channels are the
// only operations where one running goroutine writes to the stack of
// another running goroutine. The GC assumes that stack writes only
// happen when the goroutine is running and are only done by that
// goroutine. Using a write barrier is sufficient to make up for
// violating that assumption, but the write barrier has to work.
// typedmemmove will call bulkBarrierPreWrite, but the target bytes
// are not in the heap, so that will not help. We arrange to call
// memmove and typeBitsBulkBarrier instead.

// [Min] 将数据直接写入 sudog 中用于接收数据的变量
func sendDirect(t *_type, sg *sudog, src unsafe.Pointer) {
	// src is on our stack, dst is a slot on another stack.

	// Once we read sg.elem out of sg, it will no longer
	// be updated if the destination's stack gets copied (shrunk).
	// So make sure that no preemption points can happen between read & use.
	dst := sg.elem
	typeBitsBulkBarrier(t, uintptr(dst), uintptr(src), t.size)
	// No need for cgo write barrier checks because dst is always
	// Go memory.
	memmove(dst, src, t.size)
}

// [Min] 直接将数据从 sg.elem 中拷贝至 dst 对应的变量
func recvDirect(t *_type, sg *sudog, dst unsafe.Pointer) {
	// dst is on our stack or the heap, src is on another stack.
	// The channel is locked, so src will not move during this
	// operation.
	src := sg.elem
	typeBitsBulkBarrier(t, uintptr(dst), uintptr(src), t.size)
	memmove(dst, src, t.size)
}

func closechan(c *hchan) {
	if c == nil {
		panic(plainError("close of nil channel"))
	}

	lock(&c.lock)
	if c.closed != 0 {
		unlock(&c.lock)
		panic(plainError("close of closed channel"))
	}

	if raceenabled {
		callerpc := getcallerpc()
		racewritepc(unsafe.Pointer(c), callerpc, funcPC(closechan))
		racerelease(unsafe.Pointer(c))
	}

	c.closed = 1

	var glist *g

	// release all readers
	for {
		sg := c.recvq.dequeue()
		if sg == nil {
			break
		}
		if sg.elem != nil {
			typedmemclr(c.elemtype, sg.elem)
			sg.elem = nil
		}
		if sg.releasetime != 0 {
			sg.releasetime = cputicks()
		}
		gp := sg.g
		gp.param = nil
		if raceenabled {
			raceacquireg(gp, unsafe.Pointer(c))
		}
		gp.schedlink.set(glist)
		glist = gp
	}

	// release all writers (they will panic)
	for {
		sg := c.sendq.dequeue()
		if sg == nil {
			break
		}
		sg.elem = nil
		if sg.releasetime != 0 {
			sg.releasetime = cputicks()
		}
		gp := sg.g
		gp.param = nil
		if raceenabled {
			raceacquireg(gp, unsafe.Pointer(c))
		}
		gp.schedlink.set(glist)
		glist = gp
	}
	unlock(&c.lock)

	// Ready all Gs now that we've dropped the channel lock.
	for glist != nil {
		gp := glist
		glist = glist.schedlink.ptr()
		gp.schedlink = 0
		goready(gp, 3)
	}
}

// entry points for <- c from compiled code
//go:nosplit
func chanrecv1(c *hchan, elem unsafe.Pointer) {
	chanrecv(c, elem, true)
}

//go:nosplit
func chanrecv2(c *hchan, elem unsafe.Pointer) (received bool) {
	_, received = chanrecv(c, elem, true)
	return
}

// chanrecv receives on channel c and writes the received data to ep.
// ep may be nil, in which case received data is ignored.
// If block == false and no elements are available, returns (false, false).
// Otherwise, if c is closed, zeros *ep and returns (true, false).
// Otherwise, fills in *ep with an element and returns (true, true).
// A non-nil ep must point to the heap or the caller's stack.
func chanrecv(c *hchan, ep unsafe.Pointer, block bool) (selected, received bool) {
	// raceenabled: don't need to check ep, as it is always on the stack
	// or is new memory allocated by reflect.

	if debugChan {
		print("chanrecv: chan=", c, "\n")
	}

	// [Min] receive from nil channel，block
	if c == nil {
		if !block {
			return
		}
		gopark(nil, nil, waitReasonChanReceiveNilChan, traceEvGoStop, 2)
		throw("unreachable")
	}

	// Fast path: check for failed non-blocking operation without acquiring the lock.
	//
	// After observing that the channel is not ready for receiving, we observe that the
	// channel is not closed. Each of these observations is a single word-sized read
	// (first c.sendq.first or c.qcount, and second c.closed).
	// Because a channel cannot be reopened, the later observation of the channel
	// being not closed implies that it was also not closed at the moment of the
	// first observation. We behave as if we observed the channel at that moment
	// and report that the receive cannot proceed.
	//
	// The order of operations is important here: reversing the operations can lead to
	// incorrect behavior when racing with a close.
	// [Min] （（channel 无缓存 && 此时并没有另一个 goroutine 已经准备好发送数据）||
	// [Min] （channel 有缓存 && 此时为空 channel））&&
	// [Min] channel 没有关闭
	// [Min] 此时无法完成接收数据，返回 false
	if !block && (c.dataqsiz == 0 && c.sendq.first == nil ||
		c.dataqsiz > 0 && atomic.Loaduint(&c.qcount) == 0) &&
		atomic.Load(&c.closed) == 0 {
		return
	}

	var t0 int64
	if blockprofilerate > 0 {
		t0 = cputicks()
	}

	// [Min] 申请锁，准备接收数据
	lock(&c.lock)

	// [Min] 如果已经关闭且 channel 为空，将接收数据的变量置为零值，且返回 false 表明通道已经关闭
	if c.closed != 0 && c.qcount == 0 {
		if raceenabled {
			raceacquire(unsafe.Pointer(c))
		}
		unlock(&c.lock)
		if ep != nil {
			typedmemclr(c.elemtype, ep)
		}
		return true, false
	}

	// [Min] channel 没有关闭，或者缓存不空
	// [Min] 尝试从等待发送的对应中弹出一个 sudog，
	// [Min] 如果存在这样的 sudog，则说明此时缓存已满或者 channel 无缓存，
	// [Min] 可以直接从 sudog 的 elem 中获取数据
	if sg := c.sendq.dequeue(); sg != nil {
		// Found a waiting sender. If buffer is size 0, receive value
		// directly from sender. Otherwise, receive from head of queue
		// and add sender's value to the tail of the queue (both map to
		// the same buffer slot because the queue is full).
		recv(c, sg, ep, func() { unlock(&c.lock) }, 3)
		return true, true
	}

	// [Min] 不存在待发送数据的 sudog
	if c.qcount > 0 {
		// [Min] 如果 buf 中有数据，则直接从 buf 中获取数据即可
		// Receive directly from queue
		// [Min] 获取当前 buf 中准备被 receive 的元素
		qp := chanbuf(c, c.recvx)
		if raceenabled {
			raceacquire(qp)
			racerelease(qp)
		}
		// [Min] 接收变量不为 nil，则直接拷贝即可
		if ep != nil {
			typedmemmove(c.elemtype, ep, qp)
		}
		// [Min] 将接收的数据从 buf 中移除
		typedmemclr(c.elemtype, qp)
		// [Min] 调整 buf 索引
		c.recvx++
		if c.recvx == c.dataqsiz {
			c.recvx = 0
		}
		// [Min] buf 此时的数据量减一，解锁返回，完成接收
		c.qcount--
		unlock(&c.lock)
		return true, true
	}

	if !block {
		unlock(&c.lock)
		return false, false
	}

	// no sender available: block on this channel.
	gp := getg()
	mysg := acquireSudog()
	mysg.releasetime = 0
	if t0 != 0 {
		mysg.releasetime = -1
	}
	// No stack splits between assigning elem and enqueuing mysg
	// on gp.waiting where copystack can find it.
	mysg.elem = ep
	mysg.waitlink = nil
	gp.waiting = mysg
	mysg.g = gp
	mysg.isSelect = false
	mysg.c = c
	gp.param = nil
	c.recvq.enqueue(mysg)
	goparkunlock(&c.lock, waitReasonChanReceive, traceEvGoBlockRecv, 3)

	// someone woke us up
	if mysg != gp.waiting {
		throw("G waiting list is corrupted")
	}
	gp.waiting = nil
	if mysg.releasetime > 0 {
		blockevent(mysg.releasetime-t0, 2)
	}
	closed := gp.param == nil
	gp.param = nil
	mysg.c = nil
	releaseSudog(mysg)
	return true, !closed
}

// recv processes a receive operation on a full channel c.
// There are 2 parts:
// 1) The value sent by the sender sg is put into the channel
//    and the sender is woken up to go on its merry way.
// 2) The value received by the receiver (the current G) is
//    written to ep.
// For synchronous channels, both values are the same.
// For asynchronous channels, the receiver gets its data from
// the channel buffer and the sender's data is put in the
// channel buffer.
// Channel c must be full and locked. recv unlocks c with unlockf.
// sg must already be dequeued from c.
// A non-nil ep must point to the heap or the caller's stack.
// [Min] channel 为无缓存 channel 或者缓存已满的情况下，接收数据
// [Min]  作为发送方的 sudog 已经弹出，ep 为接收数据的变量的指针
func recv(c *hchan, sg *sudog, ep unsafe.Pointer, unlockf func(), skip int) {
	if c.dataqsiz == 0 {
		// [Min] 无缓存 channel，直接将数据从 sudog 的 elem 拷贝至 ep 指向的变量中
		if raceenabled {
			racesync(c, sg)
		}
		if ep != nil {
			// copy data from sender
			recvDirect(c.elemtype, sg, ep)
		}
	} else {
		// Queue is full. Take the item at the
		// head of the queue. Make the sender enqueue
		// its item at the tail of the queue. Since the
		// queue is full, those are both the same slot.
		// [Min] 此时 buf 是满的，我们要先将 buf 中接收索引指向的数据移出到接收变量 ep，
		// [Min] 再将 sudog 中待发送的数据写入到 buf 中发送索引指向的位置

		// [Min] 获取此时 buf 中接收索引指向的数据
		qp := chanbuf(c, c.recvx)
		if raceenabled {
			raceacquire(qp)
			racerelease(qp)
			raceacquireg(sg.g, qp)
			racereleaseg(sg.g, qp)
		}
		// copy data from queue to receiver
		// [Min] 接收变量不为 nil，则先从 buf 中获取数据
		if ep != nil {
			typedmemmove(c.elemtype, ep, qp)
		}
		// copy data from sender to queue
		// [Min] 再将待发送的 sudog 中的数据写入到 buf 中（取代原来的接收索引位置即可）
		typedmemmove(c.elemtype, qp, sg.elem)
		// [Min] 调整索引值
		c.recvx++
		if c.recvx == c.dataqsiz {
			c.recvx = 0
		}
		c.sendx = c.recvx // c.sendx = (c.sendx+1) % c.dataqsiz
	}
	sg.elem = nil
	gp := sg.g
	unlockf()
	gp.param = unsafe.Pointer(sg)
	if sg.releasetime != 0 {
		sg.releasetime = cputicks()
	}
	// [Min] 将待发送数据的 sudog 对应的 goroutine 置为 ready
	goready(gp, skip+1)
}

// compiler implements
//
//	select {
//	case c <- v:
//		... foo
//	default:
//		... bar
//	}
//
// as
//
//	if selectnbsend(c, v) {
//		... foo
//	} else {
//		... bar
//	}
//
// [Min] 用于 select case 中的发送数据到 channel，返回是否发送成功（成功则表明取消阻塞）
func selectnbsend(c *hchan, elem unsafe.Pointer) (selected bool) {
	return chansend(c, elem, false, getcallerpc())
}

// compiler implements
//
//	select {
//	case v = <-c:
//		... foo
//	default:
//		... bar
//	}
//
// as
//
//	if selectnbrecv(&v, c) {
//		... foo
//	} else {
//		... bar
//	}
//
// [Min] 用于 select case 中从 channel 接收数据（一元），返回是否接收成功（成功则表示取消阻塞）
func selectnbrecv(elem unsafe.Pointer, c *hchan) (selected bool) {
	selected, _ = chanrecv(c, elem, false)
	return
}

// compiler implements
//
//	select {
//	case v, ok = <-c:
//		... foo
//	default:
//		... bar
//	}
//
// as
//
//	if c != nil && selectnbrecv2(&v, &ok, c) {
//		... foo
//	} else {
//		... bar
//	}
//
// [Min] 用于 select case 中从 channel 接收数据（二元），返回是否接收成功（成功则表示取消阻塞）
func selectnbrecv2(elem unsafe.Pointer, received *bool, c *hchan) (selected bool) {
	// TODO(khr): just return 2 values from this function, now that it is in Go.
	selected, *received = chanrecv(c, elem, false)
	return
}

//go:linkname reflect_chansend reflect.chansend
func reflect_chansend(c *hchan, elem unsafe.Pointer, nb bool) (selected bool) {
	return chansend(c, elem, !nb, getcallerpc())
}

//go:linkname reflect_chanrecv reflect.chanrecv
func reflect_chanrecv(c *hchan, nb bool, elem unsafe.Pointer) (selected bool, received bool) {
	return false, chanrecv(c, elem, !nb)
}

//go:linkname reflect_chanlen reflect.chanlen
func reflect_chanlen(c *hchan) int {
	if c == nil {
		return 0
	}
	return int(c.qcount)
}

//go:linkname reflect_chancap reflect.chancap
func reflect_chancap(c *hchan) int {
	if c == nil {
		return 0
	}
	return int(c.dataqsiz)
}

//go:linkname reflect_chanclose reflect.chanclose
func reflect_chanclose(c *hchan) {
	closechan(c)
}

func (q *waitq) enqueue(sgp *sudog) {
	sgp.next = nil
	x := q.last
	if x == nil {
		sgp.prev = nil
		q.first = sgp
		q.last = sgp
		return
	}
	sgp.prev = x
	x.next = sgp
	q.last = sgp
}

func (q *waitq) dequeue() *sudog {
	for {
		sgp := q.first
		if sgp == nil {
			return nil
		}
		y := sgp.next
		if y == nil {
			q.first = nil
			q.last = nil
		} else {
			y.prev = nil
			q.first = y
			sgp.next = nil // mark as removed (see dequeueSudog)
		}

		// if a goroutine was put on this queue because of a
		// select, there is a small window between the goroutine
		// being woken up by a different case and it grabbing the
		// channel locks. Once it has the lock
		// it removes itself from the queue, so we won't see it after that.
		// We use a flag in the G struct to tell us when someone
		// else has won the race to signal this goroutine but the goroutine
		// hasn't removed itself from the queue yet.
		if sgp.isSelect {
			if !atomic.Cas(&sgp.g.selectDone, 0, 1) {
				continue
			}
		}

		return sgp
	}
}

func racesync(c *hchan, sg *sudog) {
	racerelease(chanbuf(c, 0))
	raceacquireg(sg.g, chanbuf(c, 0))
	racereleaseg(sg.g, chanbuf(c, 0))
	raceacquire(chanbuf(c, 0))
}
