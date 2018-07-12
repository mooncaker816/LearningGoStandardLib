// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package context defines the Context type, which carries deadlines,
// cancelation signals, and other request-scoped values across API boundaries
// and between processes.
//
// Incoming requests to a server should create a Context, and outgoing
// calls to servers should accept a Context. The chain of function
// calls between them must propagate the Context, optionally replacing
// it with a derived Context created using WithCancel, WithDeadline,
// WithTimeout, or WithValue. When a Context is canceled, all
// Contexts derived from it are also canceled.
//
// The WithCancel, WithDeadline, and WithTimeout functions take a
// Context (the parent) and return a derived Context (the child) and a
// CancelFunc. Calling the CancelFunc cancels the child and its
// children, removes the parent's reference to the child, and stops
// any associated timers. Failing to call the CancelFunc leaks the
// child and its children until the parent is canceled or the timer
// fires. The go vet tool checks that CancelFuncs are used on all
// control-flow paths.
//
// Programs that use Contexts should follow these rules to keep interfaces
// consistent across packages and enable static analysis tools to check context
// propagation:
//
// Do not store Contexts inside a struct type; instead, pass a Context
// explicitly to each function that needs it. The Context should be the first
// parameter, typically named ctx:
//
// 	func DoSomething(ctx context.Context, arg Arg) error {
// 		// ... use ctx ...
// 	}
//
// Do not pass a nil Context, even if a function permits it. Pass context.TODO
// if you are unsure about which Context to use.
//
// Use context Values only for request-scoped data that transits processes and
// APIs, not for passing optional parameters to functions.
//
// The same Context may be passed to functions running in different goroutines;
// Contexts are safe for simultaneous use by multiple goroutines.
//
// See https://blog.golang.org/context for example code for a server that uses
// Contexts.
package context

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// [Min] Context 就是以初始 emptyCtx 为基础，一层一层地包裹原来的 context ，从而构造出新的实体 context，如 cancelCtx，timerCtx，valueCtx
// A Context carries a deadline, a cancelation signal, and other values across
// API boundaries.
//
// Context's methods may be called by multiple goroutines simultaneously.
type Context interface {
	// Deadline returns the time when work done on behalf of this context
	// should be canceled. Deadline returns ok==false when no deadline is
	// set. Successive calls to Deadline return the same results.
	// [Min] 返回当前 context 需要被 cancel 的时间，ok 为 false 的话表示没有 deadline
	Deadline() (deadline time.Time, ok bool)

	// Done returns a channel that's closed when work done on behalf of this
	// context should be canceled. Done may return nil if this context can
	// never be canceled. Successive calls to Done return the same value.
	//
	// WithCancel arranges for Done to be closed when cancel is called;
	// WithDeadline arranges for Done to be closed when the deadline
	// expires; WithTimeout arranges for Done to be closed when the timeout
	// elapses.
	//
	// Done is provided for use in select statements:
	//
	//  // Stream generates values with DoSomething and sends them to out
	//  // until DoSomething returns an error or ctx.Done is closed.
	//  func Stream(ctx context.Context, out chan<- Value) error {
	//  	for {
	//  		v, err := DoSomething(ctx)
	//  		if err != nil {
	//  			return err
	//  		}
	//  		select {
	//  		case <-ctx.Done():
	//  			return ctx.Err()
	//  		case out <- v:
	//  		}
	//  	}
	//  }
	//
	// See https://blog.golang.org/pipelines for more examples of how to use
	// a Done channel for cancelation.
	Done() <-chan struct{}

	// If Done is not yet closed, Err returns nil.
	// If Done is closed, Err returns a non-nil error explaining why:
	// Canceled if the context was canceled
	// or DeadlineExceeded if the context's deadline passed.
	// After Err returns a non-nil error, successive calls to Err return the same error.
	Err() error

	// Value returns the value associated with this context for key, or nil
	// if no value is associated with key. Successive calls to Value with
	// the same key returns the same result.
	//
	// Use context values only for request-scoped data that transits
	// processes and API boundaries, not for passing optional parameters to
	// functions.
	//
	// A key identifies a specific value in a Context. Functions that wish
	// to store values in Context typically allocate a key in a global
	// variable then use that key as the argument to context.WithValue and
	// Context.Value. A key can be any type that supports equality;
	// packages should define keys as an unexported type to avoid
	// collisions.
	//
	// Packages that define a Context key should provide type-safe accessors
	// for the values stored using that key:
	//
	// 	// Package user defines a User type that's stored in Contexts.
	// 	package user
	//
	// 	import "context"
	//
	// 	// User is the type of value stored in the Contexts.
	// 	type User struct {...}
	//
	// 	// key is an unexported type for keys defined in this package.
	// 	// This prevents collisions with keys defined in other packages.
	// 	type key int
	//
	// 	// userKey is the key for user.User values in Contexts. It is
	// 	// unexported; clients use user.NewContext and user.FromContext
	// 	// instead of using this key directly.
	// 	var userKey key
	//
	// 	// NewContext returns a new Context that carries value u.
	// 	func NewContext(ctx context.Context, u *User) context.Context {
	// 		return context.WithValue(ctx, userKey, u)
	// 	}
	//
	// 	// FromContext returns the User value stored in ctx, if any.
	// 	func FromContext(ctx context.Context) (*User, bool) {
	// 		u, ok := ctx.Value(userKey).(*User)
	// 		return u, ok
	// 	}
	Value(key interface{}) interface{}
}

// Canceled is the error returned by Context.Err when the context is canceled.
var Canceled = errors.New("context canceled")

// DeadlineExceeded is the error returned by Context.Err when the context's
// deadline passes.
var DeadlineExceeded error = deadlineExceededError{}

type deadlineExceededError struct{}

func (deadlineExceededError) Error() string   { return "context deadline exceeded" }
func (deadlineExceededError) Timeout() bool   { return true }
func (deadlineExceededError) Temporary() bool { return true }

// An emptyCtx is never canceled, has no values, and has no deadline. It is not
// struct{}, since vars of this type must have distinct addresses.
// [Min] emptyCtx 没有 deadline，不能被 cancel，没有 value
// [Min] 因为对于 emptyCtx 的变量需要有唯一的地址，所以底层类型不是 struct{}，而是 int
type emptyCtx int

// [Min] 没有 deadline
func (*emptyCtx) Deadline() (deadline time.Time, ok bool) {
	return
}

// [Min] Done() 通道永远阻塞，即无法 cancel
func (*emptyCtx) Done() <-chan struct{} {
	return nil
}

// [Min] Err 永远为 nil
func (*emptyCtx) Err() error {
	return nil
}

// [Min] 没有 value
func (*emptyCtx) Value(key interface{}) interface{} {
	return nil
}

func (e *emptyCtx) String() string {
	switch e {
	case background:
		return "context.Background"
	case todo:
		return "context.TODO"
	}
	return "unknown empty Context"
}

var (
	background = new(emptyCtx)
	todo       = new(emptyCtx)
)

// Background returns a non-nil, empty Context. It is never canceled, has no
// values, and has no deadline. It is typically used by the main function,
// initialization, and tests, and as the top-level Context for incoming
// requests.
// [Min] Background 用于顶层 Context，作为root context
func Background() Context {
	return background
}

// TODO returns a non-nil, empty Context. Code should use context.TODO when
// it's unclear which Context to use or it is not yet available (because the
// surrounding function has not yet been extended to accept a Context
// parameter). TODO is recognized by static analysis tools that determine
// whether Contexts are propagated correctly in a program.
func TODO() Context {
	return todo
}

// A CancelFunc tells an operation to abandon its work.
// A CancelFunc does not wait for the work to stop.
// After the first call, subsequent calls to a CancelFunc do nothing.
// [Min] CancelFunc 用来直接取消当前工作，只有第一次调用真正有效，后续调用相当于什么都没做
type CancelFunc func()

// WithCancel returns a copy of parent with a new Done channel. The returned
// context's Done channel is closed when the returned cancel function is called
// or when the parent context's Done channel is closed, whichever happens first.
//
// Canceling this context releases resources associated with it, so code should
// call cancel as soon as the operations running in this Context complete.
// [Min] 继承 parent Context，返回子 context 和子 context 对应的 CancelFunc
// [Min] 子 context 的 Done 通道只有在以下两种情况下会关闭：
// [Min] a. 调用了子 context 对应的 CancelFunc
// [Min] b. 父 context 的 Done 通道关闭
// [Min] 也就是说对于某一 context 执行其对应的 CancelFunc，会导致其所有子孙 context 的 Done 通道关闭
func WithCancel(parent Context) (ctx Context, cancel CancelFunc) {
	// [Min] 新建子 CancelCtx
	c := newCancelCtx(parent)
	// [Min] 建立完新的CancelCtx，要是他与上一级CancelCtx关联起来，
	// [Min] 才能达到上一级 cancel 之后它也 cancel 的效果
	propagateCancel(parent, &c)
	// [Min] 返回该 cancelCtx 和用来执行该 cancelCtx 的CancelFunc函数
	return &c, func() { c.cancel(true, Canceled) }
}

// newCancelCtx returns an initialized cancelCtx.
// [Min] 新建一个
func newCancelCtx(parent Context) cancelCtx {
	return cancelCtx{Context: parent}
}

// propagateCancel arranges for child to be canceled when parent is.
func propagateCancel(parent Context, child canceler) {
	if parent.Done() == nil {
		return // parent is never canceled
	}
	// [Min] 查找由 parent 开始向上追溯的第一个父cancelCtx
	// [Min] 如果有，则需要在该父cancelCtx 中记录下该子 cancelCtx，从而建立联系
	// [Min] 但有可能在创建该子 cancelCtx的时候，父 cancelCtx已经完成 cancel，
	// [Min] 这种情况下只需要直接 cancel 该子 cancelCtx 即可
	// [Min] 如果父 cancelCtx 还没有 cancel，则记录下子 cancelCtx
	if p, ok := parentCancelCtx(parent); ok {
		p.mu.Lock()
		if p.err != nil {
			// parent has already been canceled
			child.cancel(false, p.err)
		} else {
			if p.children == nil {
				p.children = make(map[canceler]struct{})
			}
			p.children[child] = struct{}{}
		}
		p.mu.Unlock()
	} else {
		// [Min] 如果没有父cancelCtx 或 timerCtx，也就是说之前的 context 都没有实现 canceler
		// [Min] 1. 当其父 context 的 done 通道关闭的时候，需要执行 cancel
		// [Min] （在没有父及以上都没有实现 canceler 的前提下，父的 done 是怎么关闭的呢？难道不是 nil 永假无法关闭么？）
		// [Min] （也有可能是为了防止 gopher 自己创建新的并且实现了能关闭 done 的 XXXCtx，这样就能关联上了）
		// [Min] （但是就目前的 context 类型来说，这段 else 似乎是多余的）
		// [Min] 2. 当子 cancelCtx 对应的 cancel 方法在外界被手动执行，无需其他操作，只需要退出该 goroutine
		go func() {
			select {
			case <-parent.Done():
				child.cancel(false, parent.Err())
			case <-child.Done():
			}
		}()
	}
}

// parentCancelCtx follows a chain of parent references until it finds a
// *cancelCtx. This function understands how each of the concrete types in this
// package represents its parent.
// [Min] 向上回溯，返回该父 context 对应的第一个cancelCtx或者 timerCtx 里的 cancelCtx
// [Min] 由于每一个 context 实体都是在其父 context 实体上根据需要生成的，
// [Min] 父和子可能是同一种实体类型，但也可能是不同种类，
// [Min] 所以要先进行类型断言，然后再根据具体类型来获得对应的 cancelCtx （如果有的话）
// [Min] 当父类型为*valueCtx时，需要一直上溯到cancelCtx或 timerCtx，直到最后
func parentCancelCtx(parent Context) (*cancelCtx, bool) {
	for {
		switch c := parent.(type) {
		case *cancelCtx:
			return c, true
		case *timerCtx:
			return &c.cancelCtx, true
		case *valueCtx:
			parent = c.Context
		default:
			return nil, false
		}
	}
}

// removeChild removes a context from its parent.
// [Min] 将 context 从其父 context 中删除
func removeChild(parent Context, child canceler) {
	// [Min] 获得上一级 cancelCtx，没有直接返回
	p, ok := parentCancelCtx(parent)
	if !ok {
		return
	}
	p.mu.Lock()
	// [Min] 从 p 中删除 child
	if p.children != nil {
		delete(p.children, child)
	}
	p.mu.Unlock()
}

// A canceler is a context type that can be canceled directly. The
// implementations are *cancelCtx and *timerCtx.
// [Min] 可以实现直接 cancel 的接口，*cancelCtx 和 *timerCtx 实现了该接口
type canceler interface {
	cancel(removeFromParent bool, err error)
	Done() <-chan struct{}
}

// closedchan is a reusable closed channel.
// [Min] 预定义的已经关闭的通道，在 newCancelCtx 的时候，采用了 lazy init，done 的值为零值 nil，
// [Min] 如果没有特殊修改，在执行 cancel 方法之前，该 cancelCtx 的 done 都是零值 nil，永远阻塞，
// [Min] 只有在执行 cancel 的时候，该 done 才会被此 closechan 替代，从而取消阻塞
var closedchan = make(chan struct{})

func init() {
	close(closedchan)
}

// A cancelCtx can be canceled. When canceled, it also cancels any children
// that implement canceler.
// [Min] 可以被 cancel 的 context 实体，其实就是对 emptyCtx 添加一些用来实现 cancel 的字段
type cancelCtx struct {
	// [Min] 父 context
	Context

	mu sync.Mutex // protects following fields
	// [Min] done 通道，用于父子 context 之间传递消息，
	// [Min] 第一次调用 cancel 时会关闭该通道
	done chan struct{} // created lazily, closed by first cancel call
	// [Min] 用来记录该 cancelCtx 的子 context，
	// [Min] 当调用完第一次 cancel 后（ 确切的说是关闭完儿子们的 done 之后），会置为 nil
	children map[canceler]struct{} // set to nil by the first cancel call
	// [Min] 用来记录第一次调用 cancel 的原因
	err error // set to non-nil by the first cancel call
}

// [Min] 返回cancelCtx的 done 通道
func (c *cancelCtx) Done() <-chan struct{} {
	c.mu.Lock()
	if c.done == nil {
		c.done = make(chan struct{})
	}
	d := c.done // [Min] ??? 为什么要返回一个拷贝呢？   因为 done 为 lazy init，为零值 nil，需要对不同的 cancelCtx 区分
	c.mu.Unlock()
	return d
}

// [Min] 返回 cancelCtx 的 err
func (c *cancelCtx) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *cancelCtx) String() string {
	return fmt.Sprintf("%v.WithCancel", c.Context)
}

// cancel closes c.done, cancels each of c's children, and, if
// removeFromParent is true, removes c from its parent's children.
// [Min] cancel 会关闭 cancelCtx的 done 通道，并且会执行每一个子 context 的 cancel 方法
// [Min] 当removeFromParent为真时，会将该context 从其父 context（确切的说是往上回溯第一个cancelCtx或者包含 cancelCtx 的 timerCtx）中用于记录子 context 的 map 中删除
// [Min] 只有 cancelCtx 会记录子 context
func (c *cancelCtx) cancel(removeFromParent bool, err error) {
	if err == nil {
		panic("context: internal error: missing cancel error")
	}
	c.mu.Lock()
	// [Min] 如果 err 不为 nil，说明之前已经执行过 cancel，直接返回
	if c.err != nil {
		c.mu.Unlock()
		return // already canceled
	}
	// [Min] 设置 err
	c.err = err
	// [Min] 关闭 done 通道，
	// [Min] 如果 context 的 done 通道为 nil，而 nil 永远阻塞，无法关闭，
	// [Min] 所以将 context 置为一个预先设定的关闭的通道，使其达到关闭的效果
	if c.done == nil {
		c.done = closedchan
	} else {
		close(c.done)
	}
	// [Min] 对每一个字 context 执行 cancel 方法，关闭它们各自的 done 通道
	for child := range c.children {
		// NOTE: acquiring the child's lock while holding parent's lock.
		// [Min] 锁住父亲的同时，也会锁住儿子
		child.cancel(false, err)
	}
	// [Min] 此时将记录该 context 的子 context 的 map 置为 nil，
	// [Min] 因为已经将儿子们的 done 都关闭了，以后也没有用处了
	c.children = nil
	c.mu.Unlock()

	// [Min] 根据 flag，将其从父 context 中删除
	if removeFromParent {
		removeChild(c.Context, c)
	}
}

// WithDeadline returns a copy of the parent context with the deadline adjusted
// to be no later than d. If the parent's deadline is already earlier than d,
// WithDeadline(parent, d) is semantically equivalent to parent. The returned
// context's Done channel is closed when the deadline expires, when the returned
// cancel function is called, or when the parent context's Done channel is
// closed, whichever happens first.
//
// Canceling this context releases resources associated with it, so code should
// call cancel as soon as the operations running in this Context complete.
// [Min] 返回一个有 deadline 的 context，到时会自动 cancel，同时也可以提前 cancel
func WithDeadline(parent Context, d time.Time) (Context, CancelFunc) {
	// [Min] 如果 parent 有 deadline，说明 parent 肯定是 timerCtx
	// [Min] 如果现有的 deadline 在给定的 deadline 之前，则不用修改 deadline，直接由该 parent 构造 cancelCtx 即可
	if cur, ok := parent.Deadline(); ok && cur.Before(d) {
		// The current deadline is already sooner than the new one.
		return WithCancel(parent)
	}
	// [Min] 如果没有deadline 或者 deadline 比给定的晚，则需要新建 timerCtx 来设置新的 deadline
	// [Min] 其中 cancelCtx 以之前的 parent 为基础建立
	c := &timerCtx{
		cancelCtx: newCancelCtx(parent),
		deadline:  d,
	}
	// [Min] 建立子 context 与 父 context 的联系，就是将 c 写入 parent 向上（包含）的第一个 cancelCtx 的 map 中
	propagateCancel(parent, c)
	dur := time.Until(d)
	// [Min] 如果 deadline 已经过了，直接 cancel 子 context，并返回
	if dur <= 0 {
		c.cancel(true, DeadlineExceeded) // deadline has already passed
		return c, func() { c.cancel(true, Canceled) }
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// [Min] 如果 c.err 还是 nil，说明还没有 cancel，则按 deadline 设立计时器，到时执行 cancel
	if c.err == nil {
		c.timer = time.AfterFunc(dur, func() {
			c.cancel(true, DeadlineExceeded)
		})
	}
	return c, func() { c.cancel(true, Canceled) }
}

// A timerCtx carries a timer and a deadline. It embeds a cancelCtx to
// implement Done and Err. It implements cancel by stopping its timer then
// delegating to cancelCtx.cancel.
// [Min] timerCtx 以 cancelCtx 为基础，外加deadline 和计时器timer
type timerCtx struct {
	cancelCtx
	timer *time.Timer // Under cancelCtx.mu.

	deadline time.Time
}

// [Min] 返回 deadline
func (c *timerCtx) Deadline() (deadline time.Time, ok bool) {
	return c.deadline, true
}

func (c *timerCtx) String() string {
	return fmt.Sprintf("%v.WithDeadline(%s [%s])", c.cancelCtx.Context, c.deadline, time.Until(c.deadline))
}

func (c *timerCtx) cancel(removeFromParent bool, err error) {
	// [Min] 执行 cancelCtx 的
	c.cancelCtx.cancel(false, err)
	// [Min] 向上，从第一个父cancelCtx 中删除 timerCtx
	if removeFromParent {
		// Remove this timerCtx from its parent cancelCtx's children.
		removeChild(c.cancelCtx.Context, c)
	}
	c.mu.Lock()
	// [Min] 关闭 timer
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.mu.Unlock()
}

// WithTimeout returns WithDeadline(parent, time.Now().Add(timeout)).
//
// Canceling this context releases resources associated with it, so code should
// call cancel as soon as the operations running in this Context complete:
//
// 	func slowOperationWithTimeout(ctx context.Context) (Result, error) {
// 		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
// 		defer cancel()  // releases resources if slowOperation completes before timeout elapses
// 		return slowOperation(ctx)
// 	}
// [Min] 和 WithDeadline 相似，先将 timeout 时间转为对应的 deadline，再调用 WithDeadline
func WithTimeout(parent Context, timeout time.Duration) (Context, CancelFunc) {
	return WithDeadline(parent, time.Now().Add(timeout))
}

// WithValue returns a copy of parent in which the value associated with key is
// val.
//
// Use context Values only for request-scoped data that transits processes and
// APIs, not for passing optional parameters to functions.
//
// The provided key must be comparable and should not be of type
// string or any other built-in type to avoid collisions between
// packages using context. Users of WithValue should define their own
// types for keys. To avoid allocating when assigning to an
// interface{}, context keys often have concrete type
// struct{}. Alternatively, exported context key variables' static
// type should be a pointer or interface.
// [Min] 在 Context 中添加 key-value 对，key 必须是可比较的，此时 context 像一个载体，但不可当成参数滥用
func WithValue(parent Context, key, val interface{}) Context {
	if key == nil {
		panic("nil key")
	}
	if !reflect.TypeOf(key).Comparable() {
		panic("key is not comparable")
	}
	return &valueCtx{parent, key, val}
}

// A valueCtx carries a key-value pair. It implements Value for that key and
// delegates all other calls to the embedded Context.
// [Min] 以父 context 为基础，添加 key，val
type valueCtx struct {
	Context
	key, val interface{}
}

func (c *valueCtx) String() string {
	return fmt.Sprintf("%v.WithValue(%#v, %#v)", c.Context, c.key, c.val)
}

// [Min] 递归查找 context 中key 对应的 value，直到找到，或者碰到非 valueCtx 返回 nil 为止
func (c *valueCtx) Value(key interface{}) interface{} {
	if c.key == key {
		return c.val
	}
	return c.Context.Value(key)
}
