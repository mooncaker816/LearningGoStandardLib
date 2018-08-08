// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sync

import (
	"sync/atomic"
	"unsafe"
)

// Map is like a Go map[interface{}]interface{} but is safe for concurrent use
// by multiple goroutines without additional locking or coordination.
// Loads, stores, and deletes run in amortized constant time.
//
// The Map type is specialized. Most code should use a plain Go map instead,
// with separate locking or coordination, for better type safety and to make it
// easier to maintain other invariants along with the map content.
//
// The Map type is optimized for two common use cases: (1) when the entry for a given
// key is only ever written once but read many times, as in caches that only grow,
// or (2) when multiple goroutines read, write, and overwrite entries for disjoint
// sets of keys. In these two cases, use of a Map may significantly reduce lock
// contention compared to a Go map paired with a separate Mutex or RWMutex.
//
// The zero Map is empty and ready for use. A Map must not be copied after first use.
/* [Min]

1. 外界对 dirty 层的读写会加锁，对纯 read 层不用，因为是原子操作。
2. read 层的 key 可以看成是一个不变的集合（不 promote 的前提），
只要读写的 key 不超出该集合，就可以只在该层进行，不会涉及 dirty，也就增大了效率
3. 涉及 read 层和 dirty 层的交互检查读写时，仍会上锁
4. sync.Map 更适合读大于写的场景，这里的读是指 key 不经常新增的情况

存储数据
1. 如果 key 在 read 中（非标记为删除），更新到 read 中，
由于 entry 中存的是指针，所以更新 read 也更新了 dirty 中对应的 key 的 entry
（dirty中存储的是新增的 key 以及 read 中非删除的拷贝）
2. 如果 key 不在 read 中，且有可能在 dirty 中（ read 不完全，dirty 中含有 read 中没有的数据），加锁，
3. 再次尝试加载 read，（为了确保 read 的数据在这一段时间没有被改变），继续检查是否在 read 中
4. 如果 key 存在，可能是标记为删除的 entry，也可能是刚从 dirty promote 上来的数据
	4.1 如果是标记为删除的数据，那么此时的 dirty 中可能有该 key 对的数据，我们需要同时修改 read 和 read 为新的数据
	4.2 如果是刚从 dirty promote 上来的数据，那么必然不是标记为删除的数据，我们只需要修改 read 为新数据即可
5. 如果 key 不在 read 中，检查 key 是否在 dirty 中存在
	5.1 如果 key 存在在 dirty 中，更新 dirty
	5.2 如果 key 不存在 dirty 中，新增到 dirty ，
		5.2.1 如果该 key 是第一个新增到 dirty 中的 key 时（使得 read 变成不完整），
		首先会把当前 read 中所有非删除 entry 复制到 dirty 中，这样确保 read 的非删除 entry 至少是 dirty 一个子集
		且 read 更新数据时，dirty 中也会同步更新，最后当 dirty promote 到 read 时，不会丢失数据
		由于复制的都是非删除 entry，所以等到下一次 promote 的时候，会正式删除那些当前在 read 中标记为删除的 entry
		5.2.2 如果不是第一个新增 key，那么直接添加到 dirty 中即可

读取数据
1. 如果 key 在 read 中（非标记为删除），直接读取即可
2. 如果 key 不在 read 或者为删除 entry，那么加锁
3. 再次加载 read，并检查是否在 read 中，且为非删除 entry，如果是，直接读取即可
4. 再次在 read 中查找失败，尝试从 dirty 中读取，并且 miss 次数加1
5. 如果 miss 次数达到了 dirty 的长度，将 dirty promote 到 read，
同时置 dirty 为 nil，misses 为 0，新的 read.amended 为 false

删除数据
1. 优先从 read 中查找，如果有就标记为删除，dirty 也会同步为删除（指针的关系），
所以对于有些数据来说真正的物理删除还需要两次 promote，
第一次 promote 从 dirty 中物理删除，第二次 promote 从 read 中物理删除
2. 如果不在 read 中，直接从 dirty 中删除
*/
type Map struct {
	mu Mutex

	// read contains the portion of the map's contents that are safe for
	// concurrent access (with or without mu held).
	//
	// The read field itself is always safe to load, but must only be stored with
	// mu held.
	//
	// Entries stored in read may be updated concurrently without mu, but updating
	// a previously-expunged entry requires that the entry be copied to the dirty
	// map and unexpunged with mu held.
	read atomic.Value // readOnly

	// dirty contains the portion of the map's contents that require mu to be
	// held. To ensure that the dirty map can be promoted to the read map quickly,
	// it also includes all of the non-expunged entries in the read map.
	//
	// Expunged entries are not stored in the dirty map. An expunged entry in the
	// clean map must be unexpunged and added to the dirty map before a new value
	// can be stored to it.
	//
	// If the dirty map is nil, the next write to the map will initialize it by
	// making a shallow copy of the clean map, omitting stale entries.
	dirty map[interface{}]*entry

	// misses counts the number of loads since the read map was last updated that
	// needed to lock mu to determine whether the key was present.
	//
	// Once enough misses have occurred to cover the cost of copying the dirty
	// map, the dirty map will be promoted to the read map (in the unamended
	// state) and the next store to the map will make a new dirty copy.
	misses int
}

// readOnly is an immutable struct stored atomically in the Map.read field.
type readOnly struct {
	m map[interface{}]*entry
	// [Min] dirty 中有 m 没有的数据时，为真
	amended bool // true if the dirty map contains some key not in m.
}

// expunged is an arbitrary pointer that marks entries which have been deleted
// from the dirty map.
var expunged = unsafe.Pointer(new(interface{}))

// An entry is a slot in the map corresponding to a particular key.
type entry struct {
	// p points to the interface{} value stored for the entry.
	//
	// If p == nil, the entry has been deleted and m.dirty == nil.
	//
	// If p == expunged, the entry has been deleted, m.dirty != nil, and the entry
	// is missing from m.dirty.
	//
	// Otherwise, the entry is valid and recorded in m.read.m[key] and, if m.dirty
	// != nil, in m.dirty[key].
	//
	// An entry can be deleted by atomic replacement with nil: when m.dirty is
	// next created, it will atomically replace nil with expunged and leave
	// m.dirty[key] unset.
	//
	// An entry's associated value can be updated by atomic replacement, provided
	// p != expunged. If p == expunged, an entry's associated value can be updated
	// only after first setting m.dirty[key] = e so that lookups using the dirty
	// map find the entry.
	p unsafe.Pointer // *interface{}
}

func newEntry(i interface{}) *entry {
	return &entry{p: unsafe.Pointer(&i)}
}

// Load returns the value stored in the map for a key, or nil if no
// value is present.
// The ok result indicates whether value was found in the map.
// [Min] 根据 key 来读取 Map 中的数据
func (m *Map) Load(key interface{}) (value interface{}, ok bool) {
	read, _ := m.read.Load().(readOnly)
	e, ok := read.m[key]
	// [Min] 如果 m 中没有，且 dirty 中有 m 没有的数据，需要尝试从 dirty 中查找
	if !ok && read.amended {
		m.mu.Lock()
		// Avoid reporting a spurious miss if m.dirty got promoted while we were
		// blocked on m.mu. (If further loads of the same key will not miss, it's
		// not worth copying the dirty map for this key.)
		// [Min] 再次从 m 中查找一次，防止 dirty 在我们第一次查找失败后升级为 read，这样 m 就有可能找到目标
		// [Min] 这里需要对 read 也加锁
		read, _ = m.read.Load().(readOnly)
		e, ok = read.m[key]
		// [Min] 如果还是找不到，且 dirty 有 m 没有的数据，再从 dirty 中查找
		// [Min] 无论 dirty 中是否存在，都将misses 加1，如果 miss 次数达到了 dirty 的长度，
		// [Min] promote dirty 到 read，重置 dirty 和 misses
		if !ok && read.amended {
			e, ok = m.dirty[key]
			// Regardless of whether the entry was present, record a miss: this key
			// will take the slow path until the dirty map is promoted to the read
			// map.
			m.missLocked()
		}
		m.mu.Unlock()
	}
	// [Min] read，dirty 都没有，返回 nil，false
	if !ok {
		return nil, false
	}
	// [Min] 在 read 或 dirty 中找到了，调用 load 检查是否是 nil 或 标记为删除的 entry
	// [Min] 按需返回
	return e.load()
}

// [Min] 检查 entry 是否为 nil 或者是否已标记为删除
// [Min] 如果是，返回 nil，false
// [Min] 如果不是，返回对应的值
func (e *entry) load() (value interface{}, ok bool) {
	p := atomic.LoadPointer(&e.p)
	if p == nil || p == expunged {
		return nil, false
	}
	// [Min] p 是一个指向 interface{} 的指针类型的指针
	return *(*interface{})(p), true
}

// Store sets the value for a key.
// [Min] 存储 key-value
func (m *Map) Store(key, value interface{}) {
	// [Min] 首先从 read 中读取 key，如果存在尝试更新，只要 read 中不是标记为删除，都能更新成功
	// [Min] 更新成功直接返回
	read, _ := m.read.Load().(readOnly)
	if e, ok := read.m[key]; ok && e.tryStore(&value) {
		return
	}

	// [Min] read 中没有或者 read 中标记为删除
	m.mu.Lock()
	read, _ = m.read.Load().(readOnly)
	// [Min] 加锁后二次判断 read 中是否有 key，有则说明该 key 对应的 entry 之前已经标记为需要被删除
	if e, ok := read.m[key]; ok {
		// [Min] 取消 e 的删除标记,并更新为对应的 value 值
		if e.unexpungeLocked() {
			// The entry was previously expunged, which implies that there is a
			// non-nil dirty map and this entry is not in it.
			// [Min] 在 dirty 中 更新对应的 key 为 e
			m.dirty[key] = e
		}
		e.storeLocked(&value)
	} else if e, ok := m.dirty[key]; ok {
		// [Min] read 中没有，但 dirty 中有，更新 dirty 中的数据
		e.storeLocked(&value)
	} else {
		// [Min] dirty，read 都没有，且 dirty 中的数据都能在 read 中找到时，需要在 dirty 中存入该 entry
		// [Min] 如果存入之前 dirty 为 nil，会先将 read 中的非删除数据复制到 dirty 中，再添加新的 entry
		// [Min] 这一步相当于同时做了添加和正式删除 entry 的工作，因为 dirty 总会 promote 到 read 的
		// [Min] 如果 dirty 不为 nil，直接存入
		// [Min] 同时我们会更新 read 的 amended 为 true，因为添加新的 entry 到 dirty 后，dirty 就有了 read 没有的数据了
		if !read.amended {
			// We're adding the first new key to the dirty map.
			// Make sure it is allocated and mark the read-only map as incomplete.
			m.dirtyLocked()
			m.read.Store(readOnly{m: read.m, amended: true})
		}
		m.dirty[key] = newEntry(value)
	}
	m.mu.Unlock()
}

// tryStore stores a value if the entry has not been expunged.
//
// If the entry is expunged, tryStore returns false and leaves the entry
// unchanged.
// [Min] 尝试在 read 中以 i 覆盖 e，如果返回 false，那么说明 e 需要被删除
func (e *entry) tryStore(i *interface{}) bool {
	// [Min] 判断 e 是否已经标记为删除，如果是，则不用在 read 中对其进行覆盖
	p := atomic.LoadPointer(&e.p) // [Min] ①
	if p == expunged {
		return false
	}
	// [Min] e 没有标记为删除
	for {
		// [Min] 如果 e.p 在①之后没有被修改，那么将 i 赋给 e.p
		if atomic.CompareAndSwapPointer(&e.p, p, unsafe.Pointer(i)) {
			return true
		}
		// [Min] 如果 e.p 在①之后被修改了（read 可能刚从 dirty 中 promote 过来），我们需要重新判断修改后的 e 是否应该删除
		// [Min] 如果是，我们也不更新，否则继续尝试将 i 赋给 e.p
		p = atomic.LoadPointer(&e.p)
		if p == expunged {
			return false
		}
	}
}

// unexpungeLocked ensures that the entry is not marked as expunged.
//
// If the entry was previously expunged, it must be added to the dirty map
// before m.mu is unlocked.
// [Min] 确保 e 不是标记为删除
func (e *entry) unexpungeLocked() (wasExpunged bool) {
	return atomic.CompareAndSwapPointer(&e.p, expunged, nil)
}

// storeLocked unconditionally stores a value to the entry.
//
// The entry must be known not to be expunged.
// [Min] 将 i 更新到 e.p
func (e *entry) storeLocked(i *interface{}) {
	atomic.StorePointer(&e.p, unsafe.Pointer(i))
}

// LoadOrStore returns the existing value for the key if present.
// Otherwise, it stores and returns the given value.
// The loaded result is true if the value was loaded, false if stored.
// [Min] 如果 key 存在，那么久返回 key 的值，如果 key 不存在，就存储
func (m *Map) LoadOrStore(key, value interface{}) (actual interface{}, loaded bool) {
	// Avoid locking if it's a clean hit.
	read, _ := m.read.Load().(readOnly)
	if e, ok := read.m[key]; ok {
		actual, loaded, ok := e.tryLoadOrStore(value)
		if ok {
			return actual, loaded
		}
	}

	m.mu.Lock()
	read, _ = m.read.Load().(readOnly)
	if e, ok := read.m[key]; ok {
		if e.unexpungeLocked() {
			m.dirty[key] = e
		}
		actual, loaded, _ = e.tryLoadOrStore(value)
	} else if e, ok := m.dirty[key]; ok {
		actual, loaded, _ = e.tryLoadOrStore(value)
		m.missLocked()
	} else {
		if !read.amended {
			// We're adding the first new key to the dirty map.
			// Make sure it is allocated and mark the read-only map as incomplete.
			m.dirtyLocked()
			m.read.Store(readOnly{m: read.m, amended: true})
		}
		m.dirty[key] = newEntry(value)
		actual, loaded = value, false
	}
	m.mu.Unlock()

	return actual, loaded
}

// tryLoadOrStore atomically loads or stores a value if the entry is not
// expunged.
//
// If the entry is expunged, tryLoadOrStore leaves the entry unchanged and
// returns with ok==false.
func (e *entry) tryLoadOrStore(i interface{}) (actual interface{}, loaded, ok bool) {
	p := atomic.LoadPointer(&e.p)
	if p == expunged {
		return nil, false, false
	}
	if p != nil {
		return *(*interface{})(p), true, true
	}

	// Copy the interface after the first load to make this method more amenable
	// to escape analysis: if we hit the "load" path or the entry is expunged, we
	// shouldn't bother heap-allocating.
	ic := i
	for {
		if atomic.CompareAndSwapPointer(&e.p, nil, unsafe.Pointer(&ic)) {
			return i, false, true
		}
		p = atomic.LoadPointer(&e.p)
		if p == expunged {
			return nil, false, false
		}
		if p != nil {
			return *(*interface{})(p), true, true
		}
	}
}

// Delete deletes the value for a key.
// [Min] 删除 key
func (m *Map) Delete(key interface{}) {
	read, _ := m.read.Load().(readOnly)
	e, ok := read.m[key]
	// [Min] read 中没有，且 dirty 中可能有
	if !ok && read.amended {
		// [Min] 上锁
		m.mu.Lock()
		// [Min] 再次检查 read
		read, _ = m.read.Load().(readOnly)
		e, ok = read.m[key]
		// [Min] 还是没有，且 dirty 可能有
		if !ok && read.amended {
			// [Min] 从 dirty 中删除即可
			delete(m.dirty, key)
		}
		m.mu.Unlock()
	}
	// [Min] 如果在 read 中存在，
	// [Min] 如果已经标记为删除或为 nil，不用额外操作
	// [Min] 如果有值，则将 e.p 置为 nil
	if ok {
		e.delete()
	}
}

func (e *entry) delete() (hadValue bool) {
	for {
		p := atomic.LoadPointer(&e.p)
		if p == nil || p == expunged {
			return false
		}
		if atomic.CompareAndSwapPointer(&e.p, p, nil) {
			return true
		}
	}
}

// Range calls f sequentially for each key and value present in the map.
// If f returns false, range stops the iteration.
//
// Range does not necessarily correspond to any consistent snapshot of the Map's
// contents: no key will be visited more than once, but if the value for any key
// is stored or deleted concurrently, Range may reflect any mapping for that key
// from any point during the Range call.
//
// Range may be O(N) with the number of elements in the map even if f returns
// false after a constant number of calls.
func (m *Map) Range(f func(key, value interface{}) bool) {
	// We need to be able to iterate over all of the keys that were already
	// present at the start of the call to Range.
	// If read.amended is false, then read.m satisfies that property without
	// requiring us to hold m.mu for a long time.
	read, _ := m.read.Load().(readOnly)
	if read.amended {
		// m.dirty contains keys not in read.m. Fortunately, Range is already O(N)
		// (assuming the caller does not break out early), so a call to Range
		// amortizes an entire copy of the map: we can promote the dirty copy
		// immediately!
		m.mu.Lock()
		read, _ = m.read.Load().(readOnly)
		if read.amended {
			read = readOnly{m: m.dirty}
			m.read.Store(read)
			m.dirty = nil
			m.misses = 0
		}
		m.mu.Unlock()
	}

	for k, e := range read.m {
		v, ok := e.load()
		if !ok {
			continue
		}
		if !f(k, v) {
			break
		}
	}
}

// [Min] misses 加1，如果 misses 达到了 dirty 的长度，那么就将 dirty 赋给 read
// [Min] dirty 置为 nil，misses 记为 0
func (m *Map) missLocked() {
	m.misses++
	if m.misses < len(m.dirty) {
		return
	}
	m.read.Store(readOnly{m: m.dirty})
	m.dirty = nil
	m.misses = 0
}

// [Min] 如果 dirty 不为 nil，直接返回
// [Min] 否则根据当前 read 来重构 dirty，将 read 中不是删除的 entry 复制到 dirty 中
func (m *Map) dirtyLocked() {
	if m.dirty != nil {
		return
	}

	// [Min] 获取当前 read
	read, _ := m.read.Load().(readOnly)
	m.dirty = make(map[interface{}]*entry, len(read.m))
	for k, e := range read.m {
		if !e.tryExpungeLocked() {
			m.dirty[k] = e
		}
	}
}

// [Min] e 是否为标记为删除的 entry
func (e *entry) tryExpungeLocked() (isExpunged bool) {
	p := atomic.LoadPointer(&e.p)
	for p == nil {
		if atomic.CompareAndSwapPointer(&e.p, nil, expunged) {
			return true
		}
		p = atomic.LoadPointer(&e.p)
	}
	return p == expunged
}
