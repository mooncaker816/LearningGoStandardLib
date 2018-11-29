// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package heap provides heap operations for any type that implements
// heap.Interface. A heap is a tree with the property that each node is the
// minimum-valued node in its subtree.
//
// The minimum element in the tree is the root, at index 0.
//
// A heap is a common way to implement a priority queue. To build a priority
// queue, implement the Heap interface with the (negative) priority as the
// ordering for the Less method, so Push adds items while Pop removes the
// highest-priority item from the queue. The Examples include such an
// implementation; the file example_pq_test.go has the complete source.
//
package heap

import "sort"

// The Interface type describes the requirements
// for a type using the routines in this package.
// Any type that implements it may be used as a
// min-heap with the following invariants (established after
// Init has been called or if the data is empty or sorted):
//
//	!h.Less(j, i) for 0 <= i < h.Len() and 2*i+1 <= j <= 2*i+2 and j < h.Len()
//
// Note that Push and Pop in this interface are for package heap's
// implementation to call. To add and remove things from the heap,
// use heap.Push and heap.Pop.
type Interface interface {
	sort.Interface
	Push(x interface{}) // add x as element Len() 添加元素至尾部
	Pop() interface{}   // remove and return element Len() - 1. 从尾部弹出元素
}

// Init establishes the heap invariants required by the other routines in this package.
// Init is idempotent with respect to the heap invariants
// and may be called whenever the heap invariants may have been invalidated.
// Its complexity is O(n) where n = h.Len().
// 初始化堆
func Init(h Interface) {
	// heapify
	n := h.Len()
	// 从 n/2 - 1 开始，依次堆化每一个子堆
	for i := n/2 - 1; i >= 0; i-- {
		down(h, i, n)
	}
}

// Push pushes the element x onto the heap. The complexity is
// O(log(n)) where n = h.Len().
// 添加新元素，并堆化
func Push(h Interface, x interface{}) {
	h.Push(x)
	up(h, h.Len()-1)
}

// Pop removes the minimum element (according to Less) from the heap
// and returns it. The complexity is O(log(n)) where n = h.Len().
// It is equivalent to Remove(h, 0).
// 弹出堆顶元素，并维持堆属性
func Pop(h Interface) interface{} {
	// 与末元素交换，然后从顶部往下修复
	n := h.Len() - 1
	h.Swap(0, n)
	down(h, 0, n)
	return h.Pop()
}

// Remove removes the element at index i from the heap.
// The complexity is O(log(n)) where n = h.Len().
// 删除堆中索引为 i 的元素，并维持堆属性
func Remove(h Interface, i int) interface{} {
	// 与末元素交换，然后修复 i
	n := h.Len() - 1
	if n != i {
		h.Swap(i, n)
		if !down(h, i, n) {
			up(h, i)
		}
	}
	return h.Pop()
}

// Fix re-establishes the heap ordering after the element at index i has changed its value.
// Changing the value of the element at index i and then calling Fix is equivalent to,
// but less expensive than, calling Remove(h, i) followed by a Push of the new value.
// The complexity is O(log(n)) where n = h.Len().
// 修改索引为 i 的元素的值之后进行的堆化
func Fix(h Interface, i int) {
	// 首先向下堆化，
	// 如果确实发生了交换，说明 i 索引的元素变成了一个比原值大（等）的元素，必然也向上满足原来的堆，完成修复
	// 如果没有发生交换，说明向下仍满足堆，但仍需向上检查
	if !down(h, i, h.Len()) {
		up(h, i)
	}
}

// 向上堆化
func up(h Interface, j int) {
	for {
		// 获取 j 的父节点索引值
		i := (j - 1) / 2 // parent
		// 到顶或满足堆的定义就跳出
		if i == j || !h.Less(j, i) {
			break
		}
		// 交换并继续向上堆化
		h.Swap(i, j)
		j = i
	}
}

// 将以 i0 为根的子堆按堆的大小定义（Less）向下进行堆化，直到满足堆的定义，
// 如果进行了交换，则返回真，否则返回假
func down(h Interface, i0, n int) bool {
	i := i0
	for {
		j1 := 2*i + 1          // i 元素对应的左儿子索引，如果超出了堆的范围则跳出
		if j1 >= n || j1 < 0 { // j1 < 0 after int overflow
			break
		}
		// 按 Less 的定义，选出左儿子和右儿子的最小（大）值的索引
		j := j1 // left child
		if j2 := j1 + 1; j2 < n && h.Less(j2, j1) {
			j = j2 // = 2*i + 2  // right child
		}
		// 如果满足堆的定义，无需后续的交换和向下检查，直接跳出
		if !h.Less(j, i) {
			break
		}
		h.Swap(i, j)
		i = j
	}
	// i>i0 说明进行了交换
	return i > i0
}
