// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !compiler_bootstrap go1.8

package sort

import "reflect"

// Slice sorts the provided slice given the provided less function.
//
// The sort is not guaranteed to be stable. For a stable sort, use
// SliceStable.
//
// The function panics if the provided interface is not a slice.
// [Min] 根据 less 函数，对一般切片进行排序
func Slice(slice interface{}, less func(i, j int) bool) {
	rv := reflect.ValueOf(slice)   // 通过反射获取数据的值
	swap := reflect.Swapper(slice) // 通过反射获取适用于该数据类型的 swap 函数
	length := rv.Len()             // 通过反射获取数据长度
	quickSort_func(lessSwap{less, swap}, 0, length, maxDepth(length))
}

// SliceStable sorts the provided slice given the provided less
// function while keeping the original order of equal elements.
//
// The function panics if the provided interface is not a slice.
// [Min] 对一般数据进行稳定排序
func SliceStable(slice interface{}, less func(i, j int) bool) {
	rv := reflect.ValueOf(slice)
	swap := reflect.Swapper(slice)
	stable_func(lessSwap{less, swap}, rv.Len())
}

// SliceIsSorted tests whether a slice is sorted.
//
// The function panics if the provided interface is not a slice.
// [Min] 判断数据是否已排序
func SliceIsSorted(slice interface{}, less func(i, j int) bool) bool {
	rv := reflect.ValueOf(slice)
	n := rv.Len()
	for i := n - 1; i > 0; i-- {
		if less(i, i-1) {
			return false
		}
	}
	return true
}
