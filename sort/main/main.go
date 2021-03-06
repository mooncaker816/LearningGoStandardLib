package main

import (
	"fmt"
	"sort"
)

type record struct {
	name                string
	ch, math, en, total int
}

type lessFn func(r1, r2 *record) int // -1,0,1

type recordSorter struct {
	recs []record
	less []lessFn
}

func (r *recordSorter) Len() int {
	return len(r.recs)
}

func (r *recordSorter) Swap(i, j int) {
	r.recs[i], r.recs[j] = r.recs[j], r.recs[i]
}

func (r *recordSorter) Less(i, j int) bool {
	vi, vj := r.recs[i], r.recs[j]
	for _, less := range r.less {
		switch less(&vi, &vj) {
		case -1:
			return true
		case 1:
			return false
		}
		// vi = vj, check next less func
	}
	return true
}

func (r *recordSorter) Sort(recs []record) {
	r.recs = recs
	sort.Sort(r)
	// fmt.Println(r.recs)
}

var tt = []record{
	{"张三", 100, 90, 80, 270},
	{"李四", 80, 90, 100, 270},
	{"王五", 90, 90, 90, 270},
	{"赵六", 95, 90, 95, 280},
	{"钱七", 85, 95, 90, 270},
}

func OrderBy(less ...lessFn) *recordSorter {
	return &recordSorter{
		less: less,
	}
}

func main() {
	desBych := func(r1, r2 *record) int {
		if r1.ch > r2.ch {
			return -1
		}
		if r1.ch < r2.ch {
			return 1
		}
		return 0
	}
	incBych := func(r1, r2 *record) int {
		if r1.ch > r2.ch {
			return 1
		}
		if r1.ch < r2.ch {
			return -1
		}
		return 0
	}
	_ = incBych
	desBymath := func(r1, r2 *record) int {
		if r1.math > r2.math {
			return -1
		}
		if r1.math < r2.math {
			return 1
		}
		return 0
	}
	desByen := func(r1, r2 *record) int {
		if r1.en > r2.en {
			return -1
		}
		if r1.en < r2.en {
			return 1
		}
		return 0
	}
	desBytotal := func(r1, r2 *record) int {
		if r1.total > r2.total {
			return -1
		}
		if r1.total < r2.total {
			return 1
		}
		return 0
	}
	OrderBy(desBytotal, desBych, desBymath, desByen).Sort(tt)
	fmt.Println("sortedBy total,ch,math,en:")
	for _, v := range tt {
		fmt.Printf("%s %d %d %d %d\n", v.name, v.total, v.ch, v.math, v.en)
	}
	OrderBy(desBytotal, desBymath, desByen, desBych).Sort(tt)
	fmt.Println("sortedBy total,math,en,ch:")
	for _, v := range tt {
		fmt.Printf("%s %d %d %d %d\n", v.name, v.total, v.math, v.en, v.ch)
	}
	OrderBy(desBytotal, desByen, desBych, desBymath).Sort(tt)
	fmt.Println("sortedBy total,en,ch,math:")
	for _, v := range tt {
		fmt.Printf("%s %d %d %d %d\n", v.name, v.total, v.en, v.ch, v.math)
	}
}
