package tlv

import (
	"encoding/json"
	"testing"
)

//go test -bench=. -benchmem -run=none

type Strings struct {
	// Strs    []string `tlv:"strs"`
	// Byte    byte     `tlv:"byte"`
	Float32  float32   `tlv:"float32"`
	Float64  float64   `tlv:"float64"`
	Slice16  []int16   `tlv:"slice16"`
	Slice32  []int32   `tlv:"slice32"`
	Slice64  []int64   `tlv:"slice64"`
	Arraya   []string  `tlv:"arraya"`
	Arrayb   []byte    `tlv:"arrayb"`
	Slice    []int     `tlv:"slice"`
	FLoats   []float32 `tlv:"floats"`
	Float64s []float64 `tlv:"float64s"`
}

func TestMarshal(t *testing.T) {
	// 数组
	// arraya := []string{"a", "b", "c"}
	// b, err := Marshal(arraya)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// t.Log(b)
	// arraya2 := []string{}
	// uerr := Unmarshal(b, &arraya2)
	// if uerr != nil {
	// 	t.Fatal(uerr)
	// }
	// t.Log(arraya2)
	// map
	map1 := map[string]int{"a": 1, "b": 2, "c": 3}
	b, err := Marshal(map1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(b)
	m := map[string]int{}
	merr := Unmarshal(b, &m)
	if merr != nil {
		t.Fatal(merr)
	}
	t.Log(m)
}

func BenchmarkMarshal200(b *testing.B) {
	a := NewMockA()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame, err := Marshal(a)
		if err != nil {
			b.Fatal(err)
		}
		_ = frame
	}
	b.StopTimer()
}

func BenchmarkJson200(b *testing.B) {
	a := NewMockA()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		js, err := json.Marshal(a)
		if err != nil {
			b.Fatal(err)
		}
		_ = js
	}
	b.StopTimer()
}

// 极限
// BenchmarkMarshal200-6           18679048                64.35 ns/op            0 B/op          0 allocs/op
// go test -bench=. -benchmem -run=none
// 对比结果 2025/12/27(第一次尝试)
// goos: windows
// goarch: amd64
// pkg: github.com/w6xian/sloth/decoder/tlv
// cpu: Intel(R) Core(TM) i5-9400F CPU @ 2.90GHz
// BenchmarkMarshal200-6              94322             12607 ns/op            6778 B/op        308 allocs/op
// BenchmarkJson200-6                505194              2281 ns/op             648 B/op          8 allocs/op
//									执行总次数             每次执行耗时(ns)        内存分配次数        内存分配字节数
// 调优相关记录
// 第一次优化
// BenchmarkMarshal200-6              60546             20156 ns/op            1936 B/op        102 allocs/op
// BenchmarkJson200-6                515382              2293 ns/op             648 B/op          8 allocs/op
// 操作：加pool读取byte，
// 内存分配次数减少到1/3次, 内存分配字节数减少到1/3次.
// 执行耗时增加了1倍，总次数减少了1/3次.
// 时间换空间（失败的优化）
// BenchmarkMarshal200-6              91135             12639 ns/op            2161 B/op        110 allocs/op
// BenchmarkJson200-6                531483              2300 ns/op             648 B/op          8 allocs/op
//
// BenchmarkMarshal200-6              92630             12734 ns/op            4128 B/op        100 allocs/op
//
// BenchmarkMarshal200-6             108876             10809 ns/op            4259 B/op        117 allocs/op
// 用buffer优化后
// BenchmarkMarshal200-6             119476              9922 ns/op            4258 B/op        117 allocs/op
// 顺序写buffer后
// 对比结果 2025/12/27(第二次尝试)
// 执行性能提升了3/5（0.6倍）
// BenchmarkMarshal200-6             152913              7821 ns/op            2625 B/op         45 allocs/op
// BenchmarkJson200-6                527168              2286 ns/op             648 B/op          8 allocs/op
