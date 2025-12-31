package main

import (
	"encoding/json"
	"fmt"

	"github.com/w6xian/tlv"
)

func main() {
	// 测试
	strs := A{
		Strs: []string{"a", "b", "c"},
	}
	b, err := tlv.JsonEnpack(strs)
	if err != nil {
		panic(err)
	}
	fmt.Println(b)
	// 转成 struct
	jb, err := tlv.JsonUnpack(b)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(jb))
	// 转成 struct
	var strs2 A
	err = json.Unmarshal(jb, &strs2)
	if err != nil {
		panic(err)
	}
	fmt.Println(strs2)
	fmt.Println("-------")
	frame := tlv.Serialize(strs)
	fmt.Println(frame)
	data, err := tlv.NewFromFrame(frame)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(data.Value())
}

type A struct {
	Strs []string `json:"strs"`
}
