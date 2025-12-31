package tlv

import (
	"encoding/json"
	"testing"
)

func TestMarshalStrings(t *testing.T) {

	strs := NewMockA()
	b, err := JsonEnpack(strs)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(b)
	// 转成 struct
	jb, err := JsonUnpack(b)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(jb))
	// 转成 struct
	var strs2 A
	err = json.Unmarshal(jb, &strs2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(strs2)
}
