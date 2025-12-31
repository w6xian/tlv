package tlv

import (
	"bytes"
	"sync"
)

type encodeState struct {
	bytes.Buffer // accumulated output
	ptrLevel     uint
	LengthSize   int
}

var encodeStatePool sync.Pool

func newEncodeState() *encodeState {
	if v := encodeStatePool.Get(); v != nil {
		e := v.(*encodeState)
		e.Reset()
		e.ptrLevel = 0
		return e
	}
	return &encodeState{}
}
