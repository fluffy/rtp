package rtp

import (
//"errors"
//	"fmt"
)

type RTPSession struct {
	extNameMap map[string]int
}

func (s *RTPSession) AddExtMap(num int, name string) {
	s.extNameMap[name] = num
}

func NewRTPSession() *RTPSession {
	s := new(RTPSession)
	s.extNameMap = make(map[string]int)

	return s
}
