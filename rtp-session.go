package rtp

import (
	"errors"
	//	"fmt"
)

type RTPSession struct {
	extNameMap map[string]int
}

func (s *RTPSession) SetExtMap(num int, name string) error {

	if num > 14 {
		return errors.New("rtp SetExtMap 2 byte headers are not implemented")
	}

	s.extNameMap[name] = num

	return nil
}

func NewRTPSession() *RTPSession {
	s := new(RTPSession)
	s.extNameMap = make(map[string]int)

	return s
}
