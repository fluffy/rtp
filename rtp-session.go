package rtp

import (
	"errors"
	//	"fmt"
)

type RTPSession struct {
	extNameMap map[string]int
	masterKey []byte
	masterSalt []byte
	kdf KDF
}

func  (s *RTPSession) Decode( packetData []byte ) (*RTPPacket, error) {
	return nil,nil
}

func  (s *RTPSession) Encode( p *RTPPacket ) ([]byte,error) {
	return nil,nil
}

func  (s *RTPSession) NewRtcpRR() (*RTPPacket, error) {
	return nil,nil
}

func (s *RTPSession) SetSRTPKey(masterKey []byte, masterSalt []byte) error {
	return nil
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
