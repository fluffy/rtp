package rtp

import (
	"errors"
	//	"fmt"
)

type RTPSession struct {
	extNameMap map[string]int
	kdf *KDF
	seq uint16
	roc uint32
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

func (s *RTPSession) SetSRTPKey(masterKey []byte, masterSalt []byte)  error {

	var err error
	
	s.kdf,err = NewKDF( masterKey, masterSalt )
	if ( err != nil ) {
		return err
	}
	
	s.seq = 2345 ; // TODO - fill random number
	s.roc = 0
	
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
	s.kdf = nil;
	
	return s
}
