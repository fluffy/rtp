package rtp

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

type RTPSession struct {
	extNameMap map[string]int
	kdf        *KDF
	seq        uint16
	roc        uint32
}

func (s *RTPSession) Decode(packetData []byte) (*RTPPacket, error) {

	// TODO - detect and remove EKT

	p := new(RTPPacket)
	p.buffer = packetData

	cipherKeySize := 128 / 8
	cipherKeyEnc := s.kdf.Derive(Ke, uint64(s.roc), s.seq, cipherKeySize)
	//cipherKeyAuth := s.kdf.Derive(Ka, s.roc, s.seq, cipherKeySize) // not used for GCM
	cipherSalt := s.kdf.Derive(Ks, uint64(s.roc), s.seq, cipherKeySize)

	err := p.DecryptGCM(s.roc, cipherKeyEnc, cipherSalt)
	if err != nil {
		return nil, err
	}

	// remove the OHB if doubele RTP ( but not RTCP )

	return p, nil
}

func (s *RTPSession) Encode(p *RTPPacket) ([]byte, error) {
	// Form the OHB with old seq
	err := p.SetOHB(p.GetPT(), p.GetSeq(), p.GetMaker())
	if err != nil {
		return nil, err
	}

	// Set the seq number
	err = p.SetSeq(s.seq)
	if err != nil {
		return nil, err
	}

	// encrypt
	cipherKeySize := 128 / 8
	cipherKeyEnc := s.kdf.Derive(Ke, uint64(s.roc), s.seq, cipherKeySize)
	//cipherKeyAuth := s.kdf.Derive(Ka, s.roc, s.seq, cipherKeySize) // not used for GCM
	cipherSalt := s.kdf.Derive(Ks, uint64(s.roc), s.seq, cipherKeySize)

	err = p.EncryptGCM(s.roc, cipherKeyEnc, cipherSalt)

	// increment seq
	s.seq++
	if s.seq == 0 {
		s.roc++
	}

	// add back EKT
	// TODO

	return p.buffer, nil
}

func (s *RTPSession) NewRtcpRR() (*RTPPacket, error) {
	return nil, nil
}

func (s *RTPSession) SetSRTPKey(masterKey []byte, masterSalt []byte) error {

	var err error

	s.kdf, err = NewKDF(masterKey, masterSalt)
	if err != nil {
		return err
	}

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
	s.kdf = nil

	randBytes := make([]byte, 2)
	_, err := rand.Read(randBytes)
	if err != nil {
		fmt.Printf("rtp:NewRTPSession got %s\n", err.Error())
		return nil
	}
	s.seq = binary.BigEndian.Uint16(randBytes) & 0x7FFF
	s.roc = 0

	return s
}
