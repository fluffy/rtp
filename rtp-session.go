package rtp

/*
EKT defined in https://tools.ietf.org/html/draft-ietf-perc-srtp-ekt-diet-07

SRTP Profiles are at https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml

Currently only support DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM  in half mode with EKT
*/

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

type CipherID int

const (
	// From https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
	//DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM = 9
	HALF_AEAD_AES_128_GCM_AEAD_AES_128_GCM CipherID = -9
)

type RTPSession struct {
	extNameMap map[string]int
	kdf        *KDF
	seq        uint16
	roc        uint32

	cipherID CipherID
	useEKT   bool
}

func (s *RTPSession) SetCipher(cipher CipherID, useEKT bool) error {

	s.useEKT = useEKT
	s.cipherID = cipher

	return nil
}

func (s *RTPSession) Decode(packetData []byte) (*RTPPacket, error) {

	p := new(RTPPacket)

	if s.useEKT {
		ektCmd := packetData[len(packetData)-1]
		ektLen := 0
		if ektCmd == 0 {
			ektLen = 1
		} else if ektCmd == 0x02 {
			ektLen = int(binary.BigEndian.Uint16(packetData[len(packetData)-3:]))
		} else {
			// bad EKT
			return nil, errors.New("rtp: invalid EKT field")
		}

		p.buffer = packetData[0 : len(packetData)-ektLen]
		p.ekt = packetData[len(packetData)-ektLen : len(packetData)]
	}

	seq := p.GetSeq()

	if s.cipherID == HALF_AEAD_AES_128_GCM_AEAD_AES_128_GCM {
		cipherKeySize := 128 / 8
		cipherKeyEnc := s.kdf.Derive(Ke, uint64(s.roc), seq, cipherKeySize)
		//cipherKeyAuth := s.kdf.Derive(Ka, s.roc, s.seq, cipherKeySize) // not used for GCM
		cipherSalt := s.kdf.Derive(Ks, uint64(s.roc), seq, cipherKeySize)

		err := p.DecryptGCM(s.roc, cipherKeyEnc, cipherSalt)
		if err != nil {
			return nil, err
		}

		// remove the OHB if double RTP ( but not RTCP )
		ohbLen := p.GetOHBLen()
		p.buffer = p.buffer[0 : len(p.buffer)-ohbLen]
	} else {
		return nil, errors.New("rtp: cipher algorithm not supported")
	}

	return p, nil
}

func (s *RTPSession) Encode(p *RTPPacket) ([]byte, error) {

	if s.cipherID == HALF_AEAD_AES_128_GCM_AEAD_AES_128_GCM {

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
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("rtp: cipher algorithm not supported")
	}

	// increment seq
	s.seq++
	if s.seq == 0 {
		s.roc++
	}

	if s.useEKT {
		// add back EKT
		rtpLen := len(p.buffer)
		ektLen := len(p.ekt)

		if rtpLen+ektLen > cap(p.buffer) {
			return nil, errors.New("rtp: EKT too large to fit in packet MTU")
		}
		p.buffer = p.buffer[0 : rtpLen+ektLen]
		copy(p.buffer[rtpLen:rtpLen+ektLen], p.ekt)
	}

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
