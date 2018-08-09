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

type CipherID uint16

type Ssrc uint32

const (
	// From https://www.iana.org/assignments/srtp-protection/srtp-protection.xhtml
	NONE                                     CipherID = 0x0000
	SRTP_AEAD_AES_128_GCM                    CipherID = 0x0007
	SRTP_AEAD_AES_256_GCM                    CipherID = 0x0008
	DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM CipherID = 0x0009
	DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM CipherID = 0x000a
)

type RTPSession struct {
	extNameMap map[string]int
	key        []byte
	salt       []byte
	seq        uint16
	roc        uint32
	rtcpKey    []byte
	rtcpSalt   []byte

	cipher CipherID
	useEKT bool
	rewriteSeq bool
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
			ektLen += 2 + 2 + 1 // SPI + len + type
		} else {
			// bad EKT
			return nil, errors.New("rtp: invalid EKT field")
		}
		if ektLen >= len(packetData) {
			// bad EKT
			return nil, errors.New("rtp: invalid EKT field - too big")
		}

		p.buffer = packetData[0 : len(packetData)-ektLen]
		p.ekt = packetData[len(packetData)-ektLen : len(packetData)]
	}

	if s.cipher != NONE {
		err := p.DecryptGCM(s.roc, s.key, s.salt)
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

func (s *RTPSession) DecodeRTCP(packetData []byte) (*RTCPCompoundPacket, error) {
	p, err := NewSRTCPPacket(packetData)
	if err != nil {
		return nil, err
	}

	if s.cipher != NONE {
		err = p.DecryptGCM(s.rtcpKey, s.rtcpSalt)
		if err != nil {
			return nil, err
		}

		return p, nil
	}

	return nil, errors.New("rtcp: cipher algorithm not supported")
}

func (s *RTPSession) Encode(p *RTPPacket) ([]byte, error) {
	if s.cipher != NONE {
		// Form the OHB with old seq
		origPt := p.GetPT()
		origSeq := p.GetSeq()
		origMarker := p.GetMarker()

		// Set the seq number
		if (  s.rewriteSeq ) {
			err := p.SetSeq(s.seq)
			if err != nil {
				return nil, err
			}
		}

		err := p.SetOHB(origPt, origSeq, origMarker)
		if err != nil {
			return nil, err
		}

		// encrypt
		err = p.EncryptGCM(s.roc, s.key, s.salt)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("rtp: cipher algorithm not supported")
	}

	if (  s.rewriteSeq ) {
		// increment seq
		s.seq++
		if s.seq == 0 {
			s.roc++
		}
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

func (s* RTPSession) EncodeRTCP(p* RTCPCompoundPacket) ([]byte, error) {
	if s.cipher != NONE {
		err := p.EncryptGCM(s.rtcpKey, s.rtcpSalt)
		if err != nil {
			return nil, err
		}

		return p.GetBuffer(), nil
	} else {
		return nil, errors.New("rtp: cipher algorithm not supported")
	}
}

func (s *RTPSession) NewRtcpRR() (*RTPPacket, error) {
	return nil, nil
}

func (s *RTPSession) SetSRTP(cipher CipherID, useEKT bool, masterKey, masterSalt []byte) error {
	kdf, err := NewKDF(masterKey, masterSalt)
	if err != nil {
		return err
	}

	rtpKey, rtpSalt, rtcpKey, rtcpSalt, err := kdf.DeriveForStream(cipher)
	if err != nil {
		return err
	}

	fmt.Printf("SRTP encryption key: %x\n", rtpKey)

	s.key = rtpKey
	s.salt = rtpSalt
	s.rtcpKey = rtcpKey
	s.rtcpSalt = rtcpSalt
	s.cipher = cipher
	s.useEKT = useEKT
	return nil
}

func (s *RTPSession) SetExtMap(num int, name string) error {

	if num > 14 {
		return errors.New("rtp SetExtMap 2 byte headers are not implemented")
	}

	s.extNameMap[name] = num

	return nil
}

func NewRTPSession( rewriteSeq bool ) *RTPSession {
	s := new(RTPSession)
	s.extNameMap = make(map[string]int)

	randBytes := make([]byte, 2)
	_, err := rand.Read(randBytes)
	if err != nil {
		fmt.Printf("rtp:NewRTPSession got %s\n", err.Error())
		return nil
	}
	s.seq = binary.BigEndian.Uint16(randBytes) & 0x7FFF
	s.roc = 0

	s.rewriteSeq = rewriteSeq;

	return s
}
