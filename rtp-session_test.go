package rtp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEncode(t *testing.T) {

	s := NewRTPSession()
	s.SetCipher(HALF_AEAD_AES_128_GCM_AEAD_AES_128_GCM, true)

	err := s.SetSRTPKey([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14})
	if err != nil {
		t.Errorf(err.Error())
	}

	s.seq = 42 // need non random seq so the test case makes repeatable results

	p := NewRTPPacket([]byte{1, 2, 3, 4}, 8 /*pt*/, 0 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)

	var data []byte
	data, err = s.Encode(p)
	if err != nil {
		t.Errorf(err.Error())
	}

	fmt.Printf("Encode result = 0x%x \n", data)

	golden, _ := hex.DecodeString("8008002a000000210000002c3cff1d72897e475243d2e3c93a648938e0589e2f2b00")
	if !bytes.Equal(data, golden) {
		t.Fatalf("rtp sestion encoding failed")
	}
}

func TestDecode(t *testing.T) {
	data, _ := hex.DecodeString("8008002a000000210000002c3cff1d72897e475243d2e3c93a648938e0589e2f2b00")

	s := NewRTPSession()
	s.SetCipher(HALF_AEAD_AES_128_GCM_AEAD_AES_128_GCM, true)

	err := s.SetSRTPKey([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14})
	if err != nil {
		t.Errorf(err.Error())
	}

	var p *RTPPacket
	p, err = s.Decode(data)
	if err != nil {
		t.Errorf(err.Error())
	} else {
		fmt.Printf("Decoded %s \n ", p.String())
	}

	payload := p.GetPayload()
	if len(payload) != 4 {
		t.Errorf("payload data length is wrong")
	} else if payload[1] != 2 {
		t.Errorf("payload data  is wrong")
	}
}
