package rtp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestEncode(t *testing.T) {

	s := NewRTPSession( true )

	cipher := SRTP_AEAD_AES_128_GCM
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
	err := s.SetSRTP(cipher, true, key, salt)
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

	golden, _ := hex.DecodeString("8008002a000000210000002c520253e5c9581b3035417389cedb3889a5cba91b25e94500")
	if !bytes.Equal(data, golden) {
		t.Logf("golden: %x", golden)
		t.Logf("  data: %x", data)
		t.Fatalf("rtp sestion encoding failed")
	}
}

func TestDecode(t *testing.T) {
	data, _ := hex.DecodeString("8008002a000000210000002c520253e5c904fd04ac02aea781b9531c29e45a5fae00")

	s := NewRTPSession( true )

	cipher := SRTP_AEAD_AES_128_GCM
	key := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}
	err := s.SetSRTP(cipher, true, key, salt)
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
