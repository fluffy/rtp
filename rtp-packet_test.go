package rtp

import (
	// "bytes"
	"encoding/hex"
	"testing"
)

func TestConstructGet(t *testing.T) {
	p := NewRTPPacket([]byte{1, 2, 3, 4}, 8 /*pt*/, 22 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)

	pad := p.GetPad()
	if pad {
		t.Errorf("Pad is wrong")
	}

	x := p.GetExtBit()
	if x {
		t.Errorf("Extention bit is wrong")
	}

	cc := p.GetCC()
	if cc != 0 {
		t.Errorf("CC is wrong. Got %d ", cc)
	}

	pt := p.GetPT()
	if pt != 8 {
		t.Errorf("PT is wrong. Got %d ", pt)
	}

	seq := p.GetSeq()
	if seq != 22 {
		t.Errorf("Seq is wrong. Got %d ", seq)
	}

	ts := p.GetTimestamp()
	if ts != 33 {
		t.Errorf("TS is wrong. Got %d ", ts)
	}

	ssrc := p.GetSSRC()
	if ssrc != 44 {
		t.Errorf("SSRC is wrong. Got %d ", ssrc)
	}

	csrc := p.GetCSRC()
	if len(csrc) != 0 {
		t.Errorf("CSRC is wrong")
	}

	hdrExtLen := p.GetHdrExtLen()
	if hdrExtLen != 0 {
		t.Errorf("HeaderExt length is wrong")
	}

	extNum, ext := p.GetHdrExt()
	if extNum != 0 {
		t.Errorf("extNum  is wrong")
	}
	if len(ext) != 0 {
		t.Errorf("HeaderExt data length is wrong")
	}

	payload := p.GetPayload()
	if len(payload) != 4 {
		t.Errorf("payload data length is wrong")
	}
	if payload[0] != 1 {
		t.Errorf("payload data  is wrong")
	}

	pSize := len(p.buffer)
	if pSize != 16 {
		t.Errorf("Packet size is wrong. Got %d", pSize)
	}
}

func TestSet(t *testing.T) {
	var err error
	p := NewRTPPacket([]byte{1, 2, 3, 4, 5}, 8 /*pt*/, 22 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)

	err = p.SetMarker(true)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = p.SetPT(9)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = p.SetSeq(122)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = p.SetTimestamp(133)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = p.SetSSRC(144)
	if err != nil {
		t.Errorf(err.Error())
	}

	err = p.SetCSRC([]uint32{66, 67})
	if err != nil {
		t.Errorf(err.Error())
	}

	err = p.SetHdrExt(77, []byte{99, 11, 12, 14})
	if err != nil {
		t.Errorf(err.Error())
	}

	err = p.SetPayload([]byte{200, 11, 12, 13})
	if err != nil {
		t.Errorf(err.Error())
	}

	err = p.SetPadding(48)
	if err != nil {
		t.Errorf(err.Error())
	}

	pad := p.GetPad()
	if pad == false {
		t.Errorf("Pad is wrong")
	}

	x := p.GetExtBit()
	if x == false {
		t.Errorf("Extention bit is wrong")
	}

	cc := p.GetCC()
	if cc != 2 {
		t.Errorf("CC is wrong. Got %d ", cc)
	}

	pt := p.GetPT()
	if pt != 9 {
		t.Errorf("PT is wrong. Got %d ", pt)
	}

	seq := p.GetSeq()
	if seq != 122 {
		t.Errorf("Seq is wrong. Got %d ", seq)
	}

	ts := p.GetTimestamp()
	if ts != 133 {
		t.Errorf("TS is wrong. Got %d ", ts)
	}

	ssrc := p.GetSSRC()
	if ssrc != 144 {
		t.Errorf("SSRC is wrong. Got %d ", ssrc)
	}

	csrc := p.GetCSRC()
	if len(csrc) != 2 {
		t.Errorf("CSRC is wrong")
	} else if csrc[0] != 66 {
		t.Errorf("CSRC is wrong")
	}

	hdrExtLen := p.GetHdrExtLen()
	if hdrExtLen != 8 {
		t.Errorf("HeaderExt length is wrong. Got %d ", hdrExtLen)
	}

	extNum, ext := p.GetHdrExt()
	if extNum != 77 {
		t.Errorf("extNum  is wrong")
	}
	if len(ext) != 4 {
		t.Errorf("HeaderExt data length is wrong")
	} else if ext[0] != 99 {
		t.Errorf("HeaderExt data  is wrong. Got %d", ext[0])
	}

	payload := p.GetPayload()
	if len(payload) != 4 {
		t.Errorf("payload data length is wrong")
	} else if payload[0] != 200 {
		t.Errorf("payload data  is wrong")
	}

	pSize := len(p.buffer)
	if pSize != 48 {
		t.Errorf("Packet size is wrong. Got %d", pSize)
	}
}

func TestOHB(t *testing.T) {
	p := NewRTPPacket([]byte{0xa1, 0xa2, 0xa3, 0xa4}, 2 /*pt*/, 3 /*seq*/, 4 /*ts*/, 5 /*ssrc*/)

	err := p.SetOHB(6, 7, true)
	if err != nil {
		t.Errorf(err.Error())
	}

	pt, seq, m := p.GetOHB()

	if pt != 6 {
		t.Errorf("OHB PT is wrong. Got %d ", pt)
	}
	if seq != 7 {
		t.Errorf("OHB seq is wrong. Got %d ", seq)
	}
	if m != true {
		t.Errorf("OHB m wrong.")
	}
}

// https://tools.ietf.org/html/rfc7714#section-16.1.1
func TestGCM(t *testing.T) {
	plaintextHex := "8040f17b8041f8d35501a0b247616c6c" +
		"696120657374206f6d6e697320646976" +
		"69736120696e20706172746573207472" +
		"6573"
	keyHex := "000102030405060708090a0b0c0d0e0f"
	saltHex := "517569642070726f2071756f"
	ciphertextHex := "8040f17b8041f8d35501a0b2f24de3a3" +
		"fb34de6cacba861c9d7e4bcabe633bd5" +
		"0d294e6f42a5f47a51c7d19b36de3adf" +
		"8833899d7f27beb16a9152cf765ee439" +
		"0cce"

	plaintext, _ := hex.DecodeString(plaintextHex)
	key, _ := hex.DecodeString(keyHex)
	salt, _ := hex.DecodeString(saltHex)
	ciphertext, _ := hex.DecodeString(ciphertextHex)

	original := RTPPacket{}
	original.buffer = plaintext

	encrypted := RTPPacket{}
	encrypted.buffer = make([]byte, len(original.buffer))
	copy(encrypted.buffer, original.buffer)
	err := encrypted.EncryptGCM(0, key, salt)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	compareByteArrays(t, encrypted.buffer, ciphertext)

	decrypted := RTPPacket{}
	decrypted.buffer = make([]byte, len(encrypted.buffer))
	copy(decrypted.buffer, encrypted.buffer)
	err = decrypted.DecryptGCM(0, key, salt)
	if err != nil {
		t.Fatalf("Decrypt error: %v", err)
	}

	compareByteArrays(t, original.buffer, decrypted.buffer)
}
