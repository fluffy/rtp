package rtp

import (
	"fmt"
	"testing"
)

func Test1(t *testing.T) {
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

func Test2(t *testing.T) {
	p := NewRTPPacket([]byte{1, 2, 3, 4, 5}, 8 /*pt*/, 22 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)

	p.SetMarker(true)
	p.SetPT(9)
	p.SetSeq(122)
	p.SetTimestamp(133)
	p.SetSSRC(144)
	p.SetCSRC([]uint32{66, 67})
	p.SetHdrExt(77, []byte{99, 11, 12, 14, 10, 11, 12, 14})
	p.SetPayload([]byte{200, 11, 12, 13})
	p.SetPadding(48)

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
	if len(ext) != 8 {
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

func Test3(t *testing.T) {
	p := NewRTPPacket([]byte{0xa1, 0xa2, 0xa3, 0xa4}, 2 /*pt*/, 3 /*seq*/, 4 /*ts*/, 5 /*ssrc*/)

	p.SetOHB(6, 7, true)
	fmt.Printf("Post setOHB %s\n", p.String())

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
