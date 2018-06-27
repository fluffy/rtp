package rtp

import "testing"

func Test1(t *testing.T) {
	p := createPacket([]byte{1, 2, 3, 4}, 8 /*pt*/, 22 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)

	pad := p.getPad()
	if pad {
		t.Errorf("Pad is wrong")
	}

	x := p.getExtBit()
	if x {
		t.Errorf("Extention bit is wrong")
	}

	cc := p.getCC()
	if cc != 0 {
		t.Errorf("CC is wrong. Got %d ", cc)
	}

	pt := p.getPT()
	if pt != 8 {
		t.Errorf("PT is wrong. Got %d ", pt)
	}

	seq := p.getSeq()
	if seq != 22 {
		t.Errorf("Seq is wrong. Got %d ", seq)
	}

	ts := p.getTimestamp()
	if ts != 33 {
		t.Errorf("TS is wrong. Got %d ", ts)
	}

	ssrc := p.getSSRC()
	if ssrc != 44 {
		t.Errorf("SSRC is wrong. Got %d ", ssrc)
	}

	csrc := p.getCSRC()
	if len(csrc) != 0 {
		t.Errorf("CSRC is wrong")
	}

	hdrExtLen := p.getHdrExtLen()
	if hdrExtLen != 0 {
		t.Errorf("HeaderExt length is wrong")
	}

	extNum, ext := p.getHdrExt()
	if extNum != 0 {
		t.Errorf("extNum  is wrong")
	}
	if len(ext) != 0 {
		t.Errorf("HeaderExt data length is wrong")
	}

	payload := p.getPayload()
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
	p := createPacket([]byte{1, 2, 3, 4, 5}, 8 /*pt*/, 22 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)

	p.setPad(true)
	p.setMarker(true)
	p.setPT(9)
	p.setSeq(122)
	p.setTimestamp(133)
	p.setSSRC(144)
	p.setCSRC([]uint32{66, 67})
	p.setHdrExt(77, []byte{99, 11, 12, 14, 10, 11, 12, 14})
	p.setPayload([]byte{200, 11, 12, 13})
	p.padTo(48)

	pad := p.getPad()
	if pad == false {
		t.Errorf("Pad is wrong")
	}

	x := p.getExtBit()
	if x == false {
		t.Errorf("Extention bit is wrong")
	}

	cc := p.getCC()
	if cc != 2 {
		t.Errorf("CC is wrong. Got %d ", cc)
	}

	pt := p.getPT()
	if pt != 9 {
		t.Errorf("PT is wrong. Got %d ", pt)
	}

	seq := p.getSeq()
	if seq != 122 {
		t.Errorf("Seq is wrong. Got %d ", seq)
	}

	ts := p.getTimestamp()
	if ts != 133 {
		t.Errorf("TS is wrong. Got %d ", ts)
	}

	ssrc := p.getSSRC()
	if ssrc != 144 {
		t.Errorf("SSRC is wrong. Got %d ", ssrc)
	}

	csrc := p.getCSRC()
	if len(csrc) != 2 {
		t.Errorf("CSRC is wrong")
	} else if csrc[0] != 66 {
		t.Errorf("CSRC is wrong")
	}

	hdrExtLen := p.getHdrExtLen()
	if hdrExtLen != 8 {
		t.Errorf("HeaderExt length is wrong. Got %d ", hdrExtLen)
	}

	extNum, ext := p.getHdrExt()
	if extNum != 77 {
		t.Errorf("extNum  is wrong")
	}
	if len(ext) != 8 {
		t.Errorf("HeaderExt data length is wrong")
	} else if ext[0] != 99 {
		t.Errorf("HeaderExt data  is wrong. Got %d", ext[0])
	}

	payload := p.getPayload()
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
