package rtp

import (
	"testing"
)

func TestGenExt(t *testing.T) {
	p := NewRTPPacket([]byte{1, 2, 3, 4}, 8 /*pt*/, 22 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)

	p.SetGeneralExt(10, []byte{22, 33, 44})

	p.SetPayload([]byte{200, 11, 12, 13})

	ext1 := p.GetGeneralExt(1)
	if ext1 != nil {
		t.Errorf("Problem fetching missing general extention")
	}

	ext2 := p.GetGeneralExt(10)
	if ext2 == nil {
		t.Errorf("Problem general extention not found")
	} else if len(ext2) != 3 {
		t.Errorf("Problem general extention wrong length")
	} else if ext2[1] != 33 {
		t.Errorf("Problem general extention wrong data")
	}
}

func TestClientVolume(t *testing.T) {
	p := NewRTPPacket([]byte{1, 2, 3, 4}, 8 /*pt*/, 22 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)
	s := NewRTPSession()

	s.AddExtMap(42, "urn:ietf:params:rtp-hdrext:ssrc-audio-level")

	p.SetExtClientVolume(s, true, -12)
	p.SetPayload([]byte{200, 11, 12, 13})

	vad, dBov := p.GetExtClientVolume(s)
	if vad != true {
		t.Errorf("Vad bit is wrong")
	}
	if dBov != -12 {
		t.Errorf("dBov bit is wrong. Got %d", dBov)
	}

}
