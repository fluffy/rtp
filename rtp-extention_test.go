package rtp

import (
	"fmt"
	"testing"
)

func TestGenExt(t *testing.T) {
	if true {
		p := NewRTPPacket([]byte{1, 2, 3, 4}, 8 /*pt*/, 22 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)

		//fmt.Printf( "pre ext packet %s \n", p.String() )

		err := p.SetGeneralExt(9, []byte{0xA, 0xB, 0xC, 0xD})
		if err != nil {
			t.Errorf(err.Error())
		}

		//fmt.Printf( "post ext packet %s \n", p.String() )

		err = p.SetPayload([]byte{200, 11, 12, 13})
		if err != nil {
			t.Errorf(err.Error())
		}

		fmt.Printf("TestGenExt packet %s \n", p.String())

		if false {
			ext1 := p.GetGeneralExt(1)
			if ext1 != nil {
				t.Errorf("Problem fetching missing general extention")
			}
		}

		ext2 := p.GetGeneralExt(9)
		if ext2 == nil {
			t.Errorf("Problem general extention not found")
		} else if len(ext2) != 4 {
			t.Errorf("Problem general extention wrong length")
		} else if ext2[1] != 0xB {
			t.Errorf("Problem general extention wrong data")
		}

		payload := p.GetPayload()
		if len(payload) != 4 {
			t.Errorf("payload size is wrong")
		} else {
			if payload[0] != 200 {
				t.Errorf("payload data is wrong")
			}
		}
	}
}

func TestClientVolume(t *testing.T) {

	if true {

		s := NewRTPSession()
		s.AddExtMap(11, "urn:ietf:params:rtp-hdrext:ssrc-audio-level")

		p := NewRTPPacket([]byte{1, 2, 3, 4}, 8 /*pt*/, 22 /*seq*/, 33 /*ts*/, 44 /*ssrc*/)

		err := p.SetExtClientVolume(s, true, -12)
		if err != nil {
			t.Errorf(err.Error())
		}

		err = p.SetPayload([]byte{200, 11, 12, 13})
		if err != nil {
			t.Errorf(err.Error())
		}

		vad, dBov := p.GetExtClientVolume(s)
		if vad != true {
			t.Errorf("Vad bit is wrong")
		}
		if dBov != -12 {
			t.Errorf("dBov bit is wrong. Got %d", dBov)
		}
	}
}
