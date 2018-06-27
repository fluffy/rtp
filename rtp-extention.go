package rtp

/*
Header extentions described in https://tools.ietf.org/html/rfc8285

Client To Mixer volume level in https://tools.ietf.org/html/rfc6464
*/

import (
	"errors"
	//"fmt"
)

func (p *RTPPacket) SetGeneralExt(num int, data []byte) error {
	// Set a RFC5285 style General Extention
	if (num < 1) || (num == 15) || (num > 255) {
		return errors.New("rtp: bad number for SetGeneralExt")
	}

	if num < 14 {
		// using 1 byte header
		if len(data) > 16 {
			return errors.New("rtp: extention too large for SetGeneralExt short header")
		}
		if len(data) < 1 {
			return errors.New("rtp: extention too small for SetGeneralExt short header")
		}
		lenValue := len(data) - 1
		header := (num << 4) + lenValue

		extData := make([]byte, len(data)+1)
		extData[0] = byte(header)
		copy(extData[1:], data)
		extNum := uint16(0xBEDE)

		//fmt.Printf( "write gen ext num=%x data=%x \n",extNum, extData )

		p.SetHdrExt(extNum, extData)

	} else {
		// using 2 byte header
	}

	return nil
}

func (p *RTPPacket) GetGeneralExt(num int) []byte {
	// Get a RFC5285 style General Extention
	genExtNum, genExtData := p.GetHdrExt()

	//fmt.Printf( "read HDR ext num=0x%X data=0x%X \n",genExtNum, genExtData )

	if genExtNum == 0xBEDE {
		if len(genExtData) < 1 {
			return nil
		}
		extNum := int(genExtData[0] >> 4)
		extLen := int((genExtData[0] & 0x0F) + 1)

		//fmt.Printf( "read gen ext num=%x len=%x \n",extNum, extLen )

		if len(genExtData) < extLen+1 {
			return nil
		}

		if extNum == num {
			data := genExtData[1 : extLen+1]
			return data
		}
	}

	// Gen Ext not found
	return nil
}

func (p *RTPPacket) SetExtClientVolume(s *RTPSession, vad bool, dBov int8) error {
	// Set a RFC6464 client to mixer volume level
	extNum := s.extNameMap["urn:ietf:params:rtp-hdrext:ssrc-audio-level"]
	if extNum <= 14 {
		data := make([]byte, 1)
		value := uint8(-dBov)
		if vad {
			value |= 0x80
		}
		data[0] = value
		err := p.SetGeneralExt(extNum, data)
		return err
	} else if extNum <= 255 {
	}

	return errors.New("rtp: extention number out or range in SetExtClientVolume")
}

func (p *RTPPacket) GetExtClientVolume(s *RTPSession) (vad bool, dBov int8) {
	// Get a RFC6464 client to mixer volume level
	extNum := s.extNameMap["urn:ietf:params:rtp-hdrext:ssrc-audio-level"]

	data := p.GetGeneralExt(extNum)

	if extNum <= 14 {
		if len(data) == 1 {

			dBov = -int8(data[0] & 0x7F)
			vad = data[0]&0x7F > 0
			return
		}
	}

	return false, 0
}
