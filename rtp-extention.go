package rtp

/*
Header extentions described in https://tools.ietf.org/html/rfc8285

Client To Mixer volume level in https://tools.ietf.org/html/rfc6464
*/

import (
	"errors"
	"fmt"
)

func (p *RTPPacket) SetGeneralExt(num int, data []byte) error {
	// Set a RFC5285 style General Extention
	// TODO - currently can only set a single extention
	if (num < 1) || (num == 15) || (num > 255) {
		return errors.New("rtp: bad extention number for SetGeneralExt")
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

		nonPadLen := len(data) + 1
		pad := 0
		if nonPadLen%4 != 0 {
			pad = 4 - nonPadLen%4
		}

		extData := make([]byte, nonPadLen+pad)
		copy(extData[len(extData)-4:], []byte{0, 0, 0, 0}) // TODO - is this needed or does make do this
		extData[0] = byte(header)
		copy(extData[1:], data)
		extNum := uint16(0xBEDE)

		err := p.SetHdrExt(extNum, extData)
		if err != nil {
			fmt.Printf("rtp::SetGeneralExt call to SetHdrExt got error %s \n", err.Error())
			return err
		}

	} else {
		// using 2 byte header
		// TODO
		return errors.New("rtp SetGeneralExt long header not implemented")
	}

	return nil
}

func (p *RTPPacket) GetGeneralExt(num int) []byte {
	// Get a RFC5285 style General Extention
	genExtNum, genExtData := p.GetHdrExt()

	if genExtNum == 0xBEDE {
		for {
			if len(genExtData) == 0 {
				return nil
			}
			extNum := int(genExtData[0] >> 4)
			extLen := int((genExtData[0] & 0x0F) + 1)

			if len(genExtData) < extLen+1 {
				return nil
			}

			if extNum == 0 { //this is the pad indicator
				genExtData = genExtData[1:len(genExtData)]
				continue
			}

			if extNum == 15 { // stop processing any data after this
				return nil
			}

			//fmt.Printf( "GenExt found num=%d len=%d data=0x%x\n", extNum,extLen, genExtData[1 : extLen+1] )

			if extNum == num {
				data := genExtData[1 : extLen+1]
				return data
			}

			genExtData = genExtData[extLen+1 : len(genExtData)] // move to next extention
		}
	}
	if genExtNum&0xFFF0 == 0x1000 {
		// TODO - 2byte extention
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
		// TODO
		return errors.New("rtp SetGeneralExt long header not implemented")
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
	} else if extNum <= 255 {
		// TODO

	}

	return false, 0
}
