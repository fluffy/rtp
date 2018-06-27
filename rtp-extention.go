package rtp

/*
Header extentions described in https://tools.ietf.org/html/rfc8285

Client To Mixer volume level in https://tools.ietf.org/html/rfc6464
*/

import (
//"errors"
//"fmt"
)

func (p *RTPPacket) SetGeneralExt(num int, data []byte) error {
	// Set a RFC5285 style General Extention
	return nil
}

func (p *RTPPacket) GetGeneralExt(num int) []byte {
	// Get a RFC5285 style General Extention
	return nil
}

func (p *RTPPacket) SetExtClientVolume(s *RTPSession, vad bool, dBov int8) error {
	// Set a RFC6464 client to mixer volume level
	return nil
}

func (p *RTPPacket) GetExtClientVolume(s *RTPSession) (vad bool, dBov int8) {
	// Get a RFC6464 client to mixer volume level
	extNum := s.extNameMap["urn:ietf:params:rtp-hdrext:ssrc-audio-level"]

	_ = extNum
	return false, 0
}
