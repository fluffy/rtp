
package rtp

/*
https://tools.ietf.org/html/rfc6464 Client To Mixer volume level 
*/

import (
	//"errors"
	//"fmt"
)

func  (p *RTPPacket) GetClientVolume( s *RTPSession) ( vad bool, dBov int8  ) {
	extNum := s.extNameMap["urn:ietf:params:rtp-hdrext:ssrc-audio-level"]

	_ = extNum 
	return false, 0
}

