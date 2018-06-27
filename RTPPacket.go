package rtp

/*
* RTP packet format is in
* https://tools.ietf.org/html/rfc3550#section-5.1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           timestamp                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           synchronization source (SSRC) identifier            |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |            contributing source (CSRC) identifiers             |
   |                             ....                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Header extentions described in
https://tools.ietf.org/html/rfc8285

OHB defined in
https://datatracker.ietf.org/doc/draft-ietf-perc-double/

Note when creating packets must set CSRC before setting Header extentions before setting payload bure settin pad.

*/

import (
	"encoding/binary"
	"errors"
	//"fmt"
)

const (
	MTU = 1500
)

type RTPPacket struct {
	buffer []byte // contains full packet header, ext, and payload in netwrok byte order
}

func (p *RTPPacket) SetPad(marker bool) {
	if marker {
		p.buffer[0] |= 0x20
	} else {
		p.buffer[1] &= (0xFF ^ 0x20)
	}
}

func (p *RTPPacket) GetPad() bool {
	return (p.buffer[0] & 0x10) > 0
}

func (p *RTPPacket) SetExtBit(x bool) {
	if x {
		p.buffer[0] |= 0x10
	} else {
		p.buffer[1] &= (0xFF ^ 0x10)
	}
}

func (p *RTPPacket) GetExtBit() bool {
	return (p.buffer[0] & 0x10) > 0
}

func (p *RTPPacket) SetCC(cc uint8) {
	p.buffer[0] = (p.buffer[0] & 0xF) | cc
}

func (p *RTPPacket) GetCC() int {
	r := p.buffer[0] & 0x0F
	return int(r)
}

func (p *RTPPacket) SetMarker(marker bool) {
	if marker {
		p.buffer[1] |= 0xF0
	} else {
		p.buffer[1] &= (0xFF ^ 0xF0)
	}
}

func (p *RTPPacket) GetMaker() bool {
	return (p.buffer[1] & 0xF0) > 0
}

func (p *RTPPacket) SetPT(pt int8) {
	p.buffer[1] = byte(pt)
}

func (p *RTPPacket) GetPT() int8 {
	return int8(p.buffer[1])
}

func (p *RTPPacket) SetSeq(seq uint16) {
	binary.BigEndian.PutUint16(p.buffer[2:], seq)
}

func (p *RTPPacket) GetSeq() uint16 {
	return binary.BigEndian.Uint16(p.buffer[2:])
}

func (p *RTPPacket) SetTimestamp(ts uint32) {
	binary.BigEndian.PutUint32(p.buffer[4:], ts)
}

func (p *RTPPacket) GetTimestamp() uint32 {
	return binary.BigEndian.Uint32(p.buffer[4:])
}

func (p *RTPPacket) SetSSRC(ssrc uint32) {
	binary.BigEndian.PutUint32(p.buffer[8:], ssrc)
}

func (p *RTPPacket) GetSSRC() uint32 {
	return binary.BigEndian.Uint32(p.buffer[8:])
}

func (p *RTPPacket) SetCSRC(csrc []uint32) error {
	cc := uint8(len(csrc))
	if cc > 15 {
		return errors.New("rtp: CSRC list too large")
	}

	if 12+4*len(csrc) > cap(p.buffer) {
		return errors.New("rtp: CSRC list too large to fit in packet MTU")
	}
	p.buffer = p.buffer[0 : 12+4*len(csrc)] // truncate to just header + CSRC

	p.SetCC(cc)

	for i := 0; i < len(csrc); i++ {
		binary.BigEndian.PutUint32(p.buffer[12+4*i:12+4*i+4], csrc[i])
	}

	return nil
}

func (p *RTPPacket) GetCSRC() []uint32 {

	cc := p.GetCC()

	csrc := make([]uint32, cc)

	for i := 0; i < int(cc); i++ {
		if 12+i*4+4 < len(p.buffer) {
			csrc[i] = binary.BigEndian.Uint32(p.buffer[12+i*4:])
		}
	}

	return csrc
}

func (p *RTPPacket) GetHdrExtLen() (extLen uint16) {
	extLen = 0

	if p.GetExtBit() {

		offset := 12 + 4*uint16(p.GetCC())
		extLen = binary.BigEndian.Uint16(p.buffer[offset+2:])
	}

	return
}

func (p *RTPPacket) GetHdrExt() (extNum uint16, ext []byte) {
	extNum = 0

	if p.GetExtBit() {

		offset := 12 + 4*uint16(p.GetCC())

		extNum = binary.BigEndian.Uint16(p.buffer[offset:])
		extLen := binary.BigEndian.Uint16(p.buffer[offset+2:])

		ext = p.buffer[offset+4 : offset+4+extLen]
	}

	return
}

func (p *RTPPacket) SetHdrExt(extNum uint16, ext []byte) error {
	/* Note: must set CC before setting extHdr */

	p.SetExtBit(true)

	offset := 12 + 4*p.GetCC()

	if offset+4+len(ext) > cap(p.buffer) {
		return errors.New("rtp: header extention too large to fit in packet MTU")
	}
	p.buffer = p.buffer[0 : offset+4+len(ext)] // truncate to just header + CSRC + HdrExt

	binary.BigEndian.PutUint16(p.buffer[offset:], extNum)
	binary.BigEndian.PutUint16(p.buffer[offset+2:], uint16(len(ext)))

	copy(p.buffer[offset+4:offset+4+len(ext)], ext)

	return nil
}

func (p *RTPPacket) GetPayload() []byte {
	start := 12 + 4*uint16(p.GetCC()) + p.GetHdrExtLen()
	var pad byte = 0
	if p.GetPad() {
		pad = p.buffer[len(p.buffer)-1]
	}
	end := len(p.buffer) - int(pad)

	return p.buffer[start:end]
}

func (p *RTPPacket) SetPayload(payload []byte) error {
	/* note call this after seting CSRC and header extentions */

	offset := 12 + 4*p.GetCC() + int(p.GetHdrExtLen())
	packetLen := offset + (len(payload))
	if packetLen > cap(p.buffer) {

		return errors.New("rtp: payload too large to fit in packet MTU")
	}
	p.buffer = p.buffer[0:packetLen] // truncate buffer to packet length

	copy(p.buffer[offset:], payload)

	return nil
}

func (p *RTPPacket) SetPadding(sizeMult int) error {
	packetLen := len(p.buffer)
	pad := sizeMult - packetLen%sizeMult

	if pad > 0 {
		if packetLen+pad > cap(p.buffer) {
			return errors.New("rtp: padding too large to fit in packet MTU")
		}
		p.buffer = p.buffer[0 : packetLen+pad] // truncate buffer to packet length
		p.buffer[packetLen+pad-1] = byte(pad)
	}

	return nil
}

func NewRTPPacket(payload []byte, payloadType int8, seq uint16, ts uint32, ssrc uint32) *RTPPacket {
	p := new(RTPPacket)
	p.buffer = make([]byte, 12 /*RTP Header size*/ +len(payload), MTU)
	p.buffer[0] = 128

	p.SetPT(payloadType)
	p.SetSeq(seq)
	p.SetSSRC(ssrc)
	p.SetTimestamp(ts)

	copy(p.buffer[12:], payload)

	return p
}
