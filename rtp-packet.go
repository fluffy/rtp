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

Note when creating packets must set CSRC before setting Header extentions before setting payload before setting pad.

AES-GCM for SRTP from https://datatracker.ietf.org/doc/rfc7714/

*/

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	MTU = 1500
)

type RTPPacket struct {
	buffer []byte // contains full RTP packet header, and payload in netwrok byte order
	ekt    []byte //  contain
}

func (p *RTPPacket) Clone() *RTPPacket {
	p2 := &RTPPacket{
		buffer: make([]byte, len(p.buffer)),
		ekt:    make([]byte, len(p.ekt)),
	}

	copy(p2.buffer, p.buffer)
	copy(p2.ekt, p.ekt)
	return p2
}

func (p *RTPPacket) getCSRCOffset() int {
	return 12
}

func (p *RTPPacket) getHdrExtOffset() int {
	return 12 + 4*p.GetCC()
}

func (p *RTPPacket) getPayloadOffset() int {
	ret := 12
	ret += 4 * p.GetCC()
	if p.GetExtBit() {
		ret += p.GetHdrExtLen()
	}
	return ret
}

func (p *RTPPacket) getPadOffset() int {
	var pad byte = 0
	if p.GetPad() {
		pad = p.buffer[len(p.buffer)-1]
	}
	offset := len(p.buffer) - int(pad)
	return offset
}

func (p *RTPPacket) SetPad(marker bool) error {
	if marker {
		p.buffer[0] |= 0x20
	} else {
		p.buffer[0] &= (0xFF ^ 0x20)
	}
	return nil
}

func (p *RTPPacket) GetPad() bool {
	return (p.buffer[0] & 0x20) > 0
}

func (p *RTPPacket) SetExtBit(x bool) error {
	if x {
		p.buffer[0] |= 0x10
	} else {
		p.buffer[0] &= (0xFF ^ 0x10)
	}
	return nil
}

func (p *RTPPacket) GetExtBit() bool {
	return (p.buffer[0] & 0x10) > 0
}

func (p *RTPPacket) SetCC(cc int) error {
	if (cc < 0) || (cc > 15) {
		return errors.New("rtp: invalid CC value")
	}
	p.buffer[0] = (p.buffer[0] & 0xF) | byte(cc)
	return nil
}

func (p *RTPPacket) GetCC() int {
	r := p.buffer[0] & 0x0F
	return int(r)
}

func (p *RTPPacket) SetMarker(marker bool) error {
	if marker {
		p.buffer[1] |= 0xF0
	} else {
		p.buffer[1] &= (0xFF ^ 0xF0)
	}
	return nil
}

func (p *RTPPacket) GetMarker() bool {
	return (p.buffer[1] & 0xF0) > 0
}

func (p *RTPPacket) SetPT(pt int8) error {
	p.buffer[1] = byte(pt)
	return nil
}

func (p *RTPPacket) GetPT() int8 {
	return int8(p.buffer[1])
}

func (p *RTPPacket) SetSeq(seq uint16) error {
	binary.BigEndian.PutUint16(p.buffer[2:], seq)
	return nil
}

func (p *RTPPacket) GetSeq() uint16 {
	return binary.BigEndian.Uint16(p.buffer[2:])
}

func (p *RTPPacket) SetTimestamp(ts uint32) error {
	binary.BigEndian.PutUint32(p.buffer[4:], ts)
	return nil
}

func (p *RTPPacket) GetTimestamp() uint32 {
	return binary.BigEndian.Uint32(p.buffer[4:])
}

func (p *RTPPacket) SetSSRC(ssrc uint32) error {
	binary.BigEndian.PutUint32(p.buffer[8:], ssrc)
	return nil
}

func (p *RTPPacket) GetSSRC() uint32 {
	return binary.BigEndian.Uint32(p.buffer[8:])
}

func (p *RTPPacket) SetCSRC(csrc []uint32) error {
	cc := len(csrc)
	if cc > 15 {
		return errors.New("rtp: CSRC list too large")
	}

	if 12+4*len(csrc) > cap(p.buffer) {
		return errors.New("rtp: CSRC list too large to fit in packet MTU")
	}
	p.buffer = p.buffer[0 : 12+4*len(csrc)] // truncate to just header + CSRC

	err := p.SetCC(cc)
	if err != nil {
		return err
	}

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

func (p *RTPPacket) GetHdrExtLen() (extLen int) {
	extLen = 0

	if p.GetExtBit() {
		offset := p.getHdrExtOffset()
		extCount := int(binary.BigEndian.Uint16(p.buffer[offset+2:]))
		extLen = extCount*4 + 4
	}

	return extLen
}

func (p *RTPPacket) GetHdrExt() (extNum uint16, ext []byte) {
	extNum = 0

	if p.GetExtBit() {

		offset := p.getHdrExtOffset()

		extNum = binary.BigEndian.Uint16(p.buffer[offset:])
		extCount := int(binary.BigEndian.Uint16(p.buffer[offset+2:]))
		ext = p.buffer[offset+4 : offset+4+extCount*4]
	}

	return
}

func (p *RTPPacket) SetHdrExt(extNum uint16, ext []byte) error {
	/* Note: must set CCSRC before setting extHdr */

	if len(ext)%4 != 0 {
		return errors.New("rtp: header extention must be 32 bit padded")
	}

	offset := p.getHdrExtOffset()

	if offset+4+len(ext) > cap(p.buffer) {
		return errors.New("rtp: header extention too large to fit in packet MTU")
	}
	p.buffer = p.buffer[0 : offset+4+len(ext)] // truncate to just header + CSRC + HdrExt

	err := p.SetExtBit(true)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint16(p.buffer[offset:], extNum)

	extCount := len(ext) / 4
	binary.BigEndian.PutUint16(p.buffer[offset+2:], uint16(extCount))

	copy(p.buffer[offset+4:offset+4+len(ext)], ext)

	return nil
}

func (p *RTPPacket) GetPayload() []byte {
	start := p.getPayloadOffset()

	var pad byte = 0
	if p.GetPad() {
		pad = p.buffer[len(p.buffer)-1]
	}
	end := len(p.buffer) - int(pad)

	if start >= end {
		//fmt.Printf( "GetPayload payload empty start=%d end=%d pad=%d\n", start, end, pad  )
		return nil
	}

	return p.buffer[start:end]
}

func (p *RTPPacket) SetPayload(payload []byte) error {
	/* note call this after seting CSRC and header extentions */

	offset := p.getPayloadOffset()

	packetLen := offset + len(payload)
	if packetLen > cap(p.buffer) {
		return errors.New("rtp: payload too large to fit in packet MTU")
	}

	p.buffer = p.buffer[0:packetLen] // extend buffer to packet length

	copy(p.buffer[offset:], payload)

	return nil
}

func (p *RTPPacket) SetPadding(sizeMult int) error {
	packetLen := len(p.buffer)
	pad := 0
	if packetLen%sizeMult > 0 {
		pad = sizeMult - packetLen%sizeMult
	}

	if pad > 0 {
		if packetLen+pad > cap(p.buffer) {
			grow := packetLen + pad - cap(p.buffer)
			p.buffer = append(p.buffer, make([]byte, grow)...)
		}
		p.buffer = p.buffer[0 : packetLen+pad] // extend buffer to packet length
		p.buffer[packetLen+pad-1] = byte(pad)
		p.SetPad(true)
	}

	return nil
}

func (p *RTPPacket) GetOHBLen() int {
	payload := p.GetPayload()
	if len(payload) == 0 {
		return 0
	}

	offset := len(payload) - 1

	config := payload[offset]

	ohbSize := 1
	if config&0x01 > 0 {
		ohbSize += 2
	}
	if config&0x02 > 0 {
		ohbSize += 1
	}

	return ohbSize
}

func (p *RTPPacket) GetOHB() (pt int8, seq uint16, m bool) {
	pt = p.GetPT()
	seq = p.GetSeq()
	m = p.GetMarker()

	payload := p.GetPayload()
	offset := len(payload) - 1

	config := payload[offset]
	offset--

	if config&0x01 > 0 {
		seq = binary.BigEndian.Uint16(payload[offset-1:])
		offset -= 2
	}

	if config&0x02 > 0 {
		pt = int8(payload[offset])
		offset -= 1
	}

	if config&0x03 > 0 {
		m = config&0x8 > 0
	}

	return
}

func (p *RTPPacket) SetOHB(pt int8, seq uint16, m bool) error {
	currentPt := p.GetPT()
	currentSeq := p.GetSeq()
	currentM := p.GetMarker()

	var config byte = 0
	ohbLen := 1

	if seq != currentSeq {
		config |= 0x1
		ohbLen += 2
	}

	if pt != currentPt {
		config |= 0x2
		ohbLen += 1
	}

	if m != currentM {
		config |= 0x4
		if m {
			config |= 0x8
		}
	}

	packetLen := len(p.buffer) + ohbLen
	if packetLen > cap(p.buffer) {
		grow := packetLen - cap(p.buffer)
		p.buffer = append(p.buffer, make([]byte, grow)...)
	}
	p.buffer = p.buffer[0:packetLen] // expand buffer to packet length
	offset := packetLen - 1

	p.buffer[offset] = config
	offset--

	if config&0x01 > 0 {
		binary.BigEndian.PutUint16(p.buffer[offset-1:], seq)
		offset -= 2
	}

	if config&0x02 > 0 {
		p.buffer[offset] = byte(pt)
		offset -= 1
	}

	return nil
}

func (p *RTPPacket) String() string {

	ret := fmt.Sprintf("pt=%d seq=%d ts=%d P=%t X=%t C=%d", p.GetPT(), p.GetSeq(), p.GetTimestamp(), p.GetPad(), p.GetExtBit(), p.GetCC())

	if p.GetHdrExtLen() > 0 {
		extNum, extData := p.GetHdrExt()
		ret += fmt.Sprintf(" extLen=%d extNum=0x%X extData=0x%X", p.GetHdrExtLen(), extNum, extData)
	}

	csrcList := p.GetCSRC()
	if len(csrcList) > 0 {
		ret += fmt.Sprintf(" numCSRC=%d CSRC=0x%X", len(csrcList), csrcList)
	}

	payload := p.GetPayload()
	if len(payload) > 0 {
		ret += fmt.Sprintf(" dataLen=%d data=0x%X", len(payload), payload)
	} else {
		ret += fmt.Sprintf(" NoPayload")
	}

	return ret
}

//   0  0  0  0  0  0  0  0  0  0  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1
// +--+--+--+--+--+--+--+--+--+--+--+--+
// |00|00|    SSRC   |     ROC   | SEQ |---+
// +--+--+--+--+--+--+--+--+--+--+--+--+   |
//                                         |
// +--+--+--+--+--+--+--+--+--+--+--+--+   |
// |         Encryption Salt           |->(+)
// +--+--+--+--+--+--+--+--+--+--+--+--+   |
//                                         |
// +--+--+--+--+--+--+--+--+--+--+--+--+   |
// |       Initialization Vector       |<--+
// +--+--+--+--+--+--+--+--+--+--+--+--+
func (p *RTPPacket) gcmIV(roc uint32, salt []byte) []byte {
	iv := make([]byte, 12)
	iv[2] = p.buffer[8] // SSRC
	iv[3] = p.buffer[9]
	iv[4] = p.buffer[10]
	iv[5] = p.buffer[11]
	iv[6] = byte(roc >> 24) // ROC
	iv[7] = byte(roc >> 16)
	iv[8] = byte(roc >> 8)
	iv[9] = byte(roc >> 0)
	iv[10] = p.buffer[2] // SEQ
	iv[11] = p.buffer[3]

	for i := range iv {
		iv[i] ^= salt[i]
	}

	return iv
}

func (p *RTPPacket) EncryptGCM(roc uint32, key, salt []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	iv := p.gcmIV(roc, salt)

	start := p.getPayloadOffset()
	end := len(p.buffer)

	if start >= end {
		return errors.New("rtp: invalid payload size")
	}

	tag := make([]byte, gcm.Overhead())
	p.buffer = append(p.buffer, tag...)

	aad := p.buffer[0:start]
	pt := p.buffer[start:end]

	gcm.Seal(p.buffer[start:start], iv, pt, aad)
	return nil
}

func (p *RTPPacket) DecryptGCM(roc uint32, key, salt []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	iv := p.gcmIV(roc, salt)

	start := p.getPayloadOffset()
	end := len(p.buffer)

	aad := p.buffer[0:start]
	ct := p.buffer[start:end]

	_, err = gcm.Open(p.buffer[start:start], iv, ct, aad)
	if err != nil {
		return err
	}

	p.buffer = p.buffer[:len(p.buffer)-gcm.Overhead()]
	return nil
}

func NewRTPPacket(payload []byte, payloadType int8, seq uint16, ts uint32, ssrc uint32) *RTPPacket {
	p := new(RTPPacket)
	p.buffer = make([]byte, 12 /*RTP Header size*/ +len(payload), MTU)
	p.buffer[0] = 128
	p.ekt = make([]byte, 1, 256/8+4)
	p.ekt[0] = 0 // this is short EKT heaader

	err := p.SetPT(payloadType)
	if err != nil {
		return nil
	}

	err = p.SetSeq(seq)
	if err != nil {
		return nil
	}

	err = p.SetSSRC(ssrc)
	if err != nil {
		return nil
	}

	err = p.SetTimestamp(ts)
	if err != nil {
		return nil
	}

	copy(p.buffer[12:], payload)

	return p
}
