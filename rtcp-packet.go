package rtp

/*
 * RTCP header format is in
 * https://tools.ietf.org/html/rfc3550#section-6.1
        0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header |V=2|P|    RC   |   PT=SR=200   |             length            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         SSRC of sender                        |
       +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+


        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
header  |V=2|P|    RC   |   PT=RR=201   |             length            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                     SSRC of packet sender                     |
        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report  |                 SSRC_1 (SSRC of first source)                 |
block   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
1       | fraction lost |       cumulative number of packets lost       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           extended highest sequence number received           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                      interarrival jitter                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                         last SR (LSR)                         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                   delay since last SR (DLSR)                  |
        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
report  |                 SSRC_2 (SSRC of second source)                |
block    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
2       :                               ...                             :
        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
        |                  profile-specific extensions                  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


import (
  "crypto/aes"
  "crypto/cipher"
  "encoding/binary"
  "errors"
  // "encoding/hex"
)

type RTCPTypeClass uint8

// https://tools.ietf.org/html/rfc3550#section-12.1
const (
  RTCPTypeSR         RTCPTypeClass = 200
  RTCPTypeRR
  RTCPTypeSDES
  RTCPTypeBYE
  RTCPTypeAPP
)

const (
  RTCPHeaderSize = 8
)

type RTCPHeader struct {
  buffer []byte
}

func (p *RTCPHeader) Clone() *RTCPHeader {
	p2 := &RTCPHeader{
		buffer: make([]byte, len(p.buffer)),
	}

	copy(p2.buffer, p.buffer)
	return p2
}

func (p *RTCPHeader) GetRC() int {
  rc := p.buffer[0] & 31   // 31 = 0b00011111
  return int(rc);
}

func (p* RTCPHeader) SetPT(pt RTCPTypeClass) {
  p.buffer[1] = byte(pt);
}

func (p* RTCPHeader) GetPT() RTCPTypeClass {
  return RTCPTypeClass(p.buffer[1])
}

func (p* RTCPHeader) SetLength(length uint16) {
  binary.BigEndian.PutUint16(p.buffer[2:], length)
}

func (p* RTCPHeader) GetLength() uint16 {
  return binary.BigEndian.Uint16(p.buffer[2:])
}

func (p* RTCPHeader) GetLengthInBytes() uint32 {
  return (uint32(p.GetLength())+1)*4
}

func (p* RTCPHeader) SetSenderSSRC(ssrc uint32) {
  binary.BigEndian.PutUint32(p.buffer[4:], ssrc)
}

func (p* RTCPHeader) GetSenderSSRC() uint32 {
  return binary.BigEndian.Uint32(p.buffer[4:])
}


type RTCPPacket struct {
    header RTCPHeader
    payload []byte
}

type RTCPCompoundPacket struct {
  packets []*RTCPPacket
  srtcpIndex uint32
}

func (p* RTCPCompoundPacket) GetESRTCPWord(e bool) []byte {
  word := make([]byte, 4)
  binary.BigEndian.PutUint32(word, p.srtcpIndex)

  if e {
    word[0] |= byte(128) // 128 = 0b10000000
  }

  return word
}

func gcmIV(ssrc, esrtcpWord, salt []byte) []byte {
  iv := make([]byte, 12)

  iv[0] = 0
  iv[1] = 0

  iv[2] = ssrc[0]
  iv[3] = ssrc[1]
  iv[4] = ssrc[2]
  iv[5] = ssrc[3]

  iv[6] = 0
  iv[7] = 0

  iv[8] = esrtcpWord[0] & byte(127) // 127 = 0b01111111, sets the MSB to 0
  iv[9] = esrtcpWord[1]
  iv[10] = esrtcpWord[2]
  iv[11] = esrtcpWord[3]

  for i := range iv {
    iv[i] ^= salt[i]
  }

  return iv
}

func (p* RTCPCompoundPacket) GetGCMIV(salt []byte) []byte {
  return gcmIV(p.packets[0].header.buffer[4:8], p.GetESRTCPWord(true), salt)
}

func (p *RTCPCompoundPacket) EncryptGCM(key, salt []byte) (*SRTCPPacket, error) {
  sp := new(SRTCPPacket)

  // TODO: Support more than one packet
  rtcpPacket := p.packets[0]

  sp.header.buffer = make([]byte, RTCPHeaderSize)
  copy(sp.header.buffer, rtcpPacket.header.buffer)

  sp.payload = make([]byte, len(rtcpPacket.payload))
  copy(sp.payload, rtcpPacket.payload)

  block, err := aes.NewCipher(key)
  if err != nil {
    return nil, err
  }

  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return nil, err
  }

  iv := p.GetGCMIV(salt)

  tag := make([]byte, gcm.Overhead())
  sp.payload = append(sp.payload, tag...)

  aad := sp.header.buffer
  aad = append(aad, p.GetESRTCPWord(true)...)

  pt := sp.payload[:len(sp.payload)-len(tag)]

  gcm.Seal(sp.payload[0:0], iv, pt, aad)

  sp.payload = append(sp.payload, p.GetESRTCPWord(true)...)

  return sp, nil
}

// https://tools.ietf.org/html/rfc7714#section-9.2
/*
    0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
A  |V=2|P|   RC    |  Packet Type  |            length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
A  |           synchronization source (SSRC) of sender             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
P  |                         sender info                           :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
P  |                        report block 1                         :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
P  |                        report block 2                         :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
P  |                              ...                              :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
P  |V=2|P|   SC    |  Packet Type  |              length           |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
P  |                          SSRC/CSRC_1                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
P  |                           SDES items                          :
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
P  |                              ...                              :
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
A  |1|                         SRTCP index                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
R  |                  SRTCP MKI (optional) index                   :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
R  :           SRTCP authentication tag (NOT RECOMMENDED)          :
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type SRTCPPacket struct {
  header RTCPHeader
  payload []byte

}

func (p *SRTCPPacket) GetESRTCPWord() []byte {
  len := p.header.GetLengthInBytes() + 12 - RTCPHeaderSize
  return p.payload[len:len+4]
}

func (p *SRTCPPacket) GetSRTCPIndex() uint32 {
  eAndSRTCPIndex := make([]byte, 12)
  copy(eAndSRTCPIndex, p.GetESRTCPWord())

  // Set the E-bit to 0
  eAndSRTCPIndex[0] = eAndSRTCPIndex[0] & byte(127)

  return binary.BigEndian.Uint32(eAndSRTCPIndex)
}

func (p *SRTCPPacket) GetE() bool {
  return bool((p.GetESRTCPWord()[0] & byte(128)) == 128)
}

func (p *SRTCPPacket) GetAAD() []byte {
  srtcpIndexLine := make([]byte, len(p.GetESRTCPWord()))
  copy(srtcpIndexLine, p.GetESRTCPWord())

  headerBuffer := make([]byte, len(p.header.buffer))
  copy(headerBuffer, p.header.buffer)

  return append(headerBuffer, srtcpIndexLine...)
}

func (p *SRTCPPacket) GetCT() []byte {
  return p.payload[:len(p.payload)-4]
}

// https://tools.ietf.org/html/rfc7714#section-9.1
/*
     0  1  2  3  4  5  6  7  8  9 10 11
   +--+--+--+--+--+--+--+--+--+--+--+--+
   |00|00|    SSRC   |00|00|0+SRTCP Idx|---+
   +--+--+--+--+--+--+--+--+--+--+--+--+   |
                                           |
   +--+--+--+--+--+--+--+--+--+--+--+--+   |
   |         Encryption Salt           |->(+)
   +--+--+--+--+--+--+--+--+--+--+--+--+   |
                                           |
   +--+--+--+--+--+--+--+--+--+--+--+--+   |
   |       Initialization Vector       |<--+
   +--+--+--+--+--+--+--+--+--+--+--+--+
*/

func (p *SRTCPPacket) GgetGCMIV(salt []byte) []byte {
  return gcmIV(p.header.buffer[4:8], p.GetESRTCPWord(), salt)
}

func (sp *SRTCPPacket) DecryptGCM(key, salt []byte) (*RTCPCompoundPacket, error) {

  if !sp.GetE() {
    return nil, errors.New("srtcp: Encryption flag not set")
  }

  block, err := aes.NewCipher(key)
  if err != nil {
    return nil, err
  }

  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return nil, err
  }

  iv := sp.GgetGCMIV(salt)

  aad := sp.GetAAD()
  ct := sp.payload[:len(sp.payload)-4]

  _, err = gcm.Open(sp.payload[0:0], iv, ct, aad)
  if err != nil {
    return nil, err
  }

  sp.payload = sp.payload[:len(sp.payload)-gcm.Overhead()]

  rtcp := new(RTCPCompoundPacket)

  // TODO: Support more than one packet
  rtcpPacket := new(RTCPPacket)

  rtcp.packets = []*RTCPPacket{rtcpPacket}

	return rtcp, nil
}

func NewSRTCPPacket(buffer []byte) (*SRTCPPacket, error) {
  sp := new(SRTCPPacket)

  if len(buffer) < RTCPHeaderSize {
    return nil, errors.New("rtcp: header size is too small")
  }

  sp.header.buffer = buffer[:RTCPHeaderSize]
  sp.payload = buffer[RTCPHeaderSize:]

  return sp, nil
}

func NewRTCPacket(pt RTCPTypeClass, len uint16, senderSsrc uint32, payload []byte) *RTCPPacket {
  p := new(RTCPPacket)

  p.header.buffer = make([]byte, RTCPHeaderSize, MTU)
  p.payload = payload

  p.header.SetPT(pt)
  p.header.SetLength(len)
  p.header.SetSenderSSRC(senderSsrc)

  return p
}
