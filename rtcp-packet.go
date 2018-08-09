package rtp


import (
  "crypto/aes"
  "crypto/cipher"
  "encoding/binary"
  "errors"
)

type RTCPTypeClass uint8

// https://tools.ietf.org/html/rfc3550#section-12.1
const (
  RTCPTypeSR         RTCPTypeClass = 200
  RTCPTypeRR         RTCPTypeClass = 201
  RTCPTypeSDES       RTCPTypeClass = 202
  RTCPTypeBYE        RTCPTypeClass = 203
  RTCPTypeAPP        RTCPTypeClass = 204
)

const (
  rtcpHeaderSize = 8
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

func (p* RTCPHeader) GetLengthInBytes() int {
  return (int(p.GetLength())+1)*4
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

type RTCPCompoundPacket struct {
  header RTCPHeader
  buffer []byte
  appendix []byte
}

func (p *RTCPCompoundPacket) Clone() *RTCPCompoundPacket {
  p2 := &RTCPCompoundPacket{
    header: RTCPHeader{
      buffer: make([]byte, rtcpHeaderSize),
    },
    buffer:    make([]byte, len(p.buffer)),
    appendix:    make([]byte, len(p.appendix)),
  }

  copy(p2.header.buffer, p.header.buffer)
  copy(p2.buffer, p.buffer)
  copy(p2.appendix, p.appendix)
  return p2
}

func (p *RTCPCompoundPacket) GetPackets() []*RTCPPacket {
  // TODO Support more than one package
  rtcpPacket := new(RTCPPacket)
  rtcpPacket.header = p.header
  rtcpPacket.payload = p.buffer

  return []*RTCPPacket{rtcpPacket}
}

func (p *RTCPCompoundPacket) GetHeader() *RTCPHeader {
  return &p.header
}
// SRTCP access functions
func (p *RTCPCompoundPacket) GetESRTCPWord() []byte {
  return p.appendix[:4]
}

func (p *RTCPCompoundPacket) GetSRTCPIndex() uint32 {
  esrtcpWord := binary.BigEndian.Uint32(p.GetESRTCPWord())

  // This AND sets the first bit that is the E-bit to 0
  return esrtcpWord & uint32(0x7fffffff)
}

func (p *RTCPCompoundPacket) GetE() bool {
  return bool((p.GetESRTCPWord()[0] & byte(128)) == 128)
}

func (p *RTCPCompoundPacket) getAAD() []byte {
  srtcpIndexLine := make([]byte, len(p.GetESRTCPWord()))
  copy(srtcpIndexLine, p.GetESRTCPWord())

  headerBuffer := make([]byte, len(p.header.buffer))
  copy(headerBuffer, p.header.buffer)

  return append(headerBuffer, p.GetESRTCPWord()...)
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

func (p* RTCPCompoundPacket) gcmIV(salt []byte) []byte {
  srtcpIndex := make([]byte, 4)
  binary.BigEndian.PutUint32(srtcpIndex, p.GetSRTCPIndex())

  ssrc := make([]byte, 4)
  binary.BigEndian.PutUint32(ssrc, p.header.GetSenderSSRC())

  iv := make([]byte, 12)

  iv[2] = ssrc[0]
  iv[3] = ssrc[1]
  iv[4] = ssrc[2]
  iv[5] = ssrc[3]

  iv[8] = srtcpIndex[0]
  iv[9] = srtcpIndex[1]
  iv[10] = srtcpIndex[2]
  iv[11] = srtcpIndex[3]

  for i := range iv {
    iv[i] ^= salt[i]
  }

  return iv
}

func (p *RTCPCompoundPacket) DecryptGCM(key, salt []byte) error {
  if !p.GetE() {
    return errors.New("srtcp: Encryption flag not set")
  }

  block, err := aes.NewCipher(key)
  if err != nil {
    return err
  }

  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return err
  }

  iv := p.gcmIV(salt)

  aad := p.getAAD()
  ct := p.buffer

  _, err = gcm.Open(p.buffer[0:0], iv, ct, aad)
  if err != nil {
    return err
  }

  p.buffer = p.buffer[:len(p.buffer)-gcm.Overhead()]

  return nil
}

func (p *RTCPCompoundPacket) EncryptGCM(key, salt []byte) error {
  block, err := aes.NewCipher(key)
  if err != nil {
    return err
  }

  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return err
  }

  iv := p.gcmIV(salt)

  tag := make([]byte, gcm.Overhead())
  p.buffer = append(p.buffer, tag...)

  aad := p.getAAD()
  pt := p.buffer[:len(p.buffer)-len(tag)]

  gcm.Seal(p.buffer[0:0], iv, pt, aad)

  return nil
}

func (p *RTCPCompoundPacket) GetBuffer() []byte {
  buffer := append(p.header.buffer, p.buffer...)
  buffer = append(buffer, p.appendix...)
  return buffer
}

func NewSRTCPPacket(buffer []byte) (*RTCPCompoundPacket, error) {
  sp := new(RTCPCompoundPacket)

  if len(buffer) < rtcpHeaderSize {
    return nil, errors.New("rtcp: header size is too small")
  }

  sp.header.buffer = buffer[:rtcpHeaderSize]
  length := sp.header.GetLengthInBytes() + 12

  sp.buffer = buffer[rtcpHeaderSize:length]
  sp.appendix = buffer[length:]

  return sp, nil
}

func NewRTCPCompoundPacket(buffer []byte, srtcpIndex uint32) (*RTCPCompoundPacket, error)  {
  p := new(RTCPCompoundPacket)

  p.header.buffer = buffer[:rtcpHeaderSize]
  p.buffer = buffer[rtcpHeaderSize:]
  p.appendix = make([]byte, 4)
  // | (1 << 32) sets the E-bit to 1
  binary.BigEndian.PutUint32(p.appendix, srtcpIndex | (1 << 31))

  return p, nil
}

func NewRTCPPacket(pt RTCPTypeClass, len uint16, senderSsrc uint32, payload []byte) *RTCPPacket {
  p := new(RTCPPacket)

  p.header.buffer = make([]byte, rtcpHeaderSize, MTU)
  p.payload = payload

  p.header.SetPT(pt)
  p.header.SetLength(len)
  p.header.SetSenderSSRC(senderSsrc)

  return p
}
