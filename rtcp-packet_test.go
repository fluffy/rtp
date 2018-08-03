package rtp

import (
	"bytes"
	"encoding/hex"
	"testing"
)


func unreachable(t *testing.T) {
  t.Fatalf("unreachable reached")
}

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
    println("actual: ", a)
    println("expected: ", b)
		t.Fatalf("%s != %s", a, b)
	}
}

func compareByteArrays(t *testing.T, actual []byte, expected []byte) {
  if !bytes.Equal(actual, expected) {
    t.Fatalf("Known-answer test failed: %x != %x", actual, expected)
  }
}


func TestRTCPConstructGet(t *testing.T) {
  p := NewRTCPacket(RTCPTypeSR/*pt*/, 1 /*length*/, 0xbcdc0094/*sender ssrc*/, []byte{1, 2, 3, 4} /*payload*/)

  assertEqual(t, p.header.GetPT(), RTCPTypeSR)
  assertEqual(t, p.header.GetLength(), uint16(1))
  assertEqual(t, p.header.GetSenderSSRC(), uint32(0xbcdc0094))
}

func TestRTCPSet(t *testing.T) {
  p := NewRTCPacket(RTCPTypeSR /*pt*/, 1 /*length*/, 0xbcdc0094/*sender ssrc*/, []byte{1, 2, 3, 4} /*payload*/)

  p.header.SetPT(RTCPTypeRR)
  p.header.SetLength(1)
  p.header.SetSenderSSRC(0xbcdc1010)

  assertEqual(t, p.header.GetPT(), RTCPTypeRR)
  assertEqual(t, p.header.GetLength(), uint16(1))
  assertEqual(t, p.header.GetSenderSSRC(), uint32(0xbcdc1010))
}

// Data from https://tools.ietf.org/html/rfc7714#section-17.2

// salt: 51 75 69 64 20 70 72 6f 20 71 75 6f
var salt, _ = hex.DecodeString("517569642070726f2071756f")

// Key: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
//      10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
var key, _ = hex.DecodeString("000102030405060708090a0b0c0d0e0f" +
                        "101112131415161718191a1b1c1d1e1f")


// plaintext
/*
 81c8000d 4d617273 4e545031 4e545032
 52545020 0000042a 0000e930 4c756e61
 deadbeef deadbeef deadbeef deadbeef
 deadbeef
*/
var plaintext, _  = hex.DecodeString("81c8000d4d6172734e5450314e545032" +
                                     "525450200000042a0000e9304c756e61" +
                                     "deadbeefdeadbeefdeadbeefdeadbeef" +
                                     "deadbeef")

// ciphertext
/*
81c8000d 4d617273 d50ae4d1 f5ce5d30
4ba297e4 7d470c28 2c3ece5d bffe0a50
a2eaa5c1 110555be 8415f658 c61de047
6f1b6fad 1d1eb30c 4446839f 57ff6f6c
b26ac3be 800005d4
*/
var ciphertext, _ = hex.DecodeString("81c8000d4d617273d50ae4d1f5ce5d304ba297e47d470c28" +
                                     "2c3ece5dbffe0a50a2eaa5c1110555be8415f658c61de047" +
                                     "6f1b6fad1d1eb30c4446839f57ff6f6cb26ac3be800005d4")
// GCM IV
// IV: 51 75 24 05 52 03 72 6f 20 71 70 bb
var iv, _ = hex.DecodeString("517524055203726f207170bb")

func TestSRTCPDecryption(t *testing.T) {
  expectedAAD, _ := hex.DecodeString("81c8000d4d617273800005d4")

  // CT: d50ae4d1 f5ce5d30 4ba297e4 7d470c28
  //     2c3ece5d bffe0a50 a2eaa5c1 110555be
  //     8415f658 c61de047 6f1b6fad 1d1eb30c
  //     4446839f 57ff6f6c b26ac3be
  expectedCT, _ := hex.DecodeString("d50ae4d1f5ce5d304ba297e47d470c28" +
                                    "2c3ece5dbffe0a50a2eaa5c1110555be" +
                                    "8415f658c61de0476f1b6fad1d1eb30c" +
                                    "4446839f57ff6f6cb26ac3be")

  myCiphertext := make([]byte, len(ciphertext))
  copy(myCiphertext, ciphertext)

  sp, err := NewSRTCPPacket(myCiphertext)
  if err != nil {
    unreachable(t)
  }

  assertEqual(t, sp.header.GetPT(), RTCPTypeSR)
  assertEqual(t, sp.header.GetLength(), uint16(13))
  // assertEqual(t, sp.header.GetLengthInBytes(), len(plaintext))
  assertEqual(t, sp.header.GetSenderSSRC(), uint32(1298231923))

  assertEqual(t, sp.GetSRTCPIndex(), uint32(0x000005d4))
  assertEqual(t, sp.GetE(), true)

  // Check the IV generation
  compareByteArrays(t, sp.GgetGCMIV(salt), iv)

  compareByteArrays(t, sp.GetAAD(), expectedAAD)
  compareByteArrays(t, sp.GetCT(), expectedCT)


  rtcp, err := sp.DecryptGCM(key, salt)
  if err != nil {
    unreachable(t)
  }

  myPlaintext := make([]byte, len(plaintext))
  copy(myPlaintext[:RTCPHeaderSize], sp.header.buffer)
  copy(myPlaintext[RTCPHeaderSize:], sp.payload)

  compareByteArrays(t, myPlaintext, plaintext)

  assertEqual(t, len(rtcp.packets), 1)
}

func TestSRTCPEncryption(t *testing.T) {
  rtcpPacket := new(RTCPPacket)

  rtcpPacket.header.buffer = make([]byte, RTCPHeaderSize)
  copy(rtcpPacket.header.buffer, plaintext[:RTCPHeaderSize])

  rtcpPacket.payload = make([]byte, len(plaintext)-RTCPHeaderSize)
  copy(rtcpPacket.payload, plaintext[RTCPHeaderSize:])

  rtcp := new(RTCPCompoundPacket)
  rtcp.packets = []*RTCPPacket{rtcpPacket}
  rtcp.srtcpIndex = uint32(0x000005d4)

  compareByteArrays(t, rtcp.GetGCMIV(salt), iv)

  srtcp, err := rtcp.EncryptGCM(key, salt)
  if err != nil {
    unreachable(t)
  }

  compareByteArrays(t, srtcp.GetBuffer(), ciphertext)
}
