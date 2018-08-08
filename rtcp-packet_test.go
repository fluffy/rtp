package rtp

import (
	"encoding/hex"
	"testing"
)


func TestRTCPConstructGet(t *testing.T) {
  p := NewRTCPPacket(RTCPTypeSR/*pt*/, 1 /*length*/, 0xbcdc0094/*sender ssrc*/, []byte{1, 2, 3, 4} /*payload*/)

  assertEqual(t, p.header.GetPT(), RTCPTypeSR)
  assertEqual(t, p.header.GetLength(), uint16(1))
  assertEqual(t, p.header.GetSenderSSRC(), uint32(0xbcdc0094))
}

func TestRTCPSet(t *testing.T) {
  p := NewRTCPPacket(RTCPTypeSR /*pt*/, 1 /*length*/, 0xbcdc0094/*sender ssrc*/, []byte{1, 2, 3, 4} /*payload*/)

  p.header.SetPT(RTCPTypeRR)
  p.header.SetLength(1)
  p.header.SetSenderSSRC(0xbcdc1010)

  assertEqual(t, p.header.GetPT(), RTCPTypeRR)
  assertEqual(t, p.header.GetLength(), uint16(1))
  assertEqual(t, p.header.GetSenderSSRC(), uint32(0xbcdc1010))
}

// Data from https://tools.ietf.org/html/rfc7714#section-17.2

var salt, _ = hex.DecodeString("517569642070726f2071756f")

var key, _ = hex.DecodeString("000102030405060708090a0b0c0d0e0f" +
                        "101112131415161718191a1b1c1d1e1f")


var plaintext, _  = hex.DecodeString("81c8000d4d6172734e5450314e545032" +
                                     "525450200000042a0000e9304c756e61" +
                                     "deadbeefdeadbeefdeadbeefdeadbeef" +
                                     "deadbeef")

var ciphertext, _ = hex.DecodeString("81c8000d4d617273d50ae4d1f5ce5d304ba297e47d470c28" +
                                     "2c3ece5dbffe0a50a2eaa5c1110555be8415f658c61de047" +
                                     "6f1b6fad1d1eb30c4446839f57ff6f6cb26ac3be800005d4")

var iv, _ = hex.DecodeString("517524055203726f207170bb")

func TestSRTCPDecryption(t *testing.T) {
  expectedAAD, _ := hex.DecodeString("81c8000d4d617273800005d4")

  expectedCT, _ := hex.DecodeString("d50ae4d1f5ce5d304ba297e47d470c28" +
                                    "2c3ece5dbffe0a50a2eaa5c1110555be" +
                                    "8415f658c61de0476f1b6fad1d1eb30c" +
                                    "4446839f57ff6f6cb26ac3be")

  myCiphertext := make([]byte, len(ciphertext))
  copy(myCiphertext, ciphertext)

  sp, err := NewSRTCPPacket(myCiphertext)
  if err != nil {
    t.Errorf("Failed to construct SRTCP packet")
  }

  assertEqual(t, sp.header.GetPT(), RTCPTypeSR)
  assertEqual(t, sp.header.GetLength(), uint16(13))
  assertEqual(t, sp.header.GetSenderSSRC(), uint32(1298231923))

  assertEqual(t, sp.GetSRTCPIndex(), uint32(0x000005d4))
  assertEqual(t, sp.GetE(), true)

  // Check the IV generation
  compareByteArrays(t, sp.gcmIV(salt), iv)

  compareByteArrays(t, sp.getAAD(), expectedAAD)
  compareByteArrays(t, sp.buffer, expectedCT)


  err = sp.DecryptGCM(key, salt)
  if err != nil {
    t.Errorf("Failed to decrypt SRTCP packet")
  }

  myPlaintext := make([]byte, len(plaintext))
  copy(myPlaintext[:rtcpHeaderSize], sp.header.buffer)
  copy(myPlaintext[rtcpHeaderSize:], sp.buffer)

  compareByteArrays(t, myPlaintext, plaintext)
}

func TestSRTCPEncryption(t *testing.T) {
  p, err := NewRTCPCompoundPacket(plaintext, uint32(0x000005d4))
  if err != nil {
    t.Errorf("Failed to build SRTCP packet")
  }

  compareByteArrays(t, p.gcmIV(salt), iv)

  err = p.EncryptGCM(key, salt)
  if err != nil {
    t.Errorf("Failed to encrypt SRTCP packet")
  }

  compareByteArrays(t, p.GetBuffer(), ciphertext)
}
