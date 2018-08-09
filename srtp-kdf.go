package rtp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	Ke  byte = 0x00
	Ka  byte = 0x01
	Ks  byte = 0x02
	KCe byte = 0x03
	KCa byte = 0x04
	KCs byte = 0x05
)

type KDF struct {
	masterSalt []byte
	block      cipher.Block
}

func NewKDF(masterKey, masterSalt []byte) (*KDF, error) {
	if len(masterSalt) < 14 {
		zero := bytes.Repeat([]byte{0x00}, 14-len(masterSalt))
		masterSalt = append(masterSalt, zero...)
	}

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}

	return &KDF{
		masterSalt: masterSalt,
		block:      block,
	}, nil
}

func (kdf KDF) Derive(label byte, index uint64, size int) []byte {
	indexVal := make([]byte, 6)
	for i := range indexVal {
		indexVal[5-i] = byte(index)
		index >>= 8
	}

	keyID := append([]byte{label}, indexVal...)

	x := make([]byte, len(kdf.masterSalt))
	copy(x, kdf.masterSalt)
	start := len(kdf.masterSalt) - len(keyID)
	for i := range keyID {
		x[start+i] ^= keyID[i]
	}

	zero := bytes.Repeat([]byte{0x00}, kdf.block.BlockSize()-len(x))
	iv := append(x, zero...)

	stream := cipher.NewCTR(kdf.block, iv)

	out := make([]byte, size)
	for i := range out {
		out[i] = 0x00
	}

	stream.XORKeyStream(out, out)
	return out
}

func (kdf KDF) DeriveForStream(cipher CipherID) ([]byte, []byte, []byte, []byte, error) {
	var keySize, saltSize int
	switch cipher {
	case SRTP_AEAD_AES_128_GCM:
		keySize = 16
		saltSize = 12
	case SRTP_AEAD_AES_256_GCM:
		keySize = 32
		saltSize = 12
	default:
		return nil, nil, nil, nil, fmt.Errorf("Unsupported cipher: %04x", cipher)
	}

	rtpKey := kdf.Derive(Ke, 0, keySize)
	rtpSalt := kdf.Derive(Ks, 0, saltSize)
	rtcpKey := kdf.Derive(KCe, 0, keySize)
	rtcpSalt := kdf.Derive(KCs, 0, saltSize)

	return rtpKey, rtpSalt, rtcpKey, rtcpSalt, nil
}
