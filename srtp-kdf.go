package rtp

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	Ke byte = 0x00
	Ka byte = 0x01
	Ks byte = 0x02
)

type KDF struct {
	masterSalt []byte
	block      cipher.Block
}

func NewKDF(masterKey, masterSalt []byte) (*KDF, error) {
	if len(masterSalt) != 14 {
		return nil, fmt.Errorf("SRTP master salt must be 14 bytes long")
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

// TODO - why is roc 64 bits not 32

func (kdf KDF) Derive(label byte, roc uint64, seq uint16, size int) []byte {
	indexVal := (roc << 16) + uint64(seq)
	index := make([]byte, 6)
	for i := range index {
		index[5-i] = byte(indexVal)
		indexVal >>= 8
	}

	keyID := append([]byte{label}, index...)

	x := make([]byte, len(kdf.masterSalt))
	copy(x, kdf.masterSalt)
	start := len(kdf.masterSalt) - len(keyID)
	for i := range keyID {
		x[start+i] ^= keyID[i]
	}

	iv := append(x, []byte{0x00, 0x00}...)
	stream := cipher.NewCTR(kdf.block, iv)

	out := make([]byte, size)
	for i := range out {
		out[i] = 0x00
	}

	stream.XORKeyStream(out, out)
	return out
}
