package rtp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// From https://tools.ietf.org/html/rfc3711#appendix-B.3
func TestKDF(t *testing.T) {
	masterKeyHex := "E1F97A0D3E018BE0D64FA32C06DE4139"
	masterSaltHex := "0EC675AD498AFEEBB6960B3AABE6"
	cipherKeyHex := "C61E7A93744F39EE10734AFE3FF7A087"
	cipherSaltHex := "30CBBC08863D8C85D49DB34A9AE1"

	cipherKeySize := 16
	cipherSaltSize := 14

	masterKey, _ := hex.DecodeString(masterKeyHex)
	masterSalt, _ := hex.DecodeString(masterSaltHex)
	cipherKey, _ := hex.DecodeString(cipherKeyHex)
	cipherSalt, _ := hex.DecodeString(cipherSaltHex)

	kdf, err := NewKDF(masterKey, masterSalt)
	if err != nil {
		t.Fatalf("Error creating KDF")
	}

	cipherKeyTest := kdf.Derive(Ke, 0, cipherKeySize)
	if !bytes.Equal(cipherKeyTest, cipherKey) {
		t.Fatalf("Incorrect cipher key: %x != %x", cipherKeyTest, cipherKey)
	}

	cipherSaltTest := kdf.Derive(Ks, 0, cipherSaltSize)
	if !bytes.Equal(cipherSaltTest, cipherSalt) {
		t.Fatalf("Incorrect cipher salt: %x != %x", cipherSaltTest, cipherSalt)
	}

}
