package rtp

import (
  "fmt"
	"bytes"
	"testing"
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
  if a != b {
    fmt.Printf("actual: %+v\n", a)
    fmt.Printf("expected: %+v\n", b)
		t.Fatalf("%s != %s", a, b)
	}
}

func compareByteArrays(t *testing.T, actual []byte, expected []byte) {
  if !bytes.Equal(actual, expected) {
    t.Fatalf("Known-answer test failed: %x != %x", actual, expected)
  }
}
