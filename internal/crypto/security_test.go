package crypto

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// TestDoSStream checks if large chunk sizes are rejected
func TestDoSStream(t *testing.T) {
	// Create a buffer with malicious chunk length
	buf := new(bytes.Buffer)
	
	// Write File Salt (16 bytes)
	saltBytes := make([]byte, 16)
	buf.Write(saltBytes)

	// Write Malicious Chunk Length (e.g. 100MB)
	binary.Write(buf, binary.BigEndian, uint32(100*1024*1024))
	
	// Call DecryptStream
	out := new(bytes.Buffer)
	password := []byte("password")
	salt := make([]byte, 16)
	
	err := DecryptStream(buf, out, password, salt)
	if err == nil {
		t.Fatal("Expected error for huge chunk size, got nil")
	}
	
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("Expected 'too large' error, got: %v", err)
	}
}

// TestSaltUniqueness ensures different salts produce different ciphertext
func TestSaltUniqueness(t *testing.T) {
	password := []byte("password")
	data := []byte("secret data")
	
	salt1, _ := GenerateSalt()
	salt2, _ := GenerateSalt()
	
	// Encrypt with salt1
	c1, _, _ := Encrypt(data, password, salt1)
	
	// Encrypt with salt2
	c2, _, _ := Encrypt(data, password, salt2)
	
	if bytes.Equal(c1, c2) {
		t.Fatal("Ciphertext should be different with different salts")
	}
}
