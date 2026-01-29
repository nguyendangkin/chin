package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

const (
	ChunkSize = 64 * 1024 // 64KB chunks
)

// EncryptStream encrypts data from r to w using the given password and master salt.
// Format:
// [FileSalt 16 bytes]
// [Chunk 1: Length (4 bytes) + Ciphertext + Tag]
// ...
// [Chunk N: Length (4 bytes) + Ciphertext + Tag]
// [Terminator: Length 0 (4 bytes)]
func EncryptStream(r io.Reader, w io.Writer, password []byte, masterSalt []byte) error {
	// 1. Derive Master Key from Password + MasterSalt (Slow, done once per archive, but here we do it per file context effectively if not cached. 
	// Optimization: Caller could pass MasterKey, but for now we follow existing API signature which passes password/salt)
	masterKey := DeriveKey(password, masterSalt)

	// 2. Generate File Salt (Random 16 bytes)
	fileSalt, err := GenerateSalt()
	if err != nil {
		return err
	}

	// 3. Write File Salt to stream header
	if _, err := w.Write(fileSalt); err != nil {
		return err
	}

	// 4. Derive File Key (Fast)
	fileKey, err := DeriveStreamKey(masterKey, fileSalt)
	if err != nil {
		return err
	}

	// 5. Setup GCM
	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	buf := make([]byte, ChunkSize)
	chunkIndex := uint64(0)
	nonce := make([]byte, NonceSize) // 12 bytes, initialized to 0

	for {
		n, err := r.Read(buf)
		if n > 0 {
			// update nonce for this chunk (Big Endian Counter)
			// We can use the first 8 bytes or last 8 bytes. Standard GCM uses last 4 bytes as counter, but here we control the whole nonce.
			// Let's use the last 8 bytes for counter to support massive streams.
			binary.BigEndian.PutUint64(nonce[4:], chunkIndex)

			// Encrypt
			ciphertext := gcm.Seal(nil, nonce, buf[:n], nil)

			// Write ciphertext length
			err := binary.Write(w, binary.BigEndian, uint32(len(ciphertext)))
			if err != nil {
				return err
			}

			if _, err := w.Write(ciphertext); err != nil {
				return err
			}

			chunkIndex++
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	// Write terminator (0-length chunk)
	if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
		return err
	}

	return nil
}

// DecryptStream decrypts data from r to w using the given password and master salt.
func DecryptStream(r io.Reader, w io.Writer, password []byte, masterSalt []byte) error {
	masterKey := DeriveKey(password, masterSalt)

	// 1. Read File Salt
	fileSalt := make([]byte, SaltSize)
	if _, err := io.ReadFull(r, fileSalt); err != nil {
		return err
	}

	// 2. Derive File Key
	fileKey, err := DeriveStreamKey(masterKey, fileSalt)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(fileKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	chunkIndex := uint64(0)
	nonce := make([]byte, NonceSize) // Init 0
	
	// Max allowed chunk size check
	const MaxChunkSize = ChunkSize + 256 

	for {
		// Read chunk length
		var length uint32
		err := binary.Read(r, binary.BigEndian, &length)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		
		if length == 0 {
			break // Terminator
		}

		if length > MaxChunkSize {
			return errors.New("chunk size too large: potential DoS attack")
		}

		// Read ciphertext
		ciphertext := make([]byte, length)
		if _, err := io.ReadFull(r, ciphertext); err != nil {
			return err
		}

		// Update nonce
		binary.BigEndian.PutUint64(nonce[4:], chunkIndex)

		// Decrypt
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return errors.New("decryption failed or invalid password")
		}

		if _, err := w.Write(plaintext); err != nil {
			return err
		}

		chunkIndex++
	}

	return nil
}
