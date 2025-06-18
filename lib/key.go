package lib

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

const (
	// Iterations - numbers of rounds for PBKDF2
	Iterations = 100_000

	KeyLen = 32

	hLen = sha256.Size // 32 bytes
)

// PBKDF2Key - derives a key using PBKDF2‑HMAC‑SHA256 (RFC 8018).
// secret data  - user passphrase
// salt.        - 16‑byte random value stored in header
// iterations   - cost factor (>= 100k recommended)
// keyLen       - desired output length in bytes
func PBKDF2Key(data, salt []byte, iterations, keyLen int) []byte {
	var (
		blocks  = (keyLen + hLen - 1) / hLen // ceil(keyLen / hLen)
		derived = make([]byte, 0, blocks*hLen)
	)
	for blockIdx := 1; blockIdx <= blocks; blockIdx++ {
		// U1 = HMAC(P, S || INT(blockIdx))
		mac := hmac.New(sha256.New, data)
		mac.Write(salt)
		mac.Write(uint32ToBytes(uint32(blockIdx)))
		ui := mac.Sum(nil)

		// Ti = U1 ^ U2 ^ ... ^ Uc
		ti := make([]byte, hLen)
		copy(ti, ui)

		for i := 1; i < iterations; i++ {
			mac.Reset()
			mac.Write(ui)
			ui = mac.Sum(nil)

			for j := 0; j < hLen; j++ {
				ti[j] ^= ui[j]
			}
		}

		derived = append(derived, ti...)
	}

	return derived[:keyLen]
}

func uint32ToBytes(i uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], i)
	return b[:]
}
