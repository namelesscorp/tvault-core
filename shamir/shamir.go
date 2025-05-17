package shamir

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/namelesscorp/tvault-core/secret"
)

type Share struct {
	ID    byte
	Value secret.Secret
	MAC   [32]byte
}

func computeMAC(id byte, data []byte, key []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte{id})
	h.Write(data)

	var mac [32]byte
	copy(mac[:], h.Sum(nil))

	return mac
}

func Split(input secret.Secret, n, t int, macKey []byte) ([]Share, error) {
	if t < 2 || t > 255 || n < t || n > 255 {
		return nil, errors.New("invalid threshold or number of shares")
	}

	secretBytes := input.Bytes()
	defer input.Destroy()

	shareData := make([][]byte, n)
	for i := range shareData {
		shareData[i] = make([]byte, len(secretBytes))
	}

	for i, b := range secretBytes {
		cfs := make([]byte, t)
		cfs[0] = b

		if _, err := io.ReadFull(rand.Reader, cfs[1:]); err != nil {
			return nil, err
		}

		for j := 1; j <= n; j++ {
			x := byte(j)
			shareData[j-1][i] = evalPoly(cfs, x)
		}
	}

	shares := make([]Share, n)
	for i := 0; i < n; i++ {
		val := secret.New(shareData[i])
		shares[i] = Share{
			ID:    byte(i + 1),
			Value: val,
			MAC:   computeMAC(byte(i+1), val.Bytes(), macKey),
		}
	}

	return shares, nil
}

func Combine(shares []Share, macKey []byte) (secret.Secret, error) {
	if len(shares) < 2 {
		return nil, errors.New("need at least 2 shares")
	}

	length := shares[0].Value.Len()
	res := make([]byte, length)

	for _, sh := range shares {
		expectedMAC := computeMAC(sh.ID, sh.Value.Bytes(), macKey)

		if !hmac.Equal(expectedMAC[:], sh.MAC[:]) {
			return nil, errors.New("MAC mismatch on share")
		}
	}

	for i := 0; i < length; i++ {
		var xVals, yVals []byte
		for _, sh := range shares {
			xVals = append(xVals, sh.ID)
			yVals = append(yVals, sh.Value.Bytes()[i])
		}

		res[i] = lagrangeInterpolate(0, xVals, yVals)
	}

	return secret.New(res), nil
}

func lagrangeInterpolate(x byte, xVals, yVals []byte) byte {
	res := byte(0)
	n := len(xVals)
	for i := 0; i < n; i++ {
		num := byte(1)
		den := byte(1)
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}

			num = gfMul(num, gfAdd(x, xVals[j]))
			den = gfMul(den, gfAdd(xVals[i], xVals[j]))
		}

		term := gfMul(yVals[i], gfDiv(num, den))
		res = gfAdd(res, term)
	}

	return res
}
