package shamir

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/namelesscorp/tvault-core/integrity"
)

type Share struct {
	ID         byte
	Value      []byte
	ProviderID byte
	Signature  []byte
}

func Split(input []byte, n, t int, provider integrity.Provider) ([]Share, error) {
	if t < 2 || t > 255 || n < t || n > 255 {
		return nil, errors.New("invalid threshold or number of shares")
	}

	shareData := make([][]byte, n)
	for i := range shareData {
		shareData[i] = make([]byte, len(input))
	}

	for i, b := range input {
		cfs := make([]byte, t)
		cfs[0] = b

		if _, err := io.ReadFull(rand.Reader, cfs[1:]); err != nil {
			return nil, fmt.Errorf("io read full error; %w", err)
		}

		for j := 1; j <= n; j++ {
			x := byte(j)
			shareData[j-1][i] = evalPoly(cfs, x)
		}
	}

	shares := make([]Share, n)
	for i := 0; i < n; i++ {
		var (
			id  = byte(i + 1)
			val = shareData[i]
		)

		signature, err := provider.Sign(id, val)
		if err != nil {
			return nil, fmt.Errorf("sign share error; %w", err)
		}

		shares[i] = Share{
			ID:         id,
			Value:      val,
			ProviderID: provider.ID(),
			Signature:  signature,
		}
	}

	return shares, nil
}

func Combine(shares []Share, provider integrity.Provider) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("need at least 2 shares")
	}

	var (
		length = len(shares[0].Value)
		res    = make([]byte, length)
	)
	for _, sh := range shares {
		isVerify, err := provider.IsVerify(sh.ID, sh.Value, sh.Signature)
		if err != nil {
			return nil, fmt.Errorf("verify share signature error; %w", err)
		}

		if !isVerify {
			return nil, errors.New("verify share signature failed")
		}
	}

	for i := 0; i < length; i++ {
		var xVals, yVals []byte
		for _, sh := range shares {
			xVals = append(xVals, sh.ID)
			yVals = append(yVals, sh.Value[i])
		}

		res[i] = lagrangeInterpolate(0, xVals, yVals)
	}

	return res, nil
}

func lagrangeInterpolate(x byte, xVals, yVals []byte) byte {
	var (
		res = byte(0)
		n   = len(xVals)
	)
	for i := 0; i < n; i++ {
		var (
			num = byte(1)
			den = byte(1)
		)
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
