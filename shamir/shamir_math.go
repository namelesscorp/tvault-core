package shamir

var (
	expTable [512]byte
	logTable [256]byte
)

func init() {
	x := byte(1)
	for i := 0; i < 255; i++ {
		expTable[i] = x
		logTable[x] = byte(i)
		x = gfMul(x, 0x03)
	}

	for i := 255; i < 512; i++ {
		expTable[i] = expTable[i-255]
	}
}

func gfAdd(a, b byte) byte {
	return a ^ b
}

func gfMul(a, b byte) byte {
	var p byte = 0
	for i := 0; i < 8; i++ {
		mask := byte(-(int(b) & 1))
		p ^= a & mask
		a = xtime(a)
		b >>= 1
	}
	return p
}

func xtime(a byte) byte {
	if a&0x80 != 0 {
		return (a << 1) ^ 0x1d
	}

	return a << 1
}

func gfInv(a byte) byte {
	if a == 0 {
		panic("cannot invert 0")
	}

	return expTable[255-int(logTable[a])]
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero")
	}

	if a == 0 {
		return 0
	}

	return expTable[int(logTable[a])+255-int(logTable[b])]
}

func evalPoly(coeffs []byte, x byte) byte {
	res := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		res = gfMul(res, x)
		res = gfAdd(res, coeffs[i])
	}

	return res
}
