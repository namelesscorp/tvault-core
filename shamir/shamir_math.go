package shamir

const (
	poly byte = 0x1d // Primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11d) in shortened form
)

var (
	expTable [512]byte
	logTable [256]byte
)

func init() {
	// Correct initialization of logarithm and exponent tables

	// Initialize expTable
	x := byte(1) // start with 1
	for i := 0; i < 255; i++ {
		expTable[i] = x
		// Multiply by 2 (primitive element)
		x = gfMultiply(x, 2)
	}
	for i := 255; i < 512; i++ {
		expTable[i] = expTable[i-255]
	}

	// Initialize logTable
	for i := 0; i < 256; i++ {
		logTable[i] = 255 // Initialize as "undefined"
	}
	for i := 0; i < 255; i++ {
		logTable[expTable[i]] = byte(i)
	}
	logTable[0] = 0 // explicitly set log(0), but avoid using it
}

// Direct multiplication in Galois field without using tables
func gfMultiply(a, b byte) byte {
	var p byte = 0
	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			p ^= a
		}
		highBit := (a & 0x80) != 0
		a <<= 1
		if highBit {
			a ^= poly
		}
		b >>= 1
	}
	return p
}

func gfAdd(a, b byte) byte {
	return a ^ b
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[int(logTable[a])+int(logTable[b])]
}

func xtime(a byte) byte {
	// Multiplication by x in GF(2^8)
	if a&0x80 != 0 {
		return (a << 1) ^ poly
	}
	return a << 1
}

func gfInv(a byte) byte {
	if a == 0 {
		panic("cannot invert 0")
	}
	// Inversion: a^-1 = a^(255-1) = a^254 in GF(2^8)
	return expTable[255-int(logTable[a])]
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero")
	}
	if a == 0 {
		return 0
	}
	// Division: a/b = a * b^-1 = a * b^254
	return expTable[int(logTable[a])+255-int(logTable[b])]
}

func evalPoly(coeffs []byte, x byte) byte {
	// Check for an empty coefficients array
	if len(coeffs) == 0 {
		return 0
	}

	res := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		res = gfMul(res, x)
		res = gfAdd(res, coeffs[i])
	}

	return res
}
