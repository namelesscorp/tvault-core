package shamir

import (
	"testing"
)

func TestGaloisFieldOperations(t *testing.T) {
	// Test GF addition
	t.Run("GF Addition", func(t *testing.T) {
		testCases := []struct {
			a, b, expected byte
		}{
			{0x00, 0x00, 0x00},
			{0xFF, 0x00, 0xFF},
			{0x00, 0xFF, 0xFF},
			{0x0A, 0x0F, 0x05},
			{0x53, 0xCA, 0x99},
		}

		for _, tc := range testCases {
			result := gfAdd(tc.a, tc.b)
			if result != tc.expected {
				t.Errorf("gfAdd(%#02x, %#02x) = %#02x, expected %#02x", tc.a, tc.b, result, tc.expected)
			}
		}
	})

	// Test GF multiplication
	t.Run("GF Multiplication", func(t *testing.T) {
		// Test basic cases and compare with direct multiplication
		for a := byte(1); a < 10; a++ {
			for b := byte(1); b < 10; b++ {
				direct := gfMultiply(a, b)
				tabled := gfMul(a, b)

				if direct != tabled {
					t.Errorf("gfMul(%#02x, %#02x) = %#02x, but direct calculation gives %#02x",
						a, b, tabled, direct)
				}
			}
		}

		// Special cases
		if gfMul(0, 5) != 0 {
			t.Errorf("gfMul(0, 5) should be 0")
		}

		if gfMul(5, 0) != 0 {
			t.Errorf("gfMul(5, 0) should be 0")
		}
	})

	// Test GF division
	t.Run("GF Division", func(t *testing.T) {
		for a := byte(1); a < 10; a++ {
			for b := byte(1); b < 10; b++ {
				quotient := gfDiv(a, b)
				// Check: a / b * b = a
				product := gfMul(quotient, b)

				if product != a {
					t.Errorf("gfDiv(%#02x, %#02x) = %#02x, but gfMul(%#02x, %#02x) = %#02x, expected %#02x",
						a, b, quotient, quotient, b, product, a)
				}
			}
		}
	})

	// Test GF inversion
	t.Run("GF Inversion", func(t *testing.T) {
		for a := byte(1); a < 10; a++ {
			inv := gfInv(a)
			product := gfMul(a, inv)

			if product != 1 {
				t.Errorf("gfInv(%#02x) = %#02x, but gfMul(%#02x, %#02x) = %#02x, expected 0x01",
					a, inv, a, inv, product)
			}
		}

		// Test panic on zero inversion
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("gfInv(0) should panic")
			}
		}()
		gfInv(0)
	})

	// Test xtime function
	t.Run("xtime Function", func(t *testing.T) {
		testCases := []struct {
			a byte
		}{
			{0x00},
			{0x01},
			{0x02},
			{0x80},
			{0x81},
			{0xFF},
		}

		for _, tc := range testCases {
			// Calculate expected result directly from implementation
			var expected byte
			if tc.a&0x80 != 0 {
				expected = (tc.a << 1) ^ poly
			} else {
				expected = tc.a << 1
			}

			result := xtime(tc.a)
			if result != expected {
				t.Errorf("xtime(%#02x) = %#02x, expected %#02x", tc.a, result, expected)
			}
		}
	})

	// Test polynomial evaluation
	t.Run("Polynomial Evaluation", func(t *testing.T) {
		// Check simple cases
		if evalPoly([]byte{5}, 10) != 5 {
			t.Errorf("Constant polynomial should return the constant")
		}

		// Linear polynomial: 3 + 2x at x=4
		linear := []byte{3, 2}
		expectedLinear := gfAdd(3, gfMul(2, 4))
		if evalPoly(linear, 4) != expectedLinear {
			t.Errorf("evalPoly([3, 2], 4) = %#02x, expected %#02x", evalPoly(linear, 4), expectedLinear)
		}

		// Quadratic polynomial: 1 + 2x + 3x² at x=5
		quadratic := []byte{1, 2, 3}
		x := byte(5)
		// Calculate manually: 3*5² + 2*5 + 1
		x2 := gfMul(x, x)
		term1 := gfMul(3, x2)
		term2 := gfMul(2, x)
		expectedQuadratic := gfAdd(gfAdd(term1, term2), 1)

		if evalPoly(quadratic, x) != expectedQuadratic {
			t.Errorf("evalPoly([1, 2, 3], 5) = %#02x, expected %#02x",
				evalPoly(quadratic, x), expectedQuadratic)
		}
	})

	// Test log and exp tables consistency
	t.Run("Log and Exp Tables Consistency", func(t *testing.T) {
		// Check property: exp(log(x)) = x for all non-zero x
		for x := byte(1); x != 0; x++ {
			if x == 0 {
				continue // Skip x=0 as log(0) is undefined
			}

			logX := logTable[x]
			expLogX := expTable[logX]

			if expLogX != x {
				t.Errorf("exp(log(%#02x)) = %#02x, expected %#02x", x, expLogX, x)
			}
		}
	})
}
