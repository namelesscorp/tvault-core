package shamir

import (
	"testing"
)

// Benchmark for addition operation in Galois field
func BenchmarkGFAdd(b *testing.B) {
	b.ReportAllocs()
	a, c := byte(0x53), byte(0xCA)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = gfAdd(a, c)
	}
}

// Benchmark for multiplication operation in Galois field (using tables)
func BenchmarkGFMul(b *testing.B) {
	b.ReportAllocs()
	a, c := byte(0x53), byte(0xCA)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = gfMul(a, c)
	}
}

// Benchmark for direct multiplication in Galois field (without using tables)
func BenchmarkGFMultiply(b *testing.B) {
	b.ReportAllocs()
	a, c := byte(0x53), byte(0xCA)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = gfMultiply(a, c)
	}
}

// Comparison of table-based and direct multiplication
func BenchmarkGFMulComparison(b *testing.B) {
	b.Run("Tabled", func(b *testing.B) {
		b.ReportAllocs()
		a, c := byte(0x53), byte(0xCA)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = gfMul(a, c)
		}
	})

	b.Run("Direct", func(b *testing.B) {
		b.ReportAllocs()
		a, c := byte(0x53), byte(0xCA)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = gfMultiply(a, c)
		}
	})
}

// Benchmark for division operation in Galois field
func BenchmarkGFDiv(b *testing.B) {
	b.ReportAllocs()
	a, c := byte(0x53), byte(0xCA)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = gfDiv(a, c)
	}
}

// Benchmark for inversion operation in Galois field
func BenchmarkGFInv(b *testing.B) {
	b.ReportAllocs()
	a := byte(0x53)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = gfInv(a)
	}
}

// Benchmark for xtime function
func BenchmarkXtime(b *testing.B) {
	b.ReportAllocs()
	a := byte(0x53)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = xtime(a)
	}
}

// Benchmark for polynomial evaluation of different degrees
func BenchmarkEvalPoly(b *testing.B) {
	// Polynomial of degree 1 (linear)
	b.Run("Degree1", func(b *testing.B) {
		b.ReportAllocs()
		coeffs := []byte{0x03, 0x02}
		x := byte(0x05)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = evalPoly(coeffs, x)
		}
	})

	// Polynomial of degree 2 (quadratic)
	b.Run("Degree2", func(b *testing.B) {
		b.ReportAllocs()
		coeffs := []byte{0x01, 0x02, 0x03}
		x := byte(0x05)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = evalPoly(coeffs, x)
		}
	})

	// High degree polynomial (10)
	b.Run("Degree10", func(b *testing.B) {
		b.ReportAllocs()
		coeffs := make([]byte, 11)
		for i := range coeffs {
			coeffs[i] = byte(i + 1)
		}
		x := byte(0x05)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = evalPoly(coeffs, x)
		}
	})
}

// Benchmark for Lagrange interpolation
func BenchmarkLagrangeInterpolate(b *testing.B) {
	// Interpolation with 3 points
	b.Run("3Points", func(b *testing.B) {
		b.ReportAllocs()
		xVals := []byte{0x01, 0x02, 0x03}
		yVals := []byte{0x10, 0x20, 0x30}
		x := byte(0x00)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = lagrangeInterpolate(x, xVals, yVals)
		}
	})

	// Interpolation with 5 points
	b.Run("5Points", func(b *testing.B) {
		b.ReportAllocs()
		xVals := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		yVals := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
		x := byte(0x00)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = lagrangeInterpolate(x, xVals, yVals)
		}
	})

	// Interpolation with 10 points
	b.Run("10Points", func(b *testing.B) {
		b.ReportAllocs()
		xVals := make([]byte, 10)
		yVals := make([]byte, 10)
		for i := 0; i < 10; i++ {
			xVals[i] = byte(i + 1)
			yVals[i] = byte((i + 1) * 10)
		}
		x := byte(0x00)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_ = lagrangeInterpolate(x, xVals, yVals)
		}
	})
}
