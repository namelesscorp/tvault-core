package secret

import "testing"

func BenchmarkNew(b *testing.B) {
	data := []byte("benchmark-secret")
	for i := 0; i < b.N; i++ {
		sec := New(data)
		_ = sec.Bytes()
	}
}

func BenchmarkEqual(b *testing.B) {
	sec := New([]byte("benchmark-secret"))
	other := []byte("benchmark-secret")
	for i := 0; i < b.N; i++ {
		_ = sec.Equal(other)
	}
}

func BenchmarkDestroy(b *testing.B) {
	data := []byte("destroy-me")
	for i := 0; i < b.N; i++ {
		sec := New(data)
		sec.Destroy()
	}
}
