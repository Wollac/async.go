package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3"
)

var (
	G = suite.Point().Base()
	H = suite.Point().Mul(suite.Scalar().SetInt64(2), G)
)

func TestDLEQ(t *testing.T) {
	S1, S2 := suite.Point().Mul(secret, G), suite.Point().Mul(secret, H)

	t.Logf("proof that log_{G}(%s) == log_{H}(%s) == %s", S1, S2, secret)
	p := proveDLEQ(suite, G, H, secret)
	require.True(t, verifyDLEQ(suite, G, H, S1, S2, p))

	// it must not validate for different points
	require.False(t, verifyDLEQ(suite, G, H, S1, H, p))
	require.False(t, verifyDLEQ(suite, G, H, G, S2, p))
}

func TestImplicate(t *testing.T) {
	private := suite.Scalar().SetInt64(42)
	public := suite.Point().Mul(private, G)

	data := Implicate(suite, H, private)
	require.Len(t, data, ImplicateLen(suite))

	implicate, err := CheckImplicate(suite, H, public, data)
	require.NoError(t, err)
	require.Equal(t, Secret(suite, H, private), implicate)
}

func BenchmarkDLEQ(b *testing.B) {
	type test struct {
		P1 kyber.Point
		P2 kyber.Point
		p  proof
	}
	tests := make([]test, b.N)
	for i := range tests {
		secret := suite.Scalar().Pick(suite.RandomStream())
		tests[i].P1, tests[i].P2 = suite.Point().Mul(secret, G), suite.Point().Mul(secret, H)
		tests[i].p = proveDLEQ(suite, G, H, secret)
	}
	b.ResetTimer()

	for _, p := range tests {
		_ = verifyDLEQ(suite, G, H, p.P1, p.P2, p.p)
	}
}

func BenchmarkImplicate(b *testing.B) {
	privates := make([]kyber.Scalar, b.N)
	for i := range privates {
		privates[i] = suite.Scalar().SetInt64(int64(i))
	}
	b.ResetTimer()

	for i := range privates {
		_ = Implicate(suite, H, privates[i])
	}
}

func BenchmarkCheckImplicate(b *testing.B) {
	publics := make([]kyber.Point, b.N)
	data := make([][]byte, b.N)
	for i := 0; i < b.N; i++ {
		private := suite.Scalar().SetInt64(42)
		publics[i] = suite.Point().Mul(private, G)
		data[i] = Implicate(suite, H, private)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := CheckImplicate(suite, H, publics[i], data[i]); err != nil {
			b.Fatal(err)
		}
	}
}
