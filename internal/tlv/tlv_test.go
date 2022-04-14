package tlv_test

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wollac/async.go/internal/tlv"
)

type message []byte

func (d message) MarshalBinary() ([]byte, error) { return d, nil }

func TestTLV(t *testing.T) {
	r := tlv.New()

	var testData message
	r.Register(0, testData, func(data []byte) error {
		require.Equal(t, data, []byte(testData))
		return nil
	})

	var buf bytes.Buffer
	for i := 0; i < 16; i++ {
		testData = make([]byte, 1<<i)
		rand.Read(testData)

		require.NoError(t, r.Write(&buf, testData))
		require.NoError(t, r.Handle(&buf))
	}
}

func BenchmarkHandle(b *testing.B) {
	r := tlv.New()

	var buf bytes.Buffer
	r.Register(0, message{}, func([]byte) error { return nil })
	if err := r.Write(&buf, message(bytes.Repeat([]byte{0xff}, 1024))); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = r.Handle(bytes.NewReader(buf.Bytes()))
	}
}

func BenchmarkWriteBinary(b *testing.B) {
	tlv.New().Register(0, &message{}, func([]byte) error { return nil })
	data := bytes.Repeat([]byte{0xff}, 1024)
	b.ResetTimer()

	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = tlv.WriteBinary(&buf, 0, data)
	}
}

func BenchmarkWrite(b *testing.B) {
	r := tlv.New()

	r.Register(0, message{}, func([]byte) error { return nil })
	msg := message(bytes.Repeat([]byte{0xff}, 1024))
	b.ResetTimer()

	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = r.Write(&buf, msg)
	}
}
