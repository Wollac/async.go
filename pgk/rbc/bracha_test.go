package rbc

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/wollac/async.go/pgk/config"
)

var testData = []byte{0xff}

func TestSingle(t *testing.T) {
	conf := config.NewConfig(config.SelfInfo{ID: "A"}, config.PeerInfo{ID: "A"})
	rbc := New(conf, "A", len(testData), nil)
	rbc.Input(testData)
	require.Equal(t, testData, <-rbc.Output())
	require.NoError(t, rbc.Close())
}

/*
func TestTermination(t *testing.T) {
	conf := config.NewConfig(config.PeerInfo{ID: "A"}, config.PeerInfo{ID: "B"}, config.PeerInfo{ID: "C"}, config.PeerInfo{ID: "D"})
	rbcs := map[string]*RBC{}
	for _, peer := range conf.IDs() {
		rbcs[peer] = New(conf, peer, "A", len(testData), nil)
		defer rbcs[peer].Close()
	}

	for sender, rbc := range rbcs {
		sender, rbc := sender, rbc
		go func() {
			for msg := range rbc.Messages() {
				rbc, payload := rbcs[msg.Receiver], msg.Payload
				go func() {
					time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
					require.NoError(t, rbc.Handle(sender, payload))
				}()
			}
		}()
	}

	rbcs["A"].Input(testData)
	for _, rbc := range rbcs {
		require.Equal(t, testData, <-rbc.Output())
	}
}

func BenchmarkBracha(b *testing.B) {
	conf := config.NewConfig(config.PeerInfo{ID: "A"}, config.PeerInfo{ID: "B"})
	link := func(s, d *RBC) {
		for msg := range s.Messages() {
			d.Handle(s.self, msg.Payload)
		}
	}
	b.ResetTimer()

	var data [4]byte
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		rbcA := New(conf, "A", "A", len(data), nil)
		rbcB := New(conf, "B", "A", len(data), nil)
		go link(rbcA, rbcB)
		go link(rbcB, rbcA)
		b.StartTimer()

		binary.LittleEndian.PutUint32(data[:], uint32(i))
		rbcA.Input(data[:])
		<-rbcA.Output()
		<-rbcB.Output()

		b.StopTimer()
		rbcA.Close()
		rbcB.Close()
		b.StartTimer()
	}
}
*/
