package acss

import (
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/wollac/async.go/pgk/config"
	"github.com/wollac/async.go/pgk/rbc"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

var suite = suites.MustFind("ed25519")

func TestSingle(t *testing.T) {
	selfs, peers := generateKeys("A")
	conf := config.NewConfig(selfs[0], peers...)
	acss := New(conf, suite, "A")
	secret := suite.Scalar().Pick(suite.RandomStream())
	acss.Input(secret)
	s := <-acss.Output()
	require.Equal(t, secret, s.V)
	require.NoError(t, acss.Close())
}

func TestTermination(t *testing.T) {
	selfs, peers := generateKeys("A", "B", "C", "D")
	nodes := map[string]*ACSS{}
	for _, self := range selfs {
		conf := config.NewConfig(self, peers...)
		nodes[self.ID] = New(conf, suite, "A")
		defer nodes[self.ID].Close()
	}

	for id, node := range nodes {
		id, node := id, node
		go func() {
			for msg := range node.Messages() {
				receiver, payload := nodes[msg.Receiver], msg.Payload
				go func() {
					time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
					if !receiver.Stopped() {
						t.Logf("%s->%s: %s", id, receiver.conf.Self().ID, payload.Type)
						require.NoError(t, receiver.Handle(id, payload))
					}
				}()
			}
		}()
	}

	secret := suite.Scalar().Pick(suite.RandomStream())
	nodes["A"].Input(secret)

	var shares []*share.PriShare
	for _, node := range nodes {
		shares = append(shares, <-node.Output())
	}
	recoverSecret, err := share.RecoverSecret(suite, shares, 2, 4)
	require.NoError(t, err)
	require.Equal(t, secret, recoverSecret)
}

func TestReveal(t *testing.T) {
	selfs, peers := generateKeys("A", "B", "C", "D")
	nodes := map[string]*ACSS{}
	for _, self := range selfs {
		conf := config.NewConfig(self, peers...)
		nodes[self.ID] = New(conf, suite, "A")
		defer nodes[self.ID].Close()
	}

	for id, node := range nodes {
		id, node := id, node
		go func() {
			for msg := range node.Messages() {
				receiver, payload := nodes[msg.Receiver], msg.Payload
				if payload.Type == RBC {
					rbcMessage := &rbc.Message{}
					require.NoError(t, rbcMessage.UnmarshalBinary(payload.Data))
					if rbcMessage.Type == rbc.Propose {
						rbcMessage.Data[len(rbcMessage.Data)-1]++
					}
				}
				go func() {
					time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
					if !receiver.Stopped() {
						t.Logf("%s->%s: %s", id, receiver.conf.Self().ID, payload.Type)
						require.NoError(t, receiver.Handle(id, payload))
					}
				}()
			}
		}()
	}

	secret := suite.Scalar().Pick(suite.RandomStream())
	nodes["A"].Input(secret)

	var shares []*share.PriShare
	for _, node := range nodes {
		shares = append(shares, <-node.Output())
	}
	recoverSecret, err := share.RecoverSecret(suite, shares, 2, 4)
	require.NoError(t, err)
	require.Equal(t, secret, recoverSecret)
}

func generateKeys(ids ...string) (selfs []config.SelfInfo, peers []config.PeerInfo) {
	for _, id := range ids {
		s := suite.Scalar().Pick(suite.RandomStream())
		p := suite.Point().Mul(s, nil)
		selfs = append(selfs, config.SelfInfo{ID: id, PrivKey: s})
		peers = append(peers, config.PeerInfo{ID: id, PubKey: p})
	}
	return
}
