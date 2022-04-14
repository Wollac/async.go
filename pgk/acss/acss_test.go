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
	out := <-acss.Output()
	require.NotNil(t, out)
	require.Equal(t, secret, out.V)
	require.NoError(t, acss.Close())
}

func TestTermination(t *testing.T) {
	nodes, shutdown := createNodes("A", "A", "B", "C", "D")
	defer shutdown()
	// link the nodes by handling each other's messages
	for id, node := range nodes {
		id, node := id, node
		go func() {
			for msg := range node.Messages() {
				go handle(t, id, nodes[msg.Receiver], msg.Payload)
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
	nodes, shutdown := createNodes("A", "A", "B", "C", "D")
	defer shutdown()

	for id, node := range nodes {
		id, node := id, node
		go func() {
			for msg := range node.Messages() {
				// modify RBC-PROPOSE messages so that the signatures are invalid
				if msg.Payload.Type == RBC {
					rbcMessage := &rbc.Message{}
					require.NoError(t, rbcMessage.UnmarshalBinary(msg.Payload.Data))
					if rbcMessage.Type == rbc.Propose {
						rbcMessage.Data[len(rbcMessage.Data)-1]++
					}
				}
				go handle(t, id, nodes[msg.Receiver], msg.Payload)
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

func handle(t *testing.T, srcID string, dst *ACSS, message *Message) {
	time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
	if !dst.Stopped() {
		t.Logf("%s->%s: %s", srcID, dst.conf.Self().ID, message.Type)
		require.NoError(t, dst.Handle(srcID, message))
	}
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

func createNodes(dealer string, ids ...string) (map[string]*ACSS, func()) {
	selfs, peers := generateKeys(ids...)
	nodes := map[string]*ACSS{}
	for _, self := range selfs {
		conf := config.NewConfig(self, peers...)
		nodes[self.ID] = New(conf, suite, dealer)
	}
	shutdown := func() {
		for _, node := range nodes {
			_ = node.Close()
		}
	}
	return nodes, shutdown
}
