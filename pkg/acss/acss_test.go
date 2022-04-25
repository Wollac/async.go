package acss

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/asaskevich/EventBus"
	"github.com/stretchr/testify/require"
	"github.com/wollac/async.go/pkg/config"
	"github.com/wollac/async.go/pkg/rbc"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

var (
	suite  = suites.MustFind("ed25519")
	secret = suite.Scalar().SetInt64(42)
)

func TestSingle(t *testing.T) {
	selfs, peers := generateKeys("A")
	conf := config.NewConfig(selfs[0], peers...)
	acss := New(suite, conf, "A")
	acss.Input(secret)
	out := <-acss.Output()
	require.NotNil(t, out)
	require.Equal(t, secret, out.V)
	require.NoError(t, acss.Close())
	require.True(t, acss.Stopped())
}

func TestACSS(t *testing.T) {
	nodes := createNodes("A", "A", "B", "C", "D")
	wait := relayMessages(t, nodes, 0, nil)

	nodes["A"].Input(secret)

	var shares []*share.PriShare
	for _, node := range nodes {
		shares = append(shares, <-node.Output())
		require.NoError(t, node.Close())
	}
	recoverSecret, err := share.RecoverSecret(suite, shares, 2, 4)
	require.NoError(t, err)
	require.Equal(t, secret, recoverSecret)

	// wait for everything to close, to correctly log all potential errors
	wait()
}

func TestOffline(t *testing.T) {
	nodes := createNodes("A", "A", "B", "C", "D")
	wait := relayMessages(t, nodes, 0, nil)

	// one offline node should be tolerated
	require.NoError(t, nodes["D"].Close())
	nodes["A"].Input(secret)

	var shares []*share.PriShare
	for _, node := range nodes {
		if !node.Stopped() {
			shares = append(shares, <-node.Output())
			require.NoError(t, node.Close())
		}
	}
	recoverSecret, err := share.RecoverSecret(suite, shares, 2, 4)
	require.NoError(t, err)
	require.Equal(t, secret, recoverSecret)

	// wait for everything to close, to correctly log all potential errors
	wait()
}

func TestNever(t *testing.T) {
	nodes := createNodes("A", "A", "B", "C", "D")
	wait := relayMessages(t, nodes, 0, nil)

	require.NoError(t, nodes["C"].Close())
	require.NoError(t, nodes["D"].Close())
	nodes["A"].Input(secret)

	// we must never output
	require.Never(t, func() bool {
		select {
		case <-nodes["A"].Output():
			return true
		default:
			return false
		}
	}, time.Second, 100*time.Millisecond)

	for _, node := range nodes {
		if !node.Stopped() {
			require.NoError(t, node.Close())
		}
	}

	// wait for everything to close, to correctly log all potential errors
	wait()
}

func TestDelayed(t *testing.T) {
	nodes := createNodes("A", "A", "B", "C", "D")
	wait := relayMessages(t, nodes, time.Second, nil)

	nodes["A"].Input(secret)

	var shares []*share.PriShare
	for _, node := range nodes {
		shares = append(shares, <-node.Output())
		require.NoError(t, node.Close())
	}
	recoverSecret, err := share.RecoverSecret(suite, shares, 2, 4)
	require.NoError(t, err)
	require.Equal(t, secret, recoverSecret)

	// wait for everything to close, to correctly log all potential errors
	wait()
}

func TestReveal(t *testing.T) {
	nodes := createNodes("A", "A", "B", "C", "D")
	wait := relayMessages(t, nodes, time.Second, invalidateRBCPropose)

	nodes["A"].Input(secret)

	// each node should output a share
	var shares []*share.PriShare
	for _, node := range nodes {
		shares = append(shares, <-node.Output())
		require.NoError(t, node.Close())
	}
	recoverSecret, err := share.RecoverSecret(suite, shares, 2, 4)
	require.NoError(t, err)
	require.Equal(t, secret, recoverSecret)

	// wait for everything to close, to correctly log all potential errors
	wait()
}

func BenchmarkACSSSingle(b *testing.B) {
	const N = 32

	type networkMessage struct {
		srcID, dstID string
		msg          *Message
	}
	var (
		wg     sync.WaitGroup
		single chan networkMessage
	)
	queue := func(a *ACSS) {
		defer wg.Done()
		for msg := range a.Messages() {
			single <- networkMessage{a.conf.Self().ID, msg.Receiver, msg.Payload}
		}
	}

	var ids []string
	for i := 0; i < N; i++ {
		ids = append(ids, fmt.Sprint(i))
	}

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		single = make(chan networkMessage, N*N*int(end))
		nodes := createNodes("0", ids...)
		for _, node := range nodes {
			wg.Add(1)
			// add all outgoing messages to the single message queue
			go queue(node)
		}
		b.StartTimer()

		nodes["0"].Input(secret)
		// handle all messages in a single go routine
		go func() {
			for msg := range single {
				_ = nodes[msg.dstID].Handle(msg.srcID, msg.msg)
			}
		}()

		for _, node := range nodes {
			<-node.Output()
			_ = node.Close()
		}
		wg.Wait()
		close(single)
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

func createNodes(dealer string, ids ...string) map[string]*ACSS {
	selfs, peers := generateKeys(ids...)
	nodes := map[string]*ACSS{}
	for _, self := range selfs {
		conf := config.NewConfig(self, peers...)
		nodes[self.ID] = New(suite, conf, dealer)
	}
	return nodes
}

// relayMessages the nodes by handling each other's messages
func relayMessages(t *testing.T, nodes map[string]*ACSS, maxDelay time.Duration, mod func(*Message)) func() {
	bus := EventBus.New()

	// subscribe all nodes to handle incoming messages
	for id, node := range nodes {
		dst := node
		require.NoError(t, bus.SubscribeAsync(id, func(sender string, msg *Message) {
			if mod != nil {
				mod(msg)
			}
			handle(t, sender, dst, msg, maxDelay)
		}, false))
	}

	var wg sync.WaitGroup
	for id, node := range nodes {
		wg.Add(1)
		go func(id string, a *ACSS) {
			defer wg.Done()
			for msg := range a.Messages() {
				bus.Publish(msg.Receiver, id, msg.Payload)
			}
		}(id, node)
	}

	return func() {
		wg.Wait()       // wait for publishers to finish
		bus.WaitAsync() // wait for subscribers to finish
	}
}

func handle(t *testing.T, srcID string, dst *ACSS, message *Message, maxDelay time.Duration) {
	if ms := maxDelay.Milliseconds(); ms > 0 {
		time.Sleep(time.Duration(rand.Int63n(ms)) * time.Millisecond)
	}
	t.Logf("%s->%s: %s", srcID, dst.conf.Self().ID, message.Type)
	err := dst.Handle(srcID, message)
	if errors.Is(err, ErrStopped) {
		t.Logf("%s is stopped", dst.conf.Self().ID)
		return
	}
	require.NoError(t, err)
}

// modify RBC-Propose messages, so that the last encrypted share is invalid
func invalidateRBCPropose(msg *Message) {
	if msg.Type != RBC {
		return
	}
	rbcMessage := &rbc.Message{}
	_ = rbcMessage.UnmarshalBinary(msg.Data)
	if rbcMessage.Type == rbc.Propose {
		rbcMessage.Data[len(rbcMessage.Data)-1]++
		msg.Data, _ = rbcMessage.MarshalBinary()
	}
}
