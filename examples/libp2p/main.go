package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peerstore"
	"github.com/wollac/async.go/internal/tlv"
	"github.com/wollac/async.go/pgk/config"
	"github.com/wollac/async.go/pgk/rbc"
)

const protocol = "/rbc/0.0.1"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

type Node struct {
	host host.Host
	tlv  *tlv.Registry
	rbc  *rbc.RBC
}

func newConfig(hosts ...host.Host) *config.Config {
	var ids []config.PeerInfo
	for _, h := range hosts {
		ids = append(ids, config.PeerInfo{ID: h.ID().String(), Addr: h.Addrs()})
	}
	return config.NewConfig(ids...)
}

func newNode() (host.Host, error) {
	priv, _, _ := crypto.GenerateEd25519Key(rand.Reader)

	return libp2p.New(
		libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
		libp2p.Identity(priv),
	)
}

func (n *Node) bar(stream network.Stream) {
	n.tlv.Register(0, &rbc.Message{}, func(value []byte) error {
		msg := &rbc.Message{}
		if err := msg.UnmarshalBinary(value); err != nil {
			return err
		}
		return n.rbc.Handle(stream.Conn().RemotePeer().String(), msg)
	})

	go func() {
		for msg := range n.rbc.Messages() {
			n.tlv.Write(stream, msg.Payload)
		}
	}()

	for n.tlv.Handle(stream) == nil {
	}
	stream.Close()
}

func foo(conf *config.Config, h host.Host, dealer string) *Node {
	reg := tlv.New()
	bracha := rbc.New(conf, h.ID().String(), dealer, 64, nil)
	n := &Node{h, reg, bracha}
	h.SetStreamHandler(protocol, n.bar)
	return n
}

func connect(ps *peerstore.Peerstore, conf config.Config) {

}

func run() error {
	hostA, _ := newNode()
	hostB, _ := newNode()
	hostC, _ := newNode()

	hostA.Peerstore().AddAddrs(hostB.ID(), hostB.Addrs(), peerstore.ConnectedAddrTTL)
	hostB.Peerstore().AddAddrs(hostA.ID(), hostA.Addrs(), peerstore.ConnectedAddrTTL)
	host.Peerstore().AddAddrs(hostA.ID(), hostA.Addrs(), peerstore.ConnectedAddrTTL)

	conf := newConfig(hostA, hostB)
	nodeA := foo(conf, hostA, hostA.ID().String())
	nodeB := foo(conf, hostB, hostA.ID().String())

	stream, err := nodeA.host.NewStream(context.Background(), nodeB.host.ID(), protocol)
	if err != nil {
		return err
	}
	go nodeA.bar(stream)
	nodeA.rbc.Input([]byte{0xff})
	fmt.Println(<-nodeB.rbc.Output())

	// wait for a SIGINT or SIGTERM signal
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	fmt.Println("Received signal, shutting down...")

	hostA.Close()
	hostB.Close()
	return nil
}
