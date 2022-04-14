package config

import (
	"sort"

	"github.com/multiformats/go-multiaddr"
	"go.dedis.ch/kyber/v3"
)

type SelfInfo struct {
	ID      string
	PrivKey kyber.Scalar
}

type PeerInfo struct {
	ID     string
	PubKey kyber.Point
	Addr   []multiaddr.Multiaddr
}

type Config struct {
	self  SelfInfo
	peers map[string]*item

	f int
}

type item struct {
	index int
	info  PeerInfo
}

func NewConfig(self SelfInfo, infos ...PeerInfo) *Config {
	m := make(map[string]*item, len(infos))
	ids := make([]string, len(infos))
	for i, info := range infos {
		m[info.ID] = &item{index: 0, info: info}
		ids[i] = info.ID
	}

	sort.Strings(ids)
	for i, id := range ids {
		m[id].index = i
	}
	return &Config{self, m, (len(m) - 1) / 3}
}

func (c *Config) Self() SelfInfo {
	return c.self
}

func (c *Config) N() int {
	return len(c.peers)
}

func (c *Config) F() int {
	return c.f
}

func (c *Config) HasPeer(peer string) bool {
	_, contains := c.peers[peer]
	return contains
}

func (c *Config) IDs() []string {
	result := make([]string, c.N())
	for id, peer := range c.peers {
		result[peer.index] = id
	}
	return result
}

func (c *Config) Peers() []PeerInfo {
	result := make([]PeerInfo, c.N())
	for _, peer := range c.peers {
		result[peer.index] = peer.info
	}
	return result
}

func (c *Config) Index(id string) int {
	return c.peers[id].index
}

func (c *Config) SelfIndex() int {
	return c.Index(c.self.ID)
}
