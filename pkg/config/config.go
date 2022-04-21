package config

import (
	"sort"

	"go.dedis.ch/kyber/v3"
)

// SelfInfo represents a local node.
type SelfInfo struct {
	ID      string
	PrivKey kyber.Scalar
}

// PeerInfo represents any peer.
type PeerInfo struct {
	ID     string
	PubKey kyber.Point
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
	if _, ok := m[self.ID]; !ok {
		panic("config: self not contained in peers")
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

func (c *Config) PubKey(peer string) kyber.Point {
	return c.peers[peer].info.PubKey
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

func (c *Config) PubKeys() []kyber.Point {
	result := make([]kyber.Point, c.N())
	for _, peer := range c.peers {
		result[peer.index] = peer.info.PubKey
	}
	return result
}

// Index returns the index (0 to N) corresponding to the peer with id.
func (c *Config) Index(id string) int {
	return c.peers[id].index
}

// SelfIndex returns the index (0 to N) corresponding to the own peer.
func (c *Config) SelfIndex() int {
	return c.Index(c.self.ID)
}
