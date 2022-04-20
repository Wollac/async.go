package acss

import (
	"errors"
	"fmt"
	"sync"

	"github.com/wollac/async.go/pgk/acss/crypto"
	"github.com/wollac/async.go/pgk/config"
	"github.com/wollac/async.go/pgk/rbc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
	"go.uber.org/atomic"
)

var (
	ErrStopped       = errors.New("process stopped")
	ErrInvalidSender = errors.New("invalid sender")
)

type OutMessage struct {
	Receiver string
	Payload  *Message
}

type ACSS struct {
	sync.Mutex

	conf  *config.Config
	suite suites.Suite

	rbc *rbc.RBC

	rbcDone         bool            // whether the RBC has finished
	pubPoly         *share.PubPoly  // Feldman VSS commitments
	dealerPubKey    kyber.Point     // public key used to encrypt the shares
	encryptedShares [][]byte        // encrypted shares of all peers
	share           *share.PriShare // own share

	cache map[string]map[MessageType]*Message // ACSS messages received during RBC

	messagesChan chan *OutMessage

	okIDs map[string]struct{}

	ready    bool
	readyIDs map[string]struct{}

	implicateIDs map[string]struct{}

	reveal         bool
	revealIDs      map[string]struct{}
	revealedShares map[string]*share.PriShare

	output     bool
	outputChan chan *share.PriShare

	stopped atomic.Bool
	close   chan struct{}
}

func New(conf *config.Config, suite suites.Suite, dealer string) *ACSS {
	acss := &ACSS{
		conf:            conf,
		suite:           suite,
		rbc:             rbc.New(conf, dealer, crypto.DealLen(suite, conf.N()), nil),
		rbcDone:         false,
		pubPoly:         nil,
		dealerPubKey:    nil,
		encryptedShares: nil,
		share:           nil,
		cache:           map[string]map[MessageType]*Message{},
		messagesChan:    make(chan *OutMessage, conf.N()-1),
		okIDs:           map[string]struct{}{},
		ready:           false,
		readyIDs:        map[string]struct{}{},
		implicateIDs:    map[string]struct{}{},
		reveal:          false,
		revealIDs:       map[string]struct{}{},
		revealedShares:  map[string]*share.PriShare{},
		output:          false,
		outputChan:      make(chan *share.PriShare, 1),
		stopped:         atomic.Bool{},
		close:           make(chan struct{}),
	}
	go acss.run()
	return acss
}

func (a *ACSS) Stopped() bool {
	return a.stopped.Load()
}

func (a *ACSS) Close() error {
	if !a.stopped.CAS(false, true) {
		return ErrStopped
	}

	a.Lock()
	defer a.Unlock()

	close(a.close)
	close(a.outputChan)
	close(a.messagesChan)

	return a.rbc.Close()
}

// Input is called by the dealer to start the sharing of the given secret.
func (a *ACSS) Input(secret kyber.Scalar) {
	// create the deal
	data := crypto.Deal(a.suite, a.conf.PubKeys(), secret)
	// broadcast everything
	a.rbc.Input(data)
}

func (a *ACSS) run() {
	for {
		select {

		// messages of the rbc engine are forwarded
		case rbcMessage := <-a.rbc.Messages():
			data, _ := rbcMessage.Payload.MarshalBinary()
			msg := &Message{RBC, data}
			a.messagesChan <- &OutMessage{rbcMessage.Receiver, msg}

		// handle the output as soon as the rbc engine is done
		case rbcOutput := <-a.rbc.Output():
			a.handleRBC(rbcOutput)

		// acss has been stopped
		case <-a.close:
			return
		}
	}
}

// Output receives the final share.
func (a *ACSS) Output() chan *share.PriShare {
	return a.outputChan
}

// Messages receives the messages to be sent to other peers.
func (a *ACSS) Messages() <-chan *OutMessage {
	return a.messagesChan
}

// Handle must be called for each incoming message of other peers.
func (a *ACSS) Handle(sender string, msg *Message) error {
	if a.stopped.Load() {
		return ErrStopped
	}
	if !a.conf.HasPeer(sender) {
		return ErrInvalidSender
	}

	// forward RBC messages to the rbc engine
	if msg.Type == RBC {
		var rbcMessage rbc.Message
		if err := rbcMessage.UnmarshalBinary(msg.Data); err != nil {
			return err
		}
		return a.rbc.Handle(sender, &rbcMessage)
	}

	a.Lock()
	defer a.Unlock()
	if a.stopped.Load() {
		return ErrStopped
	}

	// when we receive non-RBC messages before the broadcast has finished, they need to be cached
	if !a.rbcDone {
		senderQueue := a.cache[sender]
		if senderQueue == nil {
			senderQueue = map[MessageType]*Message{}
			a.cache[sender] = senderQueue
		}
		if _, ok := senderQueue[msg.Type]; ok {
			return &MessageError{sender, msg.Type, "sent more than once"}
		}
		senderQueue[msg.Type] = msg
		return nil
	}

	return a.handleACSS(sender, msg)
}

func (a *ACSS) handleRBC(data []byte) {
	a.Lock()
	defer a.Unlock()

	a.rbcDone = true
	pubPoly, dealerPubKey, shares, err := crypto.CheckDeal(a.suite, a.conf.N(), data)
	if err == nil {
		a.pubPoly = pubPoly
		a.dealerPubKey = dealerPubKey
		a.encryptedShares = shares

		// try to extract our share
		secret := crypto.Secret(a.suite, dealerPubKey, a.conf.Self().PrivKey)
		a.share, err = crypto.DecryptShare(a.suite, pubPoly, shares, a.conf.SelfIndex(), secret)
		if err != nil {
			a.doImplicate()
		} else {
			a.doOK()
		}
	}

	// replay cached messages
	if len(a.cache) > 0 {
		for sender, queue := range a.cache {
			for _, msg := range queue {
				_ = a.handleACSS(sender, msg)
			}
		}
		a.cache = nil // free cache
	}
}

func (a *ACSS) handleACSS(sender string, msg *Message) error {
	switch msg.Type {
	case OK:
		return a.handleOK(sender, msg.Data)
	case Ready:
		return a.handleReady(sender, msg.Data)
	case Implicate:
		return a.handleImplicate(sender, msg.Data)
	case Reveal:
		return a.handleReveal(sender, msg.Data)
	}
	return ErrInvalidType
}

func (a *ACSS) handleOK(sender string, data []byte) error {
	if len(data) > 0 {
		return &MessageError{sender, OK, "data loo long"}
	}
	if _, has := a.okIDs[sender]; has {
		return &MessageError{sender, OK, "sent more than once"}
	}
	a.okIDs[sender] = struct{}{}

	if a.ready {
		return nil
	}

	count := len(a.okIDs)
	if count > (a.conf.N()+a.conf.F())/2 {
		a.ready = true

		if err := a.handleReady(a.conf.Self().ID, nil); err != nil {
			panic(fmt.Sprintf("acss: internal error: %v", err))
		}
		a.broadcast(&Message{Ready, nil})
	}
	return nil
}

func (a *ACSS) handleReady(sender string, data []byte) error {
	if len(data) > 0 {
		return &MessageError{sender, Ready, "data loo long"}
	}
	if _, has := a.readyIDs[sender]; has {
		return &MessageError{sender, Ready, "sent more than once"}
	}
	a.readyIDs[sender] = struct{}{}

	// we already output, so there is no need to count messages
	if a.output {
		return nil
	}

	count := len(a.readyIDs)
	if !a.ready && count > a.conf.F() {
		a.ready = true

		if err := a.handleReady(a.conf.Self().ID, nil); err != nil {
			panic(fmt.Sprintf("acss: internal error: %v", err))
		}
		a.broadcast(&Message{Ready, nil})
	}
	if a.share != nil && count > 2*a.conf.F() {
		a.output = true
		a.outputChan <- a.share
	}

	return nil
}

func (a *ACSS) handleImplicate(sender string, data []byte) error {
	if _, has := a.implicateIDs[sender]; has {
		return &MessageError{sender, Implicate, "sent more than once"}
	}
	a.implicateIDs[sender] = struct{}{}

	if err := a.checkImplicate(sender, data); err != nil {
		return &MessageError{sender, Implicate, err.Error()}
	}
	// we now have a proof that the dealer is faulty, and we can reveal our share
	// reveal the shared DH key, if a valid share was received
	if a.share == nil || a.reveal {
		return nil
	}

	// compute shared DH secret
	secret := crypto.Secret(a.suite, a.dealerPubKey, a.conf.Self().PrivKey)
	// reveal the shared secret
	a.reveal = true
	if err := a.handleReveal(a.conf.Self().ID, secret); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	a.broadcast(&Message{Reveal, secret})

	return nil
}

func (a *ACSS) handleReveal(sender string, data []byte) error {
	if _, has := a.revealIDs[sender]; has {
		return &MessageError{sender, Reveal, "sent more than once"}
	}
	a.revealIDs[sender] = struct{}{}

	index := a.conf.Index(sender)
	s, err := crypto.DecryptShare(a.suite, a.pubPoly, a.encryptedShares, index, data)
	if err != nil {
		return &MessageError{sender, Reveal, "invalid secret revealed"}
	}

	// if we do not have a valid share, there is nothing to reveal
	if a.share != nil {
		return nil
	}

	// store the resulting revealed share
	a.revealedShares[sender] = s
	if len(a.revealedShares) > a.conf.F() {
		var shares []*share.PriShare
		for _, priShare := range a.revealedShares {
			shares = append(shares, priShare)
		}
		// recover the priShare that we were supposed to receive
		poly, err := share.RecoverPriPoly(a.suite, shares, a.conf.F()+1, a.conf.N())
		if err != nil {
			panic(fmt.Sprintf("acss: internal error: %v", err))
		}
		a.share = poly.Eval(a.conf.SelfIndex())
		// send OK as a valid share was received
		a.doOK()
		// make sure to output, even when a READY was already sent
		if !a.output && len(a.readyIDs) > 2*a.conf.F() {
			a.output = true
			a.outputChan <- a.share
		}
	}

	return nil
}

func (a *ACSS) doOK() {
	if err := a.handleOK(a.conf.Self().ID, nil); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	a.broadcast(&Message{OK, nil})
}

// doImplicate sends and IMPLICATE message with shared key and proof of correctness.
func (a *ACSS) doImplicate() {
	data := crypto.Implicate(a.suite, a.dealerPubKey, a.conf.Self().PrivKey)
	if err := a.handleImplicate(a.conf.Self().ID, data); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	a.broadcast(&Message{Implicate, data})
}

// checkImplicate verifies that the IMPLICATE message is a correct proof of a faulty dealer.
func (a *ACSS) checkImplicate(sender string, data []byte) error {
	secret, err := crypto.CheckImplicate(a.suite, a.dealerPubKey, a.conf.PubKey(sender), data)
	if err != nil {
		return fmt.Errorf("invalid proof: %w", err)
	}

	index := a.conf.Index(sender)
	_, err = crypto.DecryptShare(a.suite, a.pubPoly, a.encryptedShares, index, secret)
	if err == nil {
		// if we are able to decrypt the share, the implication is not correct
		return errors.New("encrypted share is valid")
	}
	return nil
}

func (a *ACSS) broadcast(msg *Message) {
	for _, peer := range a.conf.IDs() {
		if peer != a.conf.Self().ID {
			a.messagesChan <- &OutMessage{peer, msg}
		}
	}
}
