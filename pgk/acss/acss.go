package acss

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

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
	sharesPubKey    kyber.Point     // public key used to encrypt the shares
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
	// F+1 commitments, ephemeral public key, N encrypted shares
	broadcastLength := (conf.F()+2)*suite.PointLen() + conf.N()*(suite.ScalarLen()+AEADOverhead)

	acss := &ACSS{
		conf:            conf,
		suite:           suite,
		rbc:             rbc.New(conf, dealer, broadcastLength, nil),
		rbcDone:         false,
		pubPoly:         nil,
		sharesPubKey:    nil,
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
	buf := &bytes.Buffer{}

	// generate Feldman commitments
	poly := share.NewPriPoly(a.suite, a.conf.F()+1, secret, a.suite.RandomStream())
	_, commits := poly.Commit(nil).Info()
	// include all F+1 commitments
	for _, p := range commits {
		if _, err := p.MarshalTo(buf); err != nil {
			panic(fmt.Sprintf("acss: internal error: %v", err))
		}
	}

	// generate ephemeral keypair
	sk := a.suite.Scalar().Pick(a.suite.RandomStream())
	pk := a.suite.Point().Mul(sk, nil)
	// include ephemeral public key
	if _, err := pk.MarshalTo(buf); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}

	// generate N shares
	priShares := poly.Shares(a.conf.N())
	for i, peerInfo := range a.conf.Peers() {
		// compute shared DH key
		dhBytes := dhExchange(a.suite, sk, peerInfo.PubKey)

		// TODO: use info for domain separation when deriving the key
		encryptedShare := encryptScalar(priShares[i].V, newAEAD(dhBytes, nil))
		// include the encrypted share
		buf.Write(encryptedShare)
	}

	// broadcast everything
	a.rbc.Input(buf.Bytes())
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
	if err := a.checkRBC(data); err != nil {
		a.doImplicate()
	} else {
		a.doOK()
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

	// compute shared DH key
	dhBytes := dhExchange(a.suite, a.conf.Self().PrivKey, a.sharesPubKey)

	// reveal the shared key
	a.reveal = true
	if err := a.handleReveal(a.conf.Self().ID, dhBytes); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	a.broadcast(&Message{Reveal, dhBytes})

	return nil
}

func (a *ACSS) handleReveal(sender string, data []byte) error {
	if len(data) != a.suite.PointLen() {
		return &MessageError{sender, Reveal, "invalid data length"}
	}
	if _, has := a.revealIDs[sender]; has {
		return &MessageError{sender, Reveal, "sent more than once"}
	}
	a.revealIDs[sender] = struct{}{}

	index := a.conf.Index(sender)
	v := a.suite.Scalar()
	if err := decryptScalar(v, newAEAD(data, nil), a.encryptedShares[index]); err != nil {
		return &MessageError{sender, Reveal, "invalid secret revealed"}
	}
	s := &share.PriShare{I: index, V: v}
	if !a.pubPoly.Check(s) {
		return &MessageError{sender, Reveal, "invalid share revealed"}
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
	// compute shared DH key
	dhBytes := dhExchange(a.suite, a.conf.Self().PrivKey, a.sharesPubKey)
	// sign to prove that privKey * sharesPubKey = dhKey, without revealing privKey
	sig, err := Sign(a.suite, a.sharesPubKey, a.conf.Self().PrivKey, dhBytes)
	if err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}

	data := append(dhBytes, sig...)
	if err := a.handleImplicate(a.conf.Self().ID, data); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	a.broadcast(&Message{Implicate, data})
}

func (a *ACSS) checkRBC(data []byte) error {
	buf := bytes.NewBuffer(data)

	// load all F+1 commitments
	commits := make([]kyber.Point, a.conf.F()+1)
	for i := range commits {
		p := a.suite.Point()
		if _, err := p.UnmarshalFrom(buf); err != nil {
			return err
		}
		commits[i] = p
	}
	a.pubPoly = share.NewPubPoly(a.suite, nil, commits)

	// load the ephemeral public key
	a.sharesPubKey = a.suite.Point()
	if _, err := a.sharesPubKey.UnmarshalFrom(buf); err != nil {
		return err
	}
	// TODO: check for non-canonical or small-order points

	// load all N encrypted shares
	encryptedDealSize := a.suite.ScalarLen() + AEADOverhead
	a.encryptedShares = make([][]byte, a.conf.N())
	for i := range a.encryptedShares {
		a.encryptedShares[i] = make([]byte, encryptedDealSize)
		if _, err := buf.Read(a.encryptedShares[i]); err != nil {
			return err
		}
	}

	// compute shared DH key
	dhBytes := dhExchange(a.suite, a.conf.Self().PrivKey, a.sharesPubKey)

	// decryptScalar the scalar
	index := a.conf.SelfIndex()
	v := a.suite.Scalar()
	if err := decryptScalar(v, newAEAD(dhBytes, nil), a.encryptedShares[index]); err != nil {
		return err
	}
	s := &share.PriShare{I: index, V: v}
	if a.pubPoly.Check(s) != true {
		return errors.New("invalid share")
	}

	a.share = s
	return nil
}

// checkImplicate verifies that the IMPLICATE message is a correct proof of a faulty dealer.
func (a *ACSS) checkImplicate(sender string, data []byte) error {
	if len(data) != 2*a.suite.PointLen()+a.suite.ScalarLen() {
		return errors.New("invalid data length")
	}
	dhBytes := data[:a.suite.PointLen()]
	sig := data[a.suite.PointLen():]

	dh := a.suite.Point()
	if err := dh.UnmarshalBinary(dhBytes); err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}
	// TODO: check for non-canonical or small-order points

	if err := Verify(a.suite, a.sharesPubKey, dh, dhBytes, sig); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	index := a.conf.Index(sender)
	v := a.suite.Scalar()
	if err := decryptScalar(v, newAEAD(dhBytes, nil), a.encryptedShares[index]); err != nil {
		// if the decryptScalar fails, the implication is correct
		return nil
	}

	s := &share.PriShare{I: index, V: v}
	if !a.pubPoly.Check(s) {
		// if the VSS verification fails, the implication is correct
		return nil
	}

	return errors.New("encrypted share is valid")
}

func (a *ACSS) broadcast(msg *Message) {
	for _, peer := range a.conf.IDs() {
		if peer != a.conf.Self().ID {
			a.messagesChan <- &OutMessage{peer, msg}
		}
	}
}
