package acss

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
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

type MessageError struct {
	SenderID string
	Type     MessageType
	Str      string
}

func (e *MessageError) Error() string {
	return "Invalid " + strconv.Quote(e.Type.String()) + " message: " + e.Str
}

type OutMessage struct {
	Receiver string
	Payload  *Message
}

type ACSS struct {
	sync.Mutex

	conf     *config.Config
	suite    suites.Suite
	dealerID string

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

	reveal          bool
	revealIDs       map[string]struct{}
	recoveredShares map[string]*share.PriShare

	output     bool
	outputChan chan *share.PriShare

	stopped atomic.Bool
	close   chan struct{}
}

func New(conf *config.Config, suite suites.Suite, dealer string) *ACSS {
	// F+1 commitments, ephemeral public key, N encrypted shares
	broadcastLength := (conf.F()+2)*suite.PointLen() + conf.N()*(suite.ScalarLen()+16)

	acss := &ACSS{
		conf:            conf,
		suite:           suite,
		dealerID:        dealer,
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
		recoveredShares: map[string]*share.PriShare{},
		output:          false,
		outputChan:      make(chan *share.PriShare, 1),
		stopped:         atomic.Bool{},
		close:           make(chan struct{}),
	}
	go acss.run()
	return acss
}

func (r *ACSS) Stopped() bool {
	return r.stopped.Load()
}

func (r *ACSS) Close() error {
	if !r.stopped.CAS(false, true) {
		return ErrStopped
	}

	r.Lock()
	defer r.Unlock()

	close(r.close)
	close(r.outputChan)
	close(r.messagesChan)

	return r.rbc.Close()
}

func (r *ACSS) Input(secret kyber.Scalar) {
	buf := &bytes.Buffer{}

	// generate Feldman commitments
	poly := share.NewPriPoly(r.suite, r.conf.F()+1, secret, r.suite.RandomStream())
	_, commits := poly.Commit(nil).Info()
	// include all F+1 commitments
	for _, p := range commits {
		if _, err := p.MarshalTo(buf); err != nil {
			panic(fmt.Sprintf("acss: internal error: %v", err))
		}
	}

	// generate ephemeral keypair
	sk := r.suite.Scalar().Pick(r.suite.RandomStream())
	pk := r.suite.Point().Mul(sk, nil)
	// include ephemeral public key
	if _, err := pk.MarshalTo(buf); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}

	// generate N shares
	priShares := poly.Shares(r.conf.N())
	for i, peerInfo := range r.conf.Peers() {
		// compute shared DH key
		dhBytes := dhExchange(r.suite, sk, peerInfo.PubKey)

		// encrypt the share using the shared key
		encryptedShare := encrypt(priShares[i].V, newAEAD(dhBytes, nil))
		// include the encrypted share
		buf.Write(encryptedShare)
	}

	// broadcast everything
	r.rbc.Input(buf.Bytes())
}

func (r *ACSS) run() {
	for {
		select {
		case rbcMessage := <-r.rbc.Messages():
			data, _ := rbcMessage.Payload.MarshalBinary()
			msg := &Message{RBC, data}
			r.messagesChan <- &OutMessage{rbcMessage.Receiver, msg}
		case rbcOutput := <-r.rbc.Output():
			r.handleRBC(rbcOutput)
		case <-r.close:
			return
		}
	}
}

func (r *ACSS) Output() chan *share.PriShare {
	return r.outputChan
}

func (r *ACSS) Messages() <-chan *OutMessage {
	return r.messagesChan
}

func (r *ACSS) Handle(sender string, msg *Message) error {
	if r.stopped.Load() {
		return ErrStopped
	}
	if !r.conf.HasPeer(sender) {
		return ErrInvalidSender
	}

	// forward RBC messages to the rbc engine
	if msg.Type == RBC {
		var rbcMessage rbc.Message
		if err := rbcMessage.UnmarshalBinary(msg.Data); err != nil {
			return err
		}
		return r.rbc.Handle(sender, &rbcMessage)
	}

	r.Lock()
	defer r.Unlock()
	if r.stopped.Load() {
		return ErrStopped
	}

	// when we receive non-RBC messages before the broadcast has finished, they need to be cached
	if !r.rbcDone {
		senderQueue := r.cache[sender]
		if senderQueue == nil {
			senderQueue = map[MessageType]*Message{}
			r.cache[sender] = senderQueue
		}
		if _, ok := senderQueue[msg.Type]; ok {
			return &MessageError{sender, msg.Type, "sent more than once"}
		}
		senderQueue[msg.Type] = msg
		return nil
	}

	return r.handleACSS(sender, msg)
}

func (r *ACSS) handleRBC(data []byte) {
	r.Lock()
	defer r.Unlock()

	r.rbcDone = true
	if err := r.checkRBC(data); err != nil {
		r.doImplicate()
	} else {
		r.doOK()
	}

	// replay cached messages
	if len(r.cache) > 0 {
		for sender, queue := range r.cache {
			for _, msg := range queue {
				_ = r.handleACSS(sender, msg)
			}
		}
		r.cache = nil // free cache
	}
}

func (r *ACSS) handleACSS(sender string, msg *Message) error {
	switch msg.Type {
	case OK:
		return r.handleOK(sender)
	case Ready:
		return r.handleReady(sender)
	case Implicate:
		return r.handleImplicate(sender, msg.Data)
	case Reveal:
		return r.handleReveal(sender, msg.Data)
	}
	return ErrInvalidType
}

func (r *ACSS) handleOK(sender string) error {
	if _, has := r.okIDs[sender]; has {
		return &MessageError{sender, OK, "sent more than once"}
	}
	r.okIDs[sender] = struct{}{}

	if r.ready {
		return nil
	}

	count := len(r.okIDs)
	if count > (r.conf.N()+r.conf.F())/2 {
		r.ready = true

		if err := r.handleReady(r.conf.Self().ID); err != nil {
			panic(fmt.Sprintf("acss: internal error: %v", err))
		}
		r.broadcast(&Message{Ready, nil})
	}
	return nil
}

func (r *ACSS) handleReady(sender string) error {
	if _, has := r.readyIDs[sender]; has {
		return &MessageError{sender, Ready, "sent more than once"}
	}
	r.readyIDs[sender] = struct{}{}

	// we already output, so there is no need to count messages
	if r.output {
		return nil
	}

	count := len(r.readyIDs)
	if !r.ready && count > r.conf.F() {
		r.ready = true

		if err := r.handleReady(r.conf.Self().ID); err != nil {
			panic(fmt.Sprintf("acss: internal error: %v", err))
		}
		r.broadcast(&Message{Ready, nil})
	}
	if r.share != nil && count > 2*r.conf.F() {
		r.output = true

		r.outputChan <- r.share
	}

	return nil
}

func (r *ACSS) handleImplicate(sender string, data []byte) error {
	if _, has := r.implicateIDs[sender]; has {
		return &MessageError{sender, Implicate, "sent more than once"}
	}
	r.implicateIDs[sender] = struct{}{}

	if err := r.checkImplicate(sender, data); err != nil {
		return err
	}

	// reveal the shared DH key, if a valid share was received
	if r.share == nil || r.reveal {
		return nil
	}

	// compute shared DH key
	dhBytes := dhExchange(r.suite, r.conf.Self().PrivKey, r.sharesPubKey)

	// reveal the shared key
	r.reveal = true
	if err := r.handleReveal(r.conf.Self().ID, dhBytes); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	r.broadcast(&Message{Reveal, dhBytes})

	return nil
}

func (r *ACSS) handleReveal(sender string, data []byte) error {
	if len(data) != r.suite.PointLen() {
		return &MessageError{sender, Reveal, "invalid data length"}
	}
	if _, has := r.revealIDs[sender]; has {
		return &MessageError{sender, Reveal, "sent more than once"}
	}
	r.revealIDs[sender] = struct{}{}

	index := r.conf.Index(sender)
	v := r.suite.Scalar()
	if err := decrypt(v, newAEAD(data, nil), r.encryptedShares[index]); err != nil {
		return err
	}
	s := &share.PriShare{I: index, V: v}
	if !r.pubPoly.Check(s) {
		return errors.New("invalid share")
	}

	if r.share != nil {
		return nil
	}

	r.recoveredShares[sender] = s
	if len(r.recoveredShares) > r.conf.F() {
		var shares []*share.PriShare
		for _, priShare := range r.recoveredShares {
			shares = append(shares, priShare)
		}
		// recover the priShare that we were supposed to receive
		poly, err := share.RecoverPriPoly(r.suite, shares, r.conf.F()+1, r.conf.N())
		if err != nil {
			panic(err)
		}
		r.share = poly.Eval(r.conf.SelfIndex())
		r.doOK()
		// make sure to output, even when READY was already sent
		if !r.output && len(r.readyIDs) > 2*r.conf.F() {
			r.output = true
			r.outputChan <- r.share
		}
	}

	return nil
}

func (r *ACSS) doOK() {
	if err := r.handleOK(r.conf.Self().ID); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	r.broadcast(&Message{OK, nil})
}

func (r *ACSS) doImplicate() {
	// compute shared DH key
	dhBytes := dhExchange(r.suite, r.conf.Self().PrivKey, r.sharesPubKey)
	// sign to prove that privKey * sharesPubKey = dhKey, without revealing privKey
	sig, err := Sign(r.suite, r.sharesPubKey, r.conf.Self().PrivKey, dhBytes)
	if err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}

	data := append(dhBytes, sig...)
	if err := r.handleImplicate(r.conf.Self().ID, data); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	r.broadcast(&Message{Implicate, data})
}

func (r *ACSS) checkRBC(data []byte) error {
	buf := bytes.NewBuffer(data)

	// load all F+1 commitments
	commits := make([]kyber.Point, r.conf.F()+1)
	for i := range commits {
		p := r.suite.Point()
		if _, err := p.UnmarshalFrom(buf); err != nil {
			return err
		}
		commits[i] = p
	}
	r.pubPoly = share.NewPubPoly(r.suite, nil, commits)

	// load the ephemeral public key
	r.sharesPubKey = r.suite.Point()
	if _, err := r.sharesPubKey.UnmarshalFrom(buf); err != nil {
		return err
	}
	// TODO: do we need to check for non-canonical or small-order points

	// load all N encrypted shares
	encryptedDealSize := r.suite.ScalarLen() + 16
	r.encryptedShares = make([][]byte, r.conf.N())
	for i := range r.encryptedShares {
		r.encryptedShares[i] = make([]byte, encryptedDealSize)
		if _, err := buf.Read(r.encryptedShares[i]); err != nil {
			return err
		}
	}

	// compute shared DH key
	dhBytes := dhExchange(r.suite, r.conf.Self().PrivKey, r.sharesPubKey)

	// decrypt the scalar
	index := r.conf.SelfIndex()
	v := r.suite.Scalar()
	if err := decrypt(v, newAEAD(dhBytes, nil), r.encryptedShares[index]); err != nil {
		return err
	}
	s := &share.PriShare{I: index, V: v}
	if r.pubPoly.Check(s) != true {
		return errors.New("invalid share")
	}

	r.share = s
	return nil
}

func (r *ACSS) checkImplicate(sender string, data []byte) error {
	if len(data) != 2*r.suite.PointLen()+r.suite.ScalarLen() {
		return errors.New("invalid data")
	}
	dhBytes := data[:r.suite.PointLen()]
	sig := data[r.suite.PointLen():]

	dh := r.suite.Point()
	if err := dh.UnmarshalBinary(dhBytes); err != nil {
		return fmt.Errorf("invalid key: %w", err)
	}
	// TODO: do we need to check for non-canonical or small-order points

	if err := Verify(r.suite, r.sharesPubKey, dh, dhBytes, sig); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	index := r.conf.Index(sender)
	v := r.suite.Scalar()
	if err := decrypt(v, newAEAD(dhBytes, nil), r.encryptedShares[index]); err != nil {
		// if the decrypt fails, the implication is correct
		return nil
	}

	s := &share.PriShare{I: index, V: v}
	if !r.pubPoly.Check(s) {
		// if the VSS verification fails, the implication is correct
		return nil
	}

	return errors.New("encrypted share is valid")
}

func (r *ACSS) broadcast(msg *Message) {
	for _, peer := range r.conf.IDs() {
		if peer != r.conf.Self().ID {
			r.messagesChan <- &OutMessage{peer, msg}
		}
	}
}
