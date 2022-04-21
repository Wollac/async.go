package rbc

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/wollac/async.go/pkg/config"
	"go.uber.org/atomic"
)

var (
	ErrStopped       = errors.New("process stopped")
	ErrDataLength    = errors.New("data too long")
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

type Predicate func([]byte) bool

type RBC struct {
	sync.Mutex

	conf      *config.Config
	dealer    string
	maxLength int
	pred      Predicate

	messagesChan chan *OutMessage

	echo       bool
	echoIDs    map[string]struct{}
	echoCounts map[string]int

	ready       bool
	readyIDs    map[string]struct{}
	readyCounts map[string]int

	output     bool
	outputChan chan []byte

	stopped atomic.Bool
}

type OutMessage struct {
	Receiver string
	Payload  *Message
}

func New(conf *config.Config, dealer string, maxLength int, pred Predicate) *RBC {
	return &RBC{
		conf:         conf,
		dealer:       dealer,
		maxLength:    maxLength,
		pred:         pred,
		messagesChan: make(chan *OutMessage, conf.N()-1),
		echo:         false,
		echoIDs:      map[string]struct{}{},
		echoCounts:   map[string]int{},
		ready:        false,
		readyIDs:     map[string]struct{}{},
		readyCounts:  map[string]int{},
		output:       false,
		outputChan:   make(chan []byte, 1),
	}
}

func (r *RBC) Close() error {
	if !r.stopped.CAS(false, true) {
		return ErrStopped
	}

	r.Lock()
	defer r.Unlock()

	close(r.outputChan)
	close(r.messagesChan)

	return nil
}

func (r *RBC) Input(data []byte) {
	if len(data) > r.maxLength {
		panic(fmt.Sprintf("rbc: %v", ErrDataLength))
	}

	propose := &Message{Propose, append([]byte{}, data...)}
	if err := r.Handle(r.conf.Self().ID, propose); err != nil {
		panic(fmt.Sprintf("rbc: internal error: %v", err))
	}
	r.broadcast(propose)
}

func (r *RBC) Output() <-chan []byte {
	return r.outputChan
}

func (r *RBC) Messages() <-chan *OutMessage {
	return r.messagesChan
}

func (r *RBC) Handle(sender string, msg *Message) error {
	if r.stopped.Load() {
		return ErrStopped
	}
	if !r.conf.HasPeer(sender) {
		return ErrInvalidSender
	}
	if len(msg.Data) > r.maxLength {
		return ErrDataLength
	}

	r.Lock()
	defer r.Unlock()
	if r.stopped.Load() {
		return ErrStopped
	}

	switch msg.Type {
	case Propose:
		return r.handlePropose(sender, msg.Data)
	case Echo:
		return r.handleEcho(sender, msg.Data)
	case Ready:
		return r.handleReady(sender, msg.Data)
	}
	return ErrInvalidType
}

func (r *RBC) handlePropose(sender string, data []byte) error {
	if sender != r.dealer {
		return &MessageError{sender, Propose, "not a dealer"}
	}
	if r.echo {
		return &MessageError{sender, Propose, "sent more than once"}
	}
	if r.pred != nil && !r.pred(data) {
		return &MessageError{sender, Propose, "data does not validate"}
	}
	r.echo = true

	if err := r.handleEcho(r.conf.Self().ID, data); err != nil {
		panic(fmt.Sprintf("rbs: internal error: %v", err))
	}
	r.broadcast(&Message{Echo, data})

	return nil
}

func (r *RBC) handleEcho(sender string, data []byte) error {
	if _, has := r.echoIDs[sender]; has {
		return &MessageError{sender, Echo, "sent more than once"}
	}
	r.echoIDs[sender] = struct{}{}

	if r.ready {
		return nil
	}

	r.echoCounts[string(data)] += 1
	count := r.echoCounts[string(data)]
	if count > (r.conf.N()+r.conf.F())/2 {
		r.ready = true
		r.echoCounts = nil // free unneeded map

		if err := r.handleReady(r.conf.Self().ID, data); err != nil {
			panic(fmt.Sprintf("rbs: internal error: %v", err))
		}
		r.broadcast(&Message{Ready, data})
	}
	return nil
}

func (r *RBC) handleReady(sender string, data []byte) error {
	if _, has := r.readyIDs[sender]; has {
		return &MessageError{sender, Ready, "sent more than once"}
	}
	r.readyIDs[sender] = struct{}{}

	// we already output, so there is no need to count messages
	if r.output {
		return nil
	}

	r.readyCounts[string(data)] += 1
	count := r.readyCounts[string(data)]
	if !r.ready && count > r.conf.F() {
		r.ready = true
		r.echoCounts = nil // free unneeded map

		if err := r.handleReady(r.conf.Self().ID, data); err != nil {
			panic(fmt.Sprintf("rbs: internal error: %v", err))
		}
		r.broadcast(&Message{Ready, data})
	}
	if count > 2*r.conf.F() {
		r.output = true
		r.readyCounts = nil // free unneeded map

		r.outputChan <- data
	}

	return nil
}

func (r *RBC) broadcast(msg *Message) {
	for _, peer := range r.conf.IDs() {
		if peer != r.conf.Self().ID {
			r.messagesChan <- &OutMessage{peer, msg}
		}
	}
}
