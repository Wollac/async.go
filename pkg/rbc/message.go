package rbc

import (
	"errors"
)

var ErrInvalidType = errors.New("invalid message type")

var typeStrings = [...]string{"PROPOSE", "ECHO", "READY"}

type MessageType byte

const (
	Propose MessageType = iota
	Echo
	Ready
	end
)

func (t MessageType) String() string {
	return typeStrings[t]
}

func ValidMessageType(v byte) bool {
	return v < byte(end)
}

type Message struct {
	Type MessageType
	Data []byte
}

func (m *Message) MarshalBinary() ([]byte, error) {
	return append([]byte{byte(m.Type)}, m.Data...), nil
}

func (m *Message) UnmarshalBinary(data []byte) error {
	if !ValidMessageType(data[0]) {
		return ErrInvalidType
	}
	m.Type = MessageType(data[0])
	m.Data = data[1:]
	return nil
}
