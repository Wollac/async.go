package tlv

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sync"
)

// MaxValueLength denotes the maximum length of the value in bytes.
const MaxValueLength = math.MaxInt32

type (
	// TypeCode specifies the type code.
	TypeCode = byte
	// CallbackFunc specifies the type of callbacks.
	CallbackFunc func(value []byte) error
)

type Registry struct {
	mu        sync.Mutex
	callbacks map[TypeCode]CallbackFunc
	types     map[reflect.Type]TypeCode
}

func New() *Registry {
	return &Registry{
		callbacks: map[TypeCode]CallbackFunc{},
		types:     map[reflect.Type]TypeCode{},
	}
}

// Register registers a new type for the TLV-encoder.
// The type of m will be stored to allow type code selection with Write.
// The callback is called when a new value of that type is received.
// Register can be used to re-define the callback of a type, but it panics when
// a different t is registered for the same type.
func (r *Registry) Register(t TypeCode, m encoding.BinaryMarshaler, callback CallbackFunc) {
	mt := reflect.TypeOf(m)
	if callback == nil {
		panic("tlv: callback must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if typeCode, contains := r.types[mt]; contains && t != typeCode {
		panic(fmt.Sprintf("tlv: type '%v' already registered under a different code", mt))
	}
	r.callbacks[t] = callback
	r.types[mt] = t
}

// Handle reads the next TLV-encoded message from r and calls the corresponding callback with its value.
// It returns an error when the message is encoded incorrectly.
func (r *Registry) Handle(rd io.Reader) error {
	br := newByteReader(rd)
	t, err := br.ReadByte()
	if err != nil {
		return fmt.Errorf("failed to read type: %w", err)
	}
	l64, err := binary.ReadUvarint(br)
	if err != nil {
		return fmt.Errorf("failed to read length: %w", err)
	}
	if l64 > MaxValueLength {
		return errors.New("max value length exceeded")
	}
	callback := r.registeredCallback(t)
	if callback == nil {
		return fmt.Errorf("invalid type: %d", t)
	}

	// due to MaxValueLength this will not overflow even on 32-bit arch
	l := int(l64)
	data := make([]byte, l)
	for w := 0; w < l; {
		n, err := rd.Read(data[w:])
		if err != nil {
			return fmt.Errorf("failed to read data: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("failed to read data: %w", io.ErrNoProgress)
		}
		w += n
	}
	return callback(data)
}

// Write TLV-encodes m and writes it to m.
func (r *Registry) Write(w io.Writer, m encoding.BinaryMarshaler) error {
	t, ok := r.registeredType(reflect.TypeOf(m))
	if !ok {
		panic("tlv: type not registered")
	}

	data, err := m.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	return WriteBinary(w, t, data)
}

// WriteBinary TLV-encodes the binary data and writes it to m.
func WriteBinary(w io.Writer, t TypeCode, v []byte) error {
	if len(v) > MaxValueLength {
		panic("tlv: max value length exceeded")
	}

	if _, err := w.Write([]byte{t}); err != nil {
		return err
	}
	var buf [binary.MaxVarintLen32]byte
	n := binary.PutUvarint(buf[:], uint64(len(v)))
	if _, err := w.Write(buf[:n]); err != nil {
		return err
	}

	_, err := w.Write(v)
	return err
}

func (r *Registry) registeredCallback(t TypeCode) CallbackFunc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.callbacks[t]
}

func (r *Registry) registeredType(u reflect.Type) (TypeCode, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.types[u]
	return t, ok
}
