package acss

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	AEADKeySize  = chacha20poly1305.KeySize
	AEADOverhead = chacha20poly1305.Overhead
)

// dhExchange computes the shared key from a private key and a public key
func dhExchange(group kyber.Group, ownPrivate kyber.Scalar, remotePublic kyber.Point) []byte {
	dh := group.Point().Mul(ownPrivate, remotePublic)
	data, err := dh.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return data
}

// newAEAD creates a new AEAD cipher based on secret and info.
func newAEAD(secret []byte, info []byte) cipher.AEAD {
	h := hkdf.New(sha256.New, secret, nil, info)
	key := make([]byte, AEADKeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}

	// in order to use AES-128-GCM:
	// block, _ := aes.NewCipher(key)
	// aead, err := cipher.NewGCM(block)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(fmt.Sprintf("acss: internal error: %v", err))
	}
	return aead
}

// encryptScalar encrypts a scalar and returns the cipher text.
func encryptScalar(s kyber.Scalar, aead cipher.AEAD) []byte {
	sBytes, err := s.MarshalBinary()
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, sBytes, nil)
}

// decryptScalar decrypts cipherText and sets the corresponding scalar dst.
func decryptScalar(dst kyber.Scalar, aead cipher.AEAD, cipherText []byte) error {
	nonce := make([]byte, aead.NonceSize())
	plaintext, err := aead.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return err
	}
	if err := dst.UnmarshalBinary(plaintext); err != nil {
		return err
	}
	return nil
}

// Sign creates a signature from a msg and a private key using base as the base point.
// It is a copy of schnorr.Sign from go.dedis.ch/kyber/v3/sign/schnorr supporting a non-standard base point.
func Sign(s suites.Suite, base kyber.Point, private kyber.Scalar, msg []byte) ([]byte, error) {
	var g kyber.Group = s
	// create random secret k and public point commitment R
	k := g.Scalar().Pick(s.RandomStream())
	R := g.Point().Mul(k, base)

	// create hash(public || R || message)
	public := g.Point().Mul(private, base)
	h, err := hash(g, public, R, msg)
	if err != nil {
		return nil, err
	}

	// compute response s = k + x*h
	xh := g.Scalar().Mul(private, h)
	S := g.Scalar().Add(k, xh)

	// return R || s
	var b bytes.Buffer
	if _, err := R.MarshalTo(&b); err != nil {
		return nil, err
	}
	if _, err := S.MarshalTo(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Verify verifies a given Schnorr signature. It returns nil iff the given signature is valid.
// It is a copy of schnorr.VerifyWithChecks from go.dedis.ch/kyber/v3/sign/schnorr supporting a non-standard base point.
func Verify(g kyber.Group, base kyber.Point, public kyber.Point, msg, sig []byte) error {
	type scalarCanCheckCanonical interface {
		IsCanonical(b []byte) bool
	}

	type pointCanCheckCanonicalAndSmallOrder interface {
		HasSmallOrder() bool
		IsCanonical(b []byte) bool
	}

	R := g.Point()
	s := g.Scalar()
	pointSize := R.MarshalSize()
	scalarSize := s.MarshalSize()
	sigSize := scalarSize + pointSize
	if len(sig) != sigSize {
		return fmt.Errorf("schnorr: signature of invalid length %d instead of %d", len(sig), sigSize)
	}
	if err := R.UnmarshalBinary(sig[:pointSize]); err != nil {
		return err
	}
	if p, ok := R.(pointCanCheckCanonicalAndSmallOrder); ok {
		if !p.IsCanonical(sig[:pointSize]) {
			return fmt.Errorf("R is not canonical")
		}
		if p.HasSmallOrder() {
			return fmt.Errorf("R has small order")
		}
	}
	if s, ok := g.Scalar().(scalarCanCheckCanonical); ok && !s.IsCanonical(sig[pointSize:]) {
		return fmt.Errorf("signature is not canonical")
	}
	if err := s.UnmarshalBinary(sig[pointSize:]); err != nil {
		return err
	}

	// recompute hash(public || R || msg)
	h, err := hash(g, public, R, msg)
	if err != nil {
		return err
	}

	// compute S = B^s
	S := g.Point().Mul(s, base)
	// compute RAh = R + A^h
	Ah := g.Point().Mul(h, public)
	RAs := g.Point().Add(R, Ah)

	if !S.Equal(RAs) {
		return errors.New("schnorr: invalid signature")
	}

	return nil
}

func hash(g kyber.Group, public, r kyber.Point, msg []byte) (kyber.Scalar, error) {
	h := sha512.New()
	if _, err := r.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := public.MarshalTo(h); err != nil {
		return nil, err
	}
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return g.Scalar().SetBytes(h.Sum(nil)), nil
}
