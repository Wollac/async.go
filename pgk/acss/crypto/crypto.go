package crypto

import (
	"crypto/cipher"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var (
	ErrNotCanonical       = errors.New("not canonical")
	ErrSmallOrder         = errors.New("small order")
	ErrInvalidInputLength = errors.New("invalid input length")
	ErrVerificationFailed = errors.New("verification failed")
)

const (
	AEADKeySize  = chacha20poly1305.KeySize
	AEADOverhead = chacha20poly1305.Overhead
)

// SecretLen returns the length of Secret in bytes.
func SecretLen(g kyber.Group) int {
	return g.PointLen()
}

// Secret computes and returns the shared ephemeral secret.
func Secret(g kyber.Group, remotePublic kyber.Point, ownPrivate kyber.Scalar) []byte {
	dh := g.Point().Mul(ownPrivate, remotePublic)
	data, err := dh.MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("crypto: internal error: %v", err))
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
