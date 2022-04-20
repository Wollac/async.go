package crypto

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"hash"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
)

// ImplicateLen returns the length of Implicate in bytes.
func ImplicateLen(g kyber.Group) int {
	return SecretLen(g) + g.ScalarLen() + 2*g.PointLen()
}

// Implicate returns the secret as well as a proof of correctness.
// The proof is a NIZK that sk∗G=pk ∧ sk∗pk_d=secret.
func Implicate(suite suites.Suite, dealerPublic kyber.Point, ownPrivate kyber.Scalar) []byte {
	var buf bytes.Buffer
	buf.Write(Secret(suite, dealerPublic, ownPrivate))

	s, R1, R2 := dleqProof(suite, sha512.New(), nil, dealerPublic, ownPrivate)
	if _, err := s.MarshalTo(&buf); err != nil {
		panic(fmt.Sprintf("crypto: internal error: %v", err))
	}
	if _, err := R1.MarshalTo(&buf); err != nil {
		panic(fmt.Sprintf("crypto: internal error: %v", err))
	}
	if _, err := R2.MarshalTo(&buf); err != nil {
		panic(fmt.Sprintf("crypto: internal error: %v", err))
	}

	return buf.Bytes()
}

// CheckImplicate verifies whether data is a correct implicate from peer.
// It returns the secret which can then be used to decrypt the corresponding share.
func CheckImplicate(suite suites.Suite, dealerPublic kyber.Point, peerPublic kyber.Point, data []byte) ([]byte, error) {
	if len(data) != ImplicateLen(suite) {
		return nil, ErrInvalidInputLength
	}
	buf := bytes.NewBuffer(data)

	K := suite.Point()
	if _, err := PointUnmarshalFrom(K, buf); err != nil {
		return nil, fmt.Errorf("invalid shared key: %w", err)
	}

	s := suite.Scalar()
	if _, err := ScalarUnmarshalFrom(s, buf); err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}
	R1 := suite.Point()
	if _, err := PointUnmarshalFrom(R1, buf); err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}
	R2 := suite.Point()
	if _, err := PointUnmarshalFrom(R2, buf); err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}

	if !verify(suite, sha512.New(), nil, dealerPublic, peerPublic, K, s, R1, R2) {
		return nil, ErrVerificationFailed
	}
	secret, _ := K.MarshalBinary()
	return secret, nil
}

func dleqProof(suite suites.Suite, h hash.Hash, G kyber.Point, H kyber.Point, secret kyber.Scalar) (kyber.Scalar, kyber.Point, kyber.Point) {
	// encrypt base points with secret
	xG := suite.Point().Mul(secret, G)
	xH := suite.Point().Mul(secret, H)

	// Commitment
	v := suite.Scalar().Pick(suite.RandomStream())
	vG := suite.Point().Mul(v, G)
	vH := suite.Point().Mul(v, H)

	// Challenge
	xG.MarshalTo(h)
	xH.MarshalTo(h)
	vG.MarshalTo(h)
	vH.MarshalTo(h)
	cb := h.Sum(nil)
	c := suite.Scalar().Pick(suite.XOF(cb))

	// Response
	r := suite.Scalar()
	r.Mul(secret, c).Add(r, v)

	return r, vG, vH
}

func verify(suite suites.Suite, h hash.Hash, G kyber.Point, H kyber.Point, xG kyber.Point, xH kyber.Point, r kyber.Scalar, vG kyber.Point, vH kyber.Point) bool {
	// Challenge
	xG.MarshalTo(h)
	xH.MarshalTo(h)
	vG.MarshalTo(h)
	vH.MarshalTo(h)
	cb := h.Sum(nil)
	c := suite.Scalar().Pick(suite.XOF(cb))

	R := suite.Point()

	// r * G == c * xG + vG
	R = R.Mul(c, xG).Add(R, vG)
	if !suite.Point().Mul(r, G).Equal(R) {
		return false
	}

	// r * H == c * xH + vH
	R = R.Mul(c, xH).Add(R, vH)
	return suite.Point().Mul(r, H).Equal(R)
}
