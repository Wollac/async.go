package crypto

import (
	"bytes"
	"crypto"
	_ "crypto/sha512"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/suites"
)

// used hash function
var hash = crypto.SHA512

// ImplicateLen returns the length of Implicate in bytes.
func ImplicateLen(g kyber.Group) int {
	return SecretLen(g) + g.ScalarLen() + 2*g.PointLen()
}

// Implicate returns the secret as well as a proof of correctness.
// The proof is a NIZK that sk∗G=pk ∧ sk∗pk_d=secret.
func Implicate(suite suites.Suite, dealerPublic kyber.Point, ownPrivate kyber.Scalar) []byte {
	var buf bytes.Buffer
	buf.Write(Secret(suite, dealerPublic, ownPrivate))

	p := proveDLEQ(suite, suite.Point().Base(), dealerPublic, ownPrivate)
	if _, err := p.sigma.MarshalTo(&buf); err != nil {
		panic(err)
	}
	if _, err := p.R1.MarshalTo(&buf); err != nil {
		panic(err)
	}
	if _, err := p.R2.MarshalTo(&buf); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

// CheckImplicate verifies whether data is a correct implicate from peer.
// It returns the secret which can then be used to decrypt the corresponding share.
func CheckImplicate(g kyber.Group, dealerPublic kyber.Point, peerPublic kyber.Point, data []byte) ([]byte, error) {
	if len(data) != ImplicateLen(g) {
		return nil, ErrInvalidInputLength
	}
	buf := bytes.NewBuffer(data)

	K := g.Point()
	if _, err := PointUnmarshalFrom(K, buf); err != nil {
		return nil, fmt.Errorf("invalid shared key: %w", err)
	}

	sigma := g.Scalar()
	if _, err := ScalarUnmarshalFrom(sigma, buf); err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}
	R1 := g.Point()
	if _, err := PointUnmarshalFrom(R1, buf); err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}
	R2 := g.Point()
	if _, err := PointUnmarshalFrom(R2, buf); err != nil {
		return nil, fmt.Errorf("invalid proof: %w", err)
	}

	if !verifyDLEQ(g, g.Point().Base(), dealerPublic, peerPublic, K, proof{sigma, R1, R2}) {
		return nil, ErrVerificationFailed
	}
	return mustMarshalBinary(K), nil
}

// proof stores the proof constructed by proveDLEQ.
type proof struct {
	sigma  kyber.Scalar
	R1, R2 kyber.Point
}

// proveDLEQ constructs a proof that the prover knows s with S1=s⋅G and S2=s⋅H.
func proveDLEQ(suite suites.Suite, G kyber.Point, H kyber.Point, s kyber.Scalar) proof {
	// statement
	S1 := suite.Point().Mul(s, G)
	S2 := suite.Point().Mul(s, H)

	// commitment
	// R1, R2 ← r⋅G, r⋅B
	r := suite.Scalar().Pick(suite.RandomStream())
	R1 := suite.Point().Mul(r, G)
	R2 := suite.Point().Mul(r, H)

	// challenge
	// c ← H(G ∥ H ∥ S1 ∥ S2 ∥ R1 ∥ R2)
	h := hash.New()
	G.MarshalTo(h)
	H.MarshalTo(h)
	S1.MarshalTo(h)
	S2.MarshalTo(h)
	R1.MarshalTo(h)
	R2.MarshalTo(h)
	digest := make([]byte, 0, hash.Size())
	digest = h.Sum(digest)
	c := suite.Scalar().SetBytes(digest)

	// response
	// σ ← c⋅s + r
	sigma := suite.Scalar()
	sigma.Mul(s, c).Add(sigma, r)

	return proof{sigma, R1, R2}
}

// verifyDLEQ validates a proof whether the prover knows s with S1=s⋅G and S2=s⋅H.
func verifyDLEQ(g kyber.Group, G kyber.Point, H kyber.Point, S1 kyber.Point, S2 kyber.Point, p proof) bool {
	// c ← H(G ∥ H ∥ S1 ∥ S2 ∥ R1 ∥ R2)
	h := hash.New()
	G.MarshalTo(h)
	H.MarshalTo(h)
	S1.MarshalTo(h)
	S2.MarshalTo(h)
	p.R1.MarshalTo(h)
	p.R2.MarshalTo(h)
	digest := make([]byte, 0, hash.Size())
	digest = h.Sum(digest)
	c := g.Scalar().SetBytes(digest)

	// validate
	// (σ⋅G == c⋅S1 + R1) ∧ (σ⋅H == c⋅S2 + R2)
	left := g.Point()
	left.Add(G, H).Mul(p.sigma, left)

	right := g.Point()
	right.Add(S1, S2).Mul(c, right).Add(right, p.R1).Add(right, p.R2)

	return left.Equal(right)
}
