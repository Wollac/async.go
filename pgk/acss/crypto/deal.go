package crypto

import (
	"bytes"
	"errors"
	"fmt"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

func ShareLen(g kyber.Group) int {
	return g.ScalarLen() + AEADOverhead
}

// DealLen returns the length of the deal in bytes.
func DealLen(g kyber.Group, n int) int {
	t := (n-1)/3 + 1 // threshold is fixed ⌊n/3⌋+1
	// t commitments, ephemeral public key, n encrypted shares
	return t*g.PointLen() + g.PointLen() + n*ShareLen(g)
}

// Deal creates data necessary to distribute scalar to the peers.
// It returns the commitments C, public key pk_d and the encrypted shares Z.
func Deal(suite suites.Suite, pubKeys []kyber.Point, scalar kyber.Scalar) []byte {
	buf := &bytes.Buffer{}
	n := len(pubKeys)
	t := (n-1)/3 + 1 // threshold is fixed ⌊n/3⌋+1

	// generate Feldman commitments
	poly := share.NewPriPoly(suite, t, scalar, suite.RandomStream())
	_, commits := poly.Commit(nil).Info()
	// include all commitments
	for _, p := range commits {
		if _, err := p.MarshalTo(buf); err != nil {
			panic(fmt.Sprintf("crypto: internal error: %v", err))
		}
	}

	// generate ephemeral keypair
	sk := suite.Scalar().Pick(suite.RandomStream())
	pk := suite.Point().Mul(sk, nil)
	// include ephemeral public key
	if _, err := pk.MarshalTo(buf); err != nil {
		panic(fmt.Sprintf("crypto: internal error: %v", err))
	}

	// generate n shares
	priShares := poly.Shares(n)
	for i, pubkey := range pubKeys {
		// compute shared DH secret
		secret := Secret(suite, pubkey, sk)
		// encrypt with that secret
		encryptedShare := encryptScalar(priShares[i].V, newAEAD(secret, nil))
		// include the encrypted share
		buf.Write(encryptedShare)
	}

	return buf.Bytes()
}

// CheckDeal verifies a deal.
// If an error is returned, the data is invalid and cannot be used by any peer.
// Otherwise, it returns the commitments C, public key pk_d and the encrypted shares.
func CheckDeal(suite suites.Suite, n int, data []byte) (*share.PubPoly, kyber.Point, [][]byte, error) {
	if len(data) != DealLen(suite, n) {
		return nil, nil, nil, ErrInvalidInputLength
	}

	buf := bytes.NewBuffer(data)
	t := (n-1)/3 + 1 // threshold is fixed ⌊n/3⌋+1
	// load all commitments
	commits := make([]kyber.Point, t)
	for i := range commits {
		p := suite.Point()
		if _, err := PointUnmarshalFrom(p, buf); err != nil {
			return nil, nil, nil, fmt.Errorf("invalid commitment %d: %w", i, err)
		}
		commits[i] = p
	}
	pubPoly := share.NewPubPoly(suite, nil, commits)

	// load the dealer public key
	dealerPubKey := suite.Point()
	if _, err := PointUnmarshalFrom(dealerPubKey, buf); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid dealer public key: %w", err)
	}

	// load all N encrypted shares
	shareLen := ShareLen(suite)
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, shareLen)
		if _, err := buf.Read(shares[i]); err != nil {
			return nil, nil, nil, err
		}
	}

	return pubPoly, dealerPubKey, shares, nil
}

// DecryptShare decrypts and validates the encrypted share with the given index using the given secret.
// An error is returned if no valid share could be decrypted.
func DecryptShare(suite suites.Suite, pubPoly *share.PubPoly, shares [][]byte, index int, secret []byte) (*share.PriShare, error) {
	if len(secret) != suite.PointLen() {
		return nil, errors.New("invalid secret length")
	}
	v := suite.Scalar()
	if err := decryptScalar(v, newAEAD(secret, nil), shares[index]); err != nil {
		return nil, fmt.Errorf("decryption failed: %s", err)
	}
	s := &share.PriShare{I: index, V: v}
	if !pubPoly.Check(s) {
		return nil, ErrVerificationFailed
	}
	return s, nil
}
