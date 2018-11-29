package goUmbral

import (
	"encoding"
	"errors"
	"hash"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/nucypher/goUmbral/math"
	"github.com/nucypher/goUmbral/openssl"
	"golang.org/x/crypto/blake2b"
)

type Signature struct {
	r *math.ModBigNum
	s *math.ModBigNum
}

func NewSignature(r *math.ModBigNum, s *math.ModBigNum) (*Signature, error) {
	return &Signature{r: r, s: s}, nil
}

func SignatureLength(curve *openssl.Curve) (uint, error) {
	if curve == nil {
		defaultcurve, err := defaultCurve()
		if err != nil {
			return 0, err
		}
		curve = defaultcurve
	}
	size, err := curve.GroupOrderSize()
	return size * 2, err
}

func BytesToSignature(signatureBytes []byte, curve *openssl.Curve) (*Signature, error) {
	if curve == nil {
		defaultcurve, err := defaultCurve()
		if err != nil {
			return nil, err
		}
		curve = defaultcurve
	}
	r, err := math.BytesToModBN(signatureBytes[:32], curve)
	if err != nil {
		return nil, err
	}
	s, err := math.BytesToModBN(signatureBytes[33:], curve)
	if err != nil {
		return nil, err
	}
	return NewSignature(r, s)
}

func (s *Signature) Verify(message []byte, verifyingkey *UmbralPublicKey) (bool, error) {

	if message == nil || len(message) == 0 || verifyingkey == nil {
		return false, errors.New("invalid input arguments")
	}

	// hash message
	hashedMessage, err := blake2b.New256(message)
	if err != nil {
		return false, err
	}
	hashedMessageBytes, err := hashToBytes(hashedMessage)
	if err != nil {
		return false, err
	}

	signautre, err := s.encodeToBytes()
	if err != nil {
		return false, err
	}

	pubKey, err := verifyingkey.Bytes(true)
	if err != nil {
		return false, err
	}

	return crypto.VerifySignature(pubKey, hashedMessageBytes, signautre), nil
}

func (s *Signature) encodeToBytes() ([]byte, error) {
	rBytes, err := s.r.Bytes()
	if err != nil {
		return nil, err
	}
	sBytes, err := s.s.Bytes()
	if err != nil {
		return nil, err
	}

	signautre := make([]byte, 64)
	signautre = append(rBytes, sBytes...)
	return signautre, nil
}

func (s *Signature) Bytes() ([]byte, error) {
	return s.encodeToBytes()
}

func (s *Signature) Length() (int, error) {
	data, err := s.encodeToBytes()
	if err != nil {
		return 0, err
	}
	return len(data), nil
}

type Signer struct {
	privatekey *UmbralPrivateKey
	curve      *openssl.Curve
}

func NewSigner(prvKey *UmbralPrivateKey, curve *openssl.Curve) *Signer {
	return &Signer{privatekey: prvKey, curve: curve}
}

func (s *Signer) Sign(message []byte) (*Signature, error) {

	hashedMessage, err := blake2b.New256(message)
	if err != nil {
		return nil, err
	}
	hashedMessageBytes, err := hashToBytes(hashedMessage)
	if err != nil {
		return nil, err
	}

	ecdsaPrvKey, err := s.privatekey.ECDSAPrivateKey(nil, 0)
	if err != nil {
		return nil, err
	}

	signature, err := crypto.Sign(hashedMessageBytes, ecdsaPrvKey)
	if err != nil {
		return nil, err
	}
	return BytesToSignature(signature, nil)
}

func hashToBytes(hashedMessage hash.Hash) ([]byte, error) {
	marsahler, ok := hashedMessage.(encoding.BinaryMarshaler)
	if !ok {
		return nil, errors.New("blake2b hash256 doesn't implment encoding.BinaryMarshaler")
	}
	return marsahler.MarshalBinary()
}
