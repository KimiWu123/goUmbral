package goUmbral

import (
	"bytes"

	"github.com/nucypher/goUmbral/math"
	"github.com/nucypher/goUmbral/openssl"
)

const (
	NO_KEY                   = 0x00
	DELEGATING_ONLY          = 0x01
	RECEIVING_ONLY           = 0x02
	DELEGATING_AND_RECEIVING = 0x03
)

type KFrag struct {
	id                []byte
	bnKey             *math.ModBigNum
	pointCommitment   *math.Point
	pointPrecursor    *math.Point
	signatureForProxy *Signature
	signatureForBob   *Signature
	keysInSignature   byte
}

func NewKFrag(
	identifier []byte,
	bnKey *math.ModBigNum,
	pointCommitment *math.Point,
	pointPrecursor *math.Point,
	signatureForProxy *Signature,
	signatureForBob *Signature) *KFrag {

	return &KFrag{
		id:                identifier,
		bnKey:             bnKey,
		pointCommitment:   pointCommitment,
		pointPrecursor:    pointPrecursor,
		signatureForProxy: signatureForProxy,
		signatureForBob:   signatureForBob,
		keysInSignature:   DELEGATING_AND_RECEIVING}
}

func KFragLength(curve *openssl.Curve) int {
	if curve == nil {
		return 0
	}
	return 0
}

func BytesToKFrag(data []byte, curve *openssl.Curve) (*KFrag, error) {
	if curve == nil {
		defaultcurve, err := defaultCurve()
		if err != nil {
			return nil, err
		}
		curve = defaultcurve
	}

	return nil, nil
}

func (k *KFrag) Bytes() ([]byte, error) {
	key, err := k.bnKey.Bytes()
	if err != nil {
		return nil, err
	}
	commitment, err := k.pointCommitment.ToBytes(true)
	if err != nil {
		return nil, err
	}
	precursor, err := k.pointPrecursor.ToBytes(true)
	if err != nil {
		return nil, err
	}
	signForProxy, err := k.signatureForProxy.Bytes()
	if err != nil {
		return nil, err
	}
	signForBob, err := k.signatureForBob.Bytes()
	if err != nil {
		return nil, err
	}

	data :=
		append(k.id, append(key,
			append(commitment,
				append(precursor,
					append(signForProxy, signForBob...)...)...)...)...)

	var b bytes.Buffer
	b.Write(data)
	b.WriteByte(k.keysInSignature)
	return b.Bytes(), nil
}

func (k *KFrag) Verify(
	signinPubKey *UmbralPublicKey,
	delegatePubKey *UmbralPublicKey,
	receivingPubKey *UmbralPublicKey,
	params *math.UmbralParameters) (bool, error) {

	var err error
	if params == nil {
		params, err = defaultParams()
	}
	if delegatePubKey != nil && delegatePubKey.params != params {
		panic("The delegating key uses different UmbralParameters")
	}
	if receivingPubKey != nil && receivingPubKey.params != params {
		panic("The receiving key uses different UmbralParameters")
	}

	correct_commitment := params.U
	correct_commitment.Mul(correct_commitment, k.bnKey)
	k.pointCommitment = correct_commitment

	var validateMessage []byte
	validateMessage = k.id

	b, err := k.pointCommitment.ToBytes(true)
	if err != nil {
		return false, err
	}
	validateMessage = append(validateMessage, b...)

	b, err = k.pointPrecursor.ToBytes(true)
	if err != nil {
		return false, err
	}
	validateMessage = append(validateMessage, b...)

	var buf bytes.Buffer
	buf.Write(validateMessage)
	buf.WriteByte(k.keysInSignature)
	validateMessage = buf.Bytes()

	if k.DelegatingKeyInSignature() {
		b, err = delegatePubKey.Bytes(true)
		if err != nil {
			return false, err
		}
		validateMessage = append(validateMessage, b...)
	}
	if k.ReceivingKeyInSignature() {
		b, err = receivingPubKey.Bytes(true)
		if err != nil {
			return false, err
		}
		validateMessage = append(validateMessage, b...)
	}

	valid, err := k.signatureForProxy.Verify(validateMessage, signinPubKey)
	if err != nil {
		return false, err
	}
	// TODO: return value is correct_commitment & valid_kfrag_signature in python
	return valid, nil

}

func (k *KFrag) DelegatingKeyInSignature() bool {
	return k.keysInSignature == DELEGATING_ONLY ||
		k.keysInSignature == RECEIVING_ONLY
}

func (k *KFrag) ReceivingKeyInSignature() bool {
	return k.keysInSignature == DELEGATING_ONLY ||
		k.keysInSignature == RECEIVING_ONLY
}

type CorrectnessProof struct {
	pointE2              *math.Point
	pointV2              *math.Point
	pointKFragCommitment *math.Point
	pointKFragPok        *math.Point
	bnSig                *math.ModBigNum
	kfragSignature       *Signature
	metadata             []byte
}

func NewCorrectnessProof(
	pointE2 *math.Point,
	pointV2 *math.Point,
	pointKFragCommitment *math.Point,
	pointKFragPok *math.Point,
	bnSig *math.ModBigNum,
	kfragSignature *Signature,
	metadata []byte) *CorrectnessProof {

	return &CorrectnessProof{
		pointE2:              pointE2,
		pointV2:              pointV2,
		pointKFragCommitment: pointKFragCommitment,
		pointKFragPok:        pointKFragPok,
		bnSig:                bnSig,
		kfragSignature:       kfragSignature,
		metadata:             metadata}
}

func CorrectnessProofLength(curve *openssl.Curve) int {
	if curve == nil {
		return 0
	}
	return 0
}

func BytesToCorrectnessProof(data []byte, curve *openssl.Curve) (*CorrectnessProof, error) {
	if curve == nil {
		defaultcurve, err := defaultCurve()
		if err != nil {
			return nil, err
		}
		curve = defaultcurve
	}

	return nil, nil

}

func (c *CorrectnessProof) Bytes() ([]byte, error) {

	e2, err := c.pointE2.ToBytes(true)
	if err != nil {
		return nil, err
	}
	v2, err := c.pointV2.ToBytes(true)
	if err != nil {
		return nil, err
	}
	kfragCommitment, err := c.pointKFragCommitment.ToBytes(true)
	if err != nil {
		return nil, err
	}
	kfragPok, err := c.pointKFragPok.ToBytes(true)
	if err != nil {
		return nil, err
	}

	bnBytes, err := c.bnSig.Bytes()
	if err != nil {
		return nil, err
	}

	sigBytes, err := c.kfragSignature.Bytes()
	if err != nil {
		return nil, err
	}

	data :=
		append(e2,
			append(v2,
				append(kfragCommitment,
					append(kfragPok,
						append(bnBytes,
							append(sigBytes, c.metadata...)...)...)...)...)...)
	return data, nil

}

type CapsuleFrag struct {
	pointE1        *math.Point
	pointV1        *math.Point
	kfragId        []byte
	pointPrecursor *math.Point
	proof          *CorrectnessProof
}

func NewCapsuleFrag(
	pointE1 *math.Point,
	pointV1 *math.Point,
	kfragId []byte,
	pointPrecursor *math.Point,
	proof *CorrectnessProof) *CapsuleFrag {

	return &CapsuleFrag{
		pointE1:        pointE1,
		pointV1:        pointV1,
		kfragId:        kfragId,
		pointPrecursor: pointPrecursor,
		proof:          proof}
}

func CapsuleFragLength(curve *openssl.Curve) int {
	if curve == nil {
		return 0
	}
	return 0
}

func BytesToCapsuleFrag(data []byte, curve *openssl.Curve) (*CapsuleFrag, error) {
	if curve == nil {
		defaultcurve, err := defaultCurve()
		if err != nil {
			return nil, err
		}
		curve = defaultcurve
	}
	return nil, nil
}

func (c *CapsuleFrag) Bytes() ([]byte, error) {
	e1, err := c.pointE1.ToBytes(true)
	if err != nil {
		return nil, err
	}
	v1, err := c.pointV1.ToBytes(true)
	if err != nil {
		return nil, err
	}
	precursor, err := c.pointPrecursor.ToBytes(true)
	if err != nil {
		return nil, err
	}

	data :=
		append(e1,
			append(v1,
				append(c.kfragId, precursor...)...)...)
	if c.proof != nil {
		b, err := c.proof.Bytes()
		if err != nil {
			return nil, err
		}
		data = append(data, b...)
	}
	return data, nil
}

func (c *CapsuleFrag) VerifyCorrectness() (bool, error) {
	return true, nil
}

func (c *CapsuleFrag) AttachProof(
	e2 *math.Point,
	v2 *math.Point,
	u1 *math.Point,
	u2 *math.Point,
	z3 *math.ModBigNum,
	kfragSignature *Signature,
	metadata []byte) {

	c.proof = &CorrectnessProof{
		pointE2:              e2,
		pointV2:              v2,
		pointKFragCommitment: u1,
		pointKFragPok:        u2,
		bnSig:                z3,
		kfragSignature:       kfragSignature,
		metadata:             metadata}
}
