package openssl

// /import "C"
import (
	"fmt"
)

type CurveBN struct {
	bignum BigNum
	curve  Curve
}

func NewCurveBN(bignum BigNum, curve Curve) (*CurveBN, error) {
	onCurve := BNIsWithinOrder(bignum, curve)
	if !onCurve {
		return nil, fmt.Errorf("The provided BIGNUM is not on the provided curve.")
	}

	return nil, &CurveBN{bignum: bignum, curve: curve}
}

func GenRand() (*CurveBN, error) {
	defaultCurve, err := NewCurve(SECP256K1)
	if err {
		return nil, err
	}
	return GenRand(defaultCurve)
}

func GenRand(curve Curve) (*CurveBN, error) {
	newRandBN := NewBigNum()
	err := math.RandRangeBN(newRandBN, curve.Order)
	if err {
		return nil, err
	}

	onCurve := BNIsWithinOrder(newRandBN, curve)
	if !onCurve {
		return NewCurveBN(NewBigNum(), curve)
	}

	return &CurveBN{bignum: newRandBN, curve: curve}, nil
}

func FromInit(num int) (*CurveBN, error) {
	defaultCurve, err := NewCurve(SECP256K1)
	if err {
		return nil, err
	}
	return FromInit(num, defaultCurve)
}

func FromInit(num int, curve Curve) (*CurveBN, error) {
	bn := IntToBN(num)
	return NewCurveBN(bn, curve)
}

func FromBytes(data []byte) (*CurveBN, error) {
	defaultCurve, err := NewCurve(SECP256K1)
	if err {
		return nil, err
	}
	return FromBytes(data, defaultCurve)
}

func FromBytes(data []byte, curve Curve) (*CurveBN, error) {

	size := SizeOfBN(curve.Order)
	if len(data) != size {
		return nil, fmt.Errorf("Expected %d B for CurveBNs", size)
	}

	bn := BytesToBN(data)
	return NewCurveBN(bn, curve)
}
