package goUmbral

import (
	"github.com/nucypher/goUmbral/math"
	"github.com/nucypher/goUmbral/openssl"
)

const (
	DEFAULT_CURVE = openssl.SECP256K1
)

func defaultCurve() (*openssl.Curve, error) {
	return openssl.NewCurve(DEFAULT_CURVE)
}

func defaultParams() (*math.UmbralParameters, error) {
	defaultCurve, err := defaultCurve()
	if err != nil {
		return nil, err
	}
	return math.NewUmbralParameters(defaultCurve)
}
