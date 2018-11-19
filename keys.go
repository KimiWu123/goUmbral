package goUmbral

import (
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"math/rand"

	umbralMath "github.com/nucypher/goUmbral/math"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	KEY_SIZE   = 32
	NONCE_SIZE = 24

	SCRYPT_COST = 20
)

type UmbralPrivateKey struct {
	params *umbralMath.UmbralParameters
	bnKey  *umbralMath.ModBigNum
	pubKey *UmbralPublicKey
}

func NewUmbralPrivateKey(bnKey *umbralMath.ModBigNum, params *umbralMath.UmbralParameters) (*UmbralPrivateKey, error) {
	err := params.G.Mul(params.G, bnKey)
	if err != nil {
		return nil, err
	}

	pubKey := NewUmbralPublicKey(params.G, params)
	return &UmbralPrivateKey{params: params, bnKey: bnKey, pubKey: pubKey}, nil
}

func GenUmbralPrivateKey(params *umbralMath.UmbralParameters) (*UmbralPrivateKey, error) {
	if params == nil {
		return nil, errors.New("params is nil, Construct params first")
	}

	ranKey, err := umbralMath.GenRandModBN(params.Curve)
	if err != nil {
		return nil, err
	}
	return NewUmbralPrivateKey(ranKey, params)
}

func BytesToUmbralPrivateKey(keyBytes []byte, params *umbralMath.UmbralParameters, password []byte, scryptCost int) (*UmbralPrivateKey, error) {
	if params == nil {
		return nil, errors.New("params is nil, Construct params first")
	}
	if len(keyBytes) == 0 {
		return nil, errors.New("keyBytes is nil, Construct keyBytes first")
	}

	if scryptCost == -1 {
		scryptCost = SCRYPT_COST
	}
	if len(password) != 0 {
		salt := keyBytes[len(keyBytes)-16:]
		keyBytes = keyBytes[:len(keyBytes)-16]
		key, err := scrypt.Key(password, salt, int(math.Pow(float64(2), float64(scryptCost))), 8, 1, KEY_SIZE)
		if err != nil {
			return nil, err
		}
		var secretKey [KEY_SIZE]byte
		copy(secretKey[:], key)

		var ok bool
		var decryptNonce [NONCE_SIZE]byte
		copy(decryptNonce[:], keyBytes[:NONCE_SIZE])
		keyBytes, ok = secretbox.Open(nil, keyBytes[NONCE_SIZE:], &decryptNonce, &secretKey)
		if !ok {
			return nil, errors.New("decrypt keyBytes failed")
		}
	}

	bnKey, err := umbralMath.BytesToModBN(keyBytes, params.Curve)
	if err != nil {
		return nil, err
	}
	return NewUmbralPrivateKey(bnKey, params)
}

func (u *UmbralPrivateKey) Bytes(password []byte, scryptCost int) ([]byte, error) {
	umbralPrvKey, err := u.bnKey.Bytes()
	if err != nil {
		return nil, err
	}

	if len(password) != 0 {
		salt := make([]byte, 16)
		rand.Read(salt)

		key, err := scrypt.Key(password, salt, int(math.Pow(float64(2), float64(scryptCost))), 8, 1, KEY_SIZE)
		if err != nil {
			return nil, err
		}
		var secretKey [KEY_SIZE]byte
		copy(secretKey[:], key)

		var nonce [24]byte
		rand.Read(nonce[:])
		umbralPrvKey = secretbox.Seal(nil, umbralPrvKey, &nonce, &secretKey)
		umbralPrvKey = append(umbralPrvKey, salt...)
	}

	return umbralPrvKey, nil
}

func (u *UmbralPrivateKey) GetPubKey() *UmbralPublicKey {
	return u.pubKey
}

// func (u *UmbralPrivateKey) ToCryptographyPrivateKey() (*ecdsa.PrivateKey, error) {

// }

func (u *UmbralPrivateKey) Free() {
	u.bnKey.Free()
	u.pubKey.Free()
}

type UmbralPublicKey struct {
	params   *umbralMath.UmbralParameters
	pointKey *umbralMath.Point
}

func NewUmbralPublicKey(point *umbralMath.Point, params *umbralMath.UmbralParameters) *UmbralPublicKey {
	return &UmbralPublicKey{params: params, pointKey: point}
}

func (u *UmbralPublicKey) BytesToNewUmbralPublicKey(keyBytes []byte, params *umbralMath.UmbralParameters) (*UmbralPublicKey, error) {
	if params == nil {
		return nil, errors.New("params is nil, Construct params first")
	}
	if len(keyBytes) == 0 {
		return nil, errors.New("keyBytes is nil, Construct keyBytes first")
	}

	pointKey, err := umbralMath.BytesToPoint(keyBytes, params.Curve)
	if err != nil {
		return nil, err
	}
	return NewUmbralPublicKey(pointKey, params), nil
}

func (u *UmbralPublicKey) Bytes(isCompressed bool) ([]byte, error) {
	return u.pointKey.ToBytes(isCompressed)
}

// func (u *UmbralPublicKey) ToCryptographyPublicKey() (*ecdsa.PublicKey, error) {
// }

func (u *UmbralPublicKey) Free() {
	u.pointKey.Free()
}

type UmbralKeyingMaterial struct {
	keyingMaterial []byte
}

func NewUmbralKeyingMaterial(keyingMaterial []byte) (*UmbralKeyingMaterial, error) {
	if len(keyingMaterial) == 0 {
		var randKey [64]byte
		rand.Read(randKey[:])
		return &UmbralKeyingMaterial{keyingMaterial: randKey[:]}, nil
	} else {
		if len(keyingMaterial) < 32 {
			return nil, errors.New("UmbralKeyingMaterial must have size at least 32 bytes.")
		}
	}
	return &UmbralKeyingMaterial{keyingMaterial: keyingMaterial}, nil
}

func (u *UmbralKeyingMaterial) DerivePrivateKeyByLabel(label []byte, salt []byte, params *umbralMath.UmbralParameters) (*UmbralPrivateKey, error) {
	if params == nil {
		return nil, errors.New("params is nil, Construct params first")
	}

	info := append([]byte("NuCypher/KeyDerivation/"), label...)
	// TODO, To support "blake2b"
	hkdfKey := hkdf.New(sha256.New, u.keyingMaterial, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfKey, key); err != nil {
		return nil, err
	}

	modBN, err := umbralMath.HashToModBN(key, params)
	if err != nil {
		return nil, err
	}
	return NewUmbralPrivateKey(modBN, params)
}

func (u *UmbralKeyingMaterial) BytesToUmbralKeyingMaterial(keyBytes []byte, password []byte, scryptCost int) (*UmbralKeyingMaterial, error) {
	if len(keyBytes) == 0 {
		return nil, errors.New("keyBytes is nil, Construct keyBytes first")
	}

	if scryptCost == -1 {
		scryptCost = SCRYPT_COST
	}
	if len(password) != 0 {
		salt := keyBytes[len(keyBytes)-16:]
		keyBytes = keyBytes[:len(keyBytes)-16]
		key, err := scrypt.Key(password, salt, int(math.Pow(float64(2), float64(scryptCost))), 8, 1, KEY_SIZE)
		if err != nil {
			return nil, err
		}
		var secretKey [KEY_SIZE]byte
		copy(secretKey[:], key)

		var ok bool
		var decryptNonce [NONCE_SIZE]byte
		copy(decryptNonce[:], keyBytes[:NONCE_SIZE])
		keyBytes, ok = secretbox.Open(nil, keyBytes[NONCE_SIZE:], &decryptNonce, &secretKey)
		if !ok {
			return nil, errors.New("decrypt keyBytes failed")
		}
	}

	return NewUmbralKeyingMaterial(keyBytes)
}

func (u *UmbralKeyingMaterial) Bytes(password []byte, scryptCost int) ([]byte, error) {
	keyingMaterial := u.keyingMaterial

	if len(password) != 0 {
		salt := make([]byte, 16)
		rand.Read(salt)

		key, err := scrypt.Key(password, salt, int(math.Pow(float64(2), float64(scryptCost))), 8, 1, KEY_SIZE)
		if err != nil {
			return nil, err
		}
		var secretKey [KEY_SIZE]byte
		copy(secretKey[:], key)

		var nonce [24]byte
		rand.Read(nonce[:])
		keyingMaterial = secretbox.Seal(nil, keyingMaterial, &nonce, &secretKey)
		keyingMaterial = append(keyingMaterial, salt...)
	}

	return keyingMaterial, nil
}
