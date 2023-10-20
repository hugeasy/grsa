package grsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

type KeyFormat uint8

const (
	PKCS1 KeyFormat = iota // PKCS#1
	PKCS8                  // PKCS#8
)

var KeyFormatErr = errors.New("key format error")

type KeyPair struct {
	privateKey []byte
	publicKey  []byte
}

func (kp KeyPair) ToPEM() (privateKey string, publicKey string, err error) {
	// private key
	privateKey, err = pemEncode("RSA PRIVATE KEY", kp.privateKey)
	if err != nil {
		return "", "", err
	}

	// public key
	publicKey, err = pemEncode("PUBLIC KEY", kp.publicKey)
	return
}

func (kp KeyPair) ToHex() (privateKey string, publicKey string) {
	privateKey = hex.EncodeToString(kp.privateKey)
	publicKey = hex.EncodeToString(kp.publicKey)
	return
}

// Generate generate key pair
func Generate(bits int, format KeyFormat) (KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return KeyPair{}, err
	}

	var privateKeyByte, publicKeyByte []byte
	switch format {
	case PKCS1:
		privateKeyByte = x509.MarshalPKCS1PrivateKey(privateKey)
	case PKCS8:
		privateKeyByte, err = x509.MarshalPKCS8PrivateKey(privateKey)
	default:
		return KeyPair{}, KeyFormatErr
	}

	publicKeyByte, err = x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return KeyPair{}, err
	}

	return KeyPair{
		privateKey: privateKeyByte,
		publicKey:  publicKeyByte,
	}, err
}
