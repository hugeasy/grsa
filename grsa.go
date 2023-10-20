package grsa

import (
	"crypto/rand"
	"crypto/rsa"
)

type Padding uint8

const (
	PKSC1Padding Padding = iota
	PKCS1OAEPPadding
	SSLV23Padding
)

func EncryptByPrivateKey(privateKey string, data []byte, padding ...Padding) ([]byte, error) {
	pk, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	return rsa.SignPKCS1v15(rand.Reader, pk, 0, data)
}

func EncryptByPublicKey(publicKey string, data []byte, padding ...Padding) ([]byte, error) {

	return nil, nil
}

func DecryptByPrivateKey(privateKey string, data []byte, padding ...Padding) ([]byte, error) {

	return nil, nil
}

func DecryptByPublicKey(publicKey string, data []byte, padding ...Padding) ([]byte, error) {

	return nil, nil
}
