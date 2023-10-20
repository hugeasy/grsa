package grsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// pemEncode 密钥转换为 PEM 格式
func pemEncode(blockType string, key []byte) (string, error) {
	buf := bytes.NewBuffer(nil)
	block := &pem.Block{
		Type:  blockType,
		Bytes: key,
	}
	if err := pem.Encode(buf, block); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// parsePrivateKey 解析字符串格式 PEM 私钥
// 支持密钥格式：PKCS#1、PKCS#8
// 私钥示例如下：
/*
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCLt6LfyKpvZ48EuLtUA05kQdY/hfKH38vzcKY4QUOgcA9G7EBV
KG6o9kaTpG/QLDUpsjleZ+iEBSc2XntiRhFUbMVvtxjGzhBhg8UpwwSwAVIHEnP/
DRHb4y6GysoSiOTGYNWEL1a6FkrYUFygaqF4clrNDXU/oIWpL8s3ljvkpQIDAQAB
AoGAD86OVEAZHDJ8qT2XH/mhyFD0gspONpYYtmmDvLCRjJiw+canvpqs7luyf2im
p8ggmZ+KwwYBddI5bfrBfcxMkHRGcBgwU4mVdgqrwZYWiY+yOihQLmE7Sjb05VKA
u81eRJxiNvVtsO/Kf4tK+UgeoIvju6s2AGwWVzaCx7pU7z8CQQCzsoWzyMgsfPeL
6mPCtzZmBQGquuANs+jeDaSjIn2uO9YQ3TRjQNd60jG8zIzN1ROCbr9XQiXwCn95
SG0b3hrjAkEAxwszq/q0joRbGYrnXA3AGkODlR1G7lJ0JGxd7/7JNfJcaTcWTg6W
X1hJkWvoNXrNJ/vzgfjDMkJAjsDctFBw1wJAGKnhBfsB1nFUfKSwCpKg6cG4J9m8
VMUjqg6PUUCzpU1bJTdnMFQ+/wGIiBQ/IyUip11R78UJdffK5TeWmiOS5wJAdZN3
ZXrF1331tmPoAOead6kz/Ax8TuFj+/QLlW4i+3v7/KbuxRM23oFvi7h7RcQRljHt
iPQikfiy2+CvPtBZpwJAJmHin43CmVS1U+MWGy8wNv9ktdp9IcizP/huqyKnc3mT
+odf/LFMlMqoAWdY38vaU+WlFo8L43CD5QgfjVbpLw==
-----END RSA PRIVATE KEY-----
*/
func parsePrivateKey(s string) (*rsa.PrivateKey, error) {
	// block
	block, _ := pem.Decode([]byte(s))
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return privateKey, nil
	}
	// parse
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	var ok bool
	if privateKey, ok = key.(*rsa.PrivateKey); !ok {
		return nil, errors.New("parse RSA private key error")
	}
	return privateKey, nil
}

// parsePublicKey 解析公钥
func parsePublicKey(s string) (*rsa.PublicKey, error) {
	// block
	block, _ := pem.Decode([]byte(s))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// parse
	publicKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("parse RSA public key error")
	}
	return publicKey, nil
}
