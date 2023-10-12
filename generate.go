package grsa

type KeyFormat uint8

const (
	PKCS1 KeyFormat = iota // PKCS#1
	PKCS8                  // PKCS#8
)

type KeyPair struct {
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
}

func (kp KeyPair) ToPEM() (string, string) {

	return "", ""
}

func (kp KeyPair) ToHex() (string, string) {

	return "", ""
}

// GenerateKeyPair generate key pair
func GenerateKeyPair(bits int, format KeyFormat, password ...string) (KeyPair, error) {

	return KeyPair{}, nil
}
