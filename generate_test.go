package grsa

import (
	"fmt"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair(1024, PKCS1)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(keyPair.ToPEM())
}
