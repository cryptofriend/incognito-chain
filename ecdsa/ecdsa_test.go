package ecdsa

import (
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/privacy"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestECDSASign(t *testing.T) {
	data := privacy.RandBytes(100)
	hash := common.HashB(data)

	ecdsaPrivateKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Printf("Error when generate ECDSA key: %v\n", err)
	}
	assert.Equal(t, nil, err)

	ecdsaPublicKey := ecdsaPrivateKey.PublicKey
	ecdsaPublicKeyBytes := crypto.CompressPubkey(&ecdsaPublicKey)

	sig, err := ECDSASign(hash, ecdsaPrivateKey.D.Bytes())
	if err != nil {
		fmt.Printf("Error when signing: %v\n", err)
	}
	assert.Equal(t, nil, err)
	assert.Equal(t, 65, len(sig))

	isValid, err := ECDSAVerify(hash, sig, ecdsaPublicKeyBytes)
	assert.Equal(t, true, isValid)
	fmt.Printf("Valid: %v\n", isValid)
}
