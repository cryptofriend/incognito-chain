package ecdsa

import (
	"bytes"
	"github.com/ethereum/go-ethereum/crypto"
)

func ECDSASign(hash []byte, privateKey []byte) ([]byte, error){
	ECDSAPrivateKey, err := crypto.ToECDSA(privateKey)
	if err != nil {
		return []byte{}, err
	}
	return crypto.Sign(hash, ECDSAPrivateKey)
}

func ECDSAVerify(hash []byte, sig []byte, publicKey []byte) (bool, error) {
	ecdsaPublicKey, err := crypto.SigToPub(hash, sig)
	if err != nil {
		return false, err
	}

	publicKeyBytes := crypto.CompressPubkey(ecdsaPublicKey)

	valid := bytes.Equal(publicKey, publicKeyBytes)

	return valid, nil

}