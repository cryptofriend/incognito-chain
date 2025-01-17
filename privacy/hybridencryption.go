package privacy

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/incognitochain/incognito-chain/common"
	"github.com/incognitochain/incognito-chain/common/base58"
)

// hybridCipherText represents to hybridCipherText for Hybrid encryption
// Hybrid encryption uses AES scheme to encrypt message with arbitrary size
// and uses Elgamal encryption to encrypt AES key
type hybridCipherText struct {
	msgEncrypted    []byte
	symKeyEncrypted []byte
}

func (ciphertext hybridCipherText) GetMsgEncrypted() []byte {
	return ciphertext.msgEncrypted
}

func (ciphertext hybridCipherText) GetSymKeyEncrypted() []byte {
	return ciphertext.symKeyEncrypted
}

// isNil check whether ciphertext is nil or not
func (ciphertext hybridCipherText) isNil() bool {
	if len(ciphertext.msgEncrypted) == 0 {
		return true
	}

	return len(ciphertext.symKeyEncrypted) == 0
}

func (hybridCipherText hybridCipherText) MarshalJSON() ([]byte, error) {
	data := hybridCipherText.Bytes()
	temp := base58.Base58Check{}.Encode(data, common.ZeroByte)
	return json.Marshal(temp)
}

func (hybridCipherText *hybridCipherText) UnmarshalJSON(data []byte) error {
	dataStr := ""
	_ = json.Unmarshal(data, &dataStr)
	temp, _, err := base58.Base58Check{}.Decode(dataStr)
	if err != nil {
		return err
	}
	hybridCipherText.SetBytes(temp)
	return nil
}

// Bytes converts ciphertext to bytes array
// if ciphertext is nil, return empty byte array
func (ciphertext hybridCipherText) Bytes() []byte {
	if ciphertext.isNil() {
		return []byte{}
	}

	res := make([]byte, 0)
	res = append(res, ciphertext.symKeyEncrypted...)
	res = append(res, ciphertext.msgEncrypted...)

	return res
}

// SetBytes reverts bytes array to hybridCipherText
func (ciphertext *hybridCipherText) SetBytes(bytes []byte) error {
	if len(bytes) == 0 {
		return NewPrivacyErr(InvalidInputToSetBytesErr, nil)
	}

	ciphertext.symKeyEncrypted = bytes[0:elGamalCiphertextSize]
	ciphertext.msgEncrypted = bytes[elGamalCiphertextSize:]
	return nil
}

// hybridEncrypt encrypts message with any size, using Publickey to encrypt
// hybridEncrypt generates AES key by randomize an elliptic point aesKeyPoint and get X-coordinate
// using AES key to encrypt message
// After that, using ElGamal encryption encrypt aesKeyPoint using publicKey
func hybridEncrypt(msg []byte, publicKey *EllipticPoint) (ciphertext *hybridCipherText, err error) {
	ciphertext = new(hybridCipherText)
	// Generate a AES key as the abscissa of a random elliptic point
	aesKeyPoint := new(EllipticPoint)
	aesKeyPoint.randomize()
	aesKeyByte := common.AddPaddingBigInt(aesKeyPoint.x, common.BigIntSize)

	// Encrypt msg using aesKeyByte
	aesScheme := &common.AES{
		Key: aesKeyByte,
	}

	ciphertext.msgEncrypted, err = aesScheme.Encrypt(msg)
	if err != nil {
		return nil, err
	}

	// Using ElGamal cryptosystem for encrypting AES sym key
	pubKey := new(elGamalPublicKey)
	pubKey.h = new(EllipticPoint)
	pubKey.h.Set(publicKey.x, publicKey.y)

	ciphertext.symKeyEncrypted = pubKey.encrypt(aesKeyPoint).Bytes()

	return ciphertext, nil
}

// hybridDecrypt receives a ciphertext and privateKey
// it decrypts aesKeyPoint, using ElGamal encryption with privateKey
// Using X-coordinate of aesKeyPoint to decrypts message
func hybridDecrypt(ciphertext *hybridCipherText, privateKey *big.Int) (msg []byte, err error) {
	// Validate ciphertext
	if ciphertext.isNil() {
		return []byte{}, errors.New("ciphertext must not be nil")
	}

	// Get receiving key, which is a private key of ElGamal cryptosystem
	privKey := new(elGamalPrivateKey)
	privKey.set(privateKey)

	// Parse encrypted AES key encoded as an elliptic point from EncryptedSymKey
	encryptedAESKey := new(elGamalCipherText)
	err = encryptedAESKey.SetBytes(ciphertext.symKeyEncrypted)
	if err != nil {
		return []byte{}, err
	}

	// Decrypt encryptedAESKey using recipient's receiving key
	aesKeyPoint, err := privKey.decrypt(encryptedAESKey)
	if err != nil {
		return []byte{}, err
	}

	// Get AES key
	aesScheme := &common.AES{
		Key: common.AddPaddingBigInt(aesKeyPoint.x, common.BigIntSize),
	}

	// Decrypt encrypted coin randomness using AES keysatt
	msg, err = aesScheme.Decrypt(ciphertext.msgEncrypted)
	if err != nil {
		return []byte{}, err
	}
	return msg, nil
}
