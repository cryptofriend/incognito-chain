package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type AES struct {
}

func (self AES) DeriveKey(passPhrase string, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, 8)
		// http://www.ietf.org/rfc/rfc2898.txt
		// Salt.
		rand.Read(salt)
	}
	return pbkdf2.Key([]byte(passPhrase), salt, 1000, 32, sha256.New), salt
}

func (self AES) Encrypt(passphrase string, plaintext []byte) (string, error) {
	key, salt := self.DeriveKey(passphrase, nil)
	iv := make([]byte, 12)
	// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// Section 8.2
	rand.Read(iv)
	b, err := aes.NewCipher(key)
	aesgcm, err := cipher.NewGCM(b)
	data := aesgcm.Seal(nil, iv, plaintext, nil)
	return hex.EncodeToString(salt) + "-" + hex.EncodeToString(iv) + "-" + hex.EncodeToString(data), err
}

func (self AES) Decrypt(passphrase, ciphertext string) ([]byte, error) {
	arr := strings.Split(ciphertext, "-")
	salt, err := hex.DecodeString(arr[0])
	iv, err := hex.DecodeString(arr[1])
	data, err := hex.DecodeString(arr[2])
	key, _ := self.DeriveKey(passphrase, salt)
	b, err := aes.NewCipher(key)
	aesgcm, err := cipher.NewGCM(b)
	data, err = aesgcm.Open(nil, iv, data, nil)
	return data, err
}