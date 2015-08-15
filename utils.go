package cryptoutils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
)

func Hex(data []byte) string {
	return hex.EncodeToString(data)
}

func B64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Random(entropyBytes int) []byte {
	b := make([]byte, entropyBytes)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func RandomHEX(entropyBytes int) string {
	return Hex(Random(entropyBytes))
}

func RandomB64(entropyBytes int) string {
	return B64(Random(entropyBytes))
}

func SHA1(data []byte) [20]byte {
	return sha1.Sum(data)
}

func SHA1Hex(data []byte) string {
	bytes := SHA1(data)
	return Hex(bytes[:])
}

func SHA1B64(data []byte) string {
	bytes := SHA1(data)
	return B64(bytes[:])
}

func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

func SHA256Hex(data []byte) string {
	bytes := SHA256(data)
	return Hex(bytes[:])
}

func SHA256B64(data []byte) string {
	bytes := SHA256(data)
	return B64(bytes[:])
}

func HMAC(h func() hash.Hash, data, key []byte) []byte {
	mac := hmac.New(h, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func HMAC_SHA1(data, key []byte) []byte {
	return HMAC(sha1.New, data, key)
}

func HMAC_SHA1Hex(data, key []byte) string {
	return Hex(HMAC_SHA1(data, key))
}

func HMAC_SHA1B64(data, key []byte) string {
	return B64(HMAC_SHA1(data, key))
}

func HMAC_SHA256(data, key []byte) []byte {
	return HMAC(sha256.New, data, key)
}

func HMAC_SHA256Hex(data, key []byte) string {
	return Hex(HMAC_SHA256(data, key))
}

func HMAC_SHA256B64(data, key []byte) string {
	return B64(HMAC_SHA256(data, key))
}

func CheckHMAC(h func() hash.Hash, message, messageMAC, key []byte) bool {
	expectedMAC := HMAC(h, message, key)
	return hmac.Equal(messageMAC, expectedMAC)
}

func CheckHMAC_SHA1(message, messageMAC, key []byte) bool {
	return CheckHMAC(sha1.New, message, messageMAC, key)
}

func CheckHMAC_SHA256(message, messageMAC, key []byte) bool {
	return CheckHMAC(sha256.New, message, messageMAC, key)
}

func CheckHMAC_SHA256B64(message, messageMAC string, key []byte) bool {
	// TODO
	return true
}
