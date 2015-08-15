package cryptoutils

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHex(t *testing.T) {
	data := []byte("abcdefghijklmnopqrstvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789")
	expected := "6162636465666768696a6b6c6d6e6f7071727374767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a313233343536373839"
	assert.Equal(t, Hex(data), expected)
}

func TestB64(t *testing.T) {
	data := []byte("abcdefghijklmnopqrstvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789")
	expected := "YWJjZGVmZ2hpamtsbW5vcHFyc3R2d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5"
	assert.Equal(t, B64(data), expected)
}

func TestRandom(t *testing.T) {
	v0 := Random(10)
	v1 := Random(10)

	v2 := Random(32)
	v3 := Random(32)

	v4 := Random(128)
	v5 := Random(128)

	assert.NotEqual(t, v0, v1)
	assert.NotEqual(t, v2, v3)
	assert.NotEqual(t, v4, v5)

	assert.Len(t, v0, 10)
	assert.Len(t, v1, 10)
	assert.Len(t, v2, 32)
	assert.Len(t, v3, 32)
	assert.Len(t, v4, 128)
	assert.Len(t, v5, 128)
}

func TestRandomHEX(t *testing.T) {
	v0 := RandomHEX(10)
	v1 := RandomHEX(10)

	assert.NotEqual(t, v0, v1)
	assert.Len(t, v0, 20)
	assert.Len(t, v1, 20)

	for i := 0; i < 30; i++ {
		v := RandomHEX(64)
		_, err := hex.DecodeString(v)
		assert.NoError(t, err)
		assert.Len(t, v, 64*2)
	}
}

func TestRandomB64(t *testing.T) {
	v0 := RandomB64(10)
	v1 := RandomB64(10)

	assert.NotEqual(t, v0, v1)
	assert.Len(t, v0, 16)
	assert.Len(t, v1, 16)

	for i := 0; i < 30; i++ {
		v := RandomB64(64)
		_, err := base64.StdEncoding.DecodeString(v)
		assert.NoError(t, err)
		assert.Len(t, v, 88)
	}
}

func TestSHA1(t *testing.T) {
	digest := SHA1([]byte("this is a text to be hashed"))
	assert.Equal(t, digest, [20]uint8{
		0x7f, 0x55, 0x82, 0xe3, 0xfb, 0xd7, 0x7b, 0x81, 0x7c, 0xcc,
		0xb0, 0x98, 0x27, 0xba, 0x4d, 0x8a, 0x61, 0x4e, 0xa9, 0xc5})
}

func TestSHA1Hex(t *testing.T) {
	digest := SHA1Hex([]byte("The quick brown fox jumps over the lazy cog"))
	assert.Equal(t, digest, "de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3")

	digest = SHA1Hex([]byte("The quick brown fox jumps over the lazy dog"))
	assert.Equal(t, digest, "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")

	digest = SHA1Hex([]byte(""))
	assert.Equal(t, digest, "da39a3ee5e6b4b0d3255bfef95601890afd80709")
}

func TestSHA1B64(t *testing.T) {
	digest := SHA1B64([]byte("The quick brown fox jumps over the lazy cog"))
	assert.Equal(t, digest, "3p8sf9JeGzr60+haC9F9mxANtLM=")

	digest = SHA1B64([]byte("The quick brown fox jumps over the lazy dog"))
	assert.Equal(t, digest, "L9ThxnotKPzthJ7hu3bnORuT6xI=")

	digest = SHA1B64([]byte(""))
	assert.Equal(t, digest, "2jmj7l5rSw0yVb/vlWAYkK/YBwk=")
}

func TestSHA256(t *testing.T) {
}

func TestSHA256Hex(t *testing.T) {
	digest := SHA256Hex([]byte("The quick brown fox jumps over the lazy cog"))
	assert.Equal(t, digest, "e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be")

	digest = SHA256Hex([]byte("The quick brown fox jumps over the lazy dog"))
	assert.Equal(t, digest, "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")

	digest = SHA256Hex([]byte(""))
	assert.Equal(t, digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
}

func TestSHA256B64(t *testing.T) {
	digest := SHA256B64([]byte("The quick brown fox jumps over the lazy cog"))
	assert.Equal(t, digest, "5MTY8792tpLeeRoXPgUyEVD3o0W0ZIT+Qn9qzH7Mgb4=")

	digest = SHA256B64([]byte("The quick brown fox jumps over the lazy dog"))
	assert.Equal(t, digest, "16j7swfXgJRpypq8sAguT41WUeRtPNt2LQLQvzfJ5ZI=")

	digest = SHA256B64([]byte(""))
	assert.Equal(t, digest, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")
}

func TestHMAC_SHA1(t *testing.T) {
}

func TestHMAC_SHA1Hex(t *testing.T) {
}

func TestHMAC_SHA1B64(t *testing.T) {
}

func TestHMAC_SHA256(t *testing.T) {
}

func TestHMAC_SHA256Hex(t *testing.T) {
}

func TestHMAC_SHA256B64(t *testing.T) {
}

func TestCheckHMAC(t *testing.T) {
}

func TestCheckHMAC_SHA1(t *testing.T) {
}

func TestCheckHMAC_SHA256(t *testing.T) {
}
