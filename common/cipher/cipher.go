package cipher

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"strings"
)

var _chars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
var _key = []byte("SpUsXuZw4z6B9EbGdKgNjQnTqVsYv2x5")

// Generate key from string
func GenerateKey(key string) {
	sha := sha256.Sum256([]byte(key))
	encode := hex.EncodeToString(sha[:])
	_key = []byte(encode[0:32])
}

// XOR encrypt
func XOR(src []byte) []byte {
	_klen := len(_key)
	for i := 0; i < len(src); i++ {
		src[i] ^= _key[i%_klen]
	}
	return src
}

// Generate random string
func Random() string {
	max := len(_chars)
	length := 8 + rand.Intn(256)
	var b strings.Builder
	for i := 0; i < length; i++ {
		b.WriteByte(_chars[rand.Intn(max)])
	}
	return b.String()
}

// RandromData generate random data
func RandomData(size int) (int32, []byte) {
	max := len(_chars)
	if size <= 0 {
		return 0, nil
	}
	length := rand.Intn(size)
	var data []byte = make([]byte, length)
	for i := 0; i < length; i++ {
		data[i] = _chars[rand.Intn(max)]
	}
	return int32(length), data
}
