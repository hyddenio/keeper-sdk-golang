package sdk

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"golang.org/x/crypto/pbkdf2"
)

func GetRandomBytes(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

const DefaultBlockSize = 16

func pkcs7Pad(data []byte) []byte {
	n := DefaultBlockSize - (len(data) % DefaultBlockSize)
	pb := make([]byte, len(data)+n)
	copy(pb, data)
	copy(pb[len(data):], bytes.Repeat([]byte{byte(n)}, n))
	return pb
}

func pkcs7Unpad(data []byte) []byte {
	if len(data)%DefaultBlockSize == 0 {
		ch := data[len(data)-1]
		if ch <= DefaultBlockSize {
			return data[:len(data)-int(ch)]
		}
	}
	return data
}

func DecryptAesV1(data []byte, key []byte) ([]byte, error) {
	return DecryptAesV1Full(data, key, true)
}

func DecryptAesV1Full(data []byte, key []byte, usePadding bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(block, data[0:DefaultBlockSize])
	result := make([]byte, len(data) - DefaultBlockSize)
	decrypter.CryptBlocks(result, data[DefaultBlockSize:])

	if usePadding {
		return pkcs7Unpad(result), nil
	}
	return result, nil
}

func EncryptAesV1(data []byte, key []byte) ([]byte, error) {
	return EncryptAesV1Full(data, key, nil, true)
}

func EncryptAesV1Full(data []byte, key []byte, iv []byte, usePadding bool) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if iv == nil {
		iv = GetRandomBytes(DefaultBlockSize)
	}
	encrypter := cipher.NewCBCEncrypter(block, iv)
	if usePadding {
		data = pkcs7Pad(data)
	}
	result := make([]byte, len(data) + DefaultBlockSize)
	copy(result, iv)
	encrypter.CryptBlocks(result[DefaultBlockSize:], data)
	return result, nil
}

func EncryptAesV2(data []byte, key []byte) ([]byte, error) {
	return EncryptAesV2Full(data, key, nil)
}

func EncryptAesV2Full(data []byte, key []byte, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if nonce == nil {
		nonce = GetRandomBytes(12)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	result := gcm.Seal(nonce, nonce, data, nil)
	return result, nil
}

func DecryptAesV2(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, data[:12], data[12:], nil)
}


func DeriveKeyV1(password string, salt []byte, iterations uint32) []byte {
	return pbkdf2.Key([]byte(password), salt, int(iterations), 32, sha256.New)
}

func DeriveKeyHashV1(password string, salt []byte, iterations uint32) []byte {
	key := DeriveKeyV1(password, salt, iterations)
	hash := sha256.New()
	hash.Write(key)
	return hash.Sum(nil)
}

func DeriveKeyHashV2(domain string, password string, salt []byte, iterations uint32) []byte {
	key := pbkdf2.Key([]byte(domain+password), salt, int(iterations), 64, sha512.New)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	return mac.Sum(nil)
}

func LoadPrivateKey(privateKeyData []byte) (privateKey crypto.PrivateKey, err error) {
	var pk interface{}
	if pk, err = x509.ParsePKCS1PrivateKey(privateKeyData); err == nil {
		var ok bool
		if privateKey, ok = pk.(crypto.PrivateKey); ok {
			return
		} else {
			err = NewKeeperError("unexpected private key type")
		}
	}
	return
}

func LoadPublicKey(publicKey []byte) (crypto.PublicKey, error) {
	return x509.ParsePKCS1PublicKey(publicKey)
}

func EncryptRsa(data []byte, publicKey crypto.PublicKey) ([]byte, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptPKCS1v15(rand.Reader, key, data)
	default:
		return nil, NewKeeperError("unsupported public key type")
	}
}

func DecryptRsa(data []byte, privateKey crypto.PrivateKey) ([]byte, error) {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.DecryptPKCS1v15(rand.Reader, key, data)
	default:
		return nil, NewKeeperError("unsupported private key type")
	}
}