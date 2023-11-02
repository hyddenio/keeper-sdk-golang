package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
)

func Base64UrlEncode(data []byte) string {
	if data == nil {
		return ""
	}
	outLen := base64.URLEncoding.EncodedLen(len(data))
	result := make([]byte, outLen)
	base64.URLEncoding.Encode(result, data)
	for ; outLen >= 0; outLen-- {
		if result[outLen-1] != '=' {
			break
		}
	}
	return string(result[:outLen])
}

func Base64UrlDecode(text string) []byte {
	if text == "" {
		return nil
	}
	switch len(text) % 4 {
	case 0:
		break
	case 1:
		return nil
	case 2:
		text += "=="
	case 3:
		text += "="
	}
	outLen := base64.URLEncoding.DecodedLen(len(text))
	result := make([]byte, outLen)
	outLen, err := base64.URLEncoding.Decode(result, []byte(text))
	if err != nil {
		return nil
	}
	return result[:outLen]
}

func GenerateUid() string {
	return Base64UrlEncode(GetRandomBytes(16))
}

func GenerateAesKey() []byte {
	return GetRandomBytes(32)
}

func DecryptEncryptionParams(decodedParams []byte, password string) (params []byte, err error) {
	if len(decodedParams) == 100 {
		it := make([]byte, 4)
		copy(it, decodedParams[:4])
		it[0] = 0
		iterations := binary.BigEndian.Uint32(it)
		salt := decodedParams[4:20]
		encDataKey := decodedParams[20:]
		key := DeriveKeyV1(password, salt, iterations)
		var decDataKey []byte
		if decDataKey, err = DecryptAesV1Full(encDataKey, key, false); err == nil {
			if len(decDataKey) == 64 {
				if bytes.Equal(decDataKey[:32], decDataKey[32:]) {
					params = decDataKey[:32]
				} else {
					err = NewKeeperError("Invalid data key: failed mirror verification")
				}
			}
		}
	} else {
		err = NewKeeperError("Invalid encryption params: bad params length")
	}
	return
}

func CreateEncryptionParams(password string, salt []byte, iterations uint32, dataKey []byte) (encryptionParams []byte, err error) {
	encryptionParams = make([]byte, 100)
	binary.BigEndian.PutUint32(encryptionParams[:4], iterations)
	encryptionParams[0] = 1
	copy(encryptionParams[4:20], salt)
	iv := GetRandomBytes(16)
	dk := make([]byte, 64)
	copy(dk[:32], dataKey)
	copy(dk[32:], dataKey)
	key := DeriveKeyV1(password, salt, iterations)
	if encDataKey, err := EncryptAesV1Full(dk, key, iv, false); err == nil {
		copy(encryptionParams[20:], encDataKey)
	}
	return
}

func CreateAuthVerifier(password string, salt []byte, iterations uint32) string {
	data := make([]byte, 1+3+16+32)
	binary.BigEndian.PutUint32(data[:4], uint32(iterations))
	data[0] = 1
	copy(data[4:20], salt)
	key := DeriveKeyV1(password, salt, iterations)
	copy(data[20:], key)
	return Base64UrlEncode(data)
}
