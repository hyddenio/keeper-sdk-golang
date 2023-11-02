package auth

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"gotest.tools/assert"
)

func TestECDHAgreement(t *testing.T) {
	var privKey = "HIIeyuuRkVGvhtax8mlX7fangaC6DKa2R8VAg5AAtBY"
	var pubKey ="BBbdHwhMWW6gTtUU1Qy6ICgFOMOMTJK5agJhPSWcsXBzh3WNprrZMTDzDcLmj3yfmJFVVeEdiccdPdBe1C1r6Ng"
	var recordUid = "1xRhhNDGkK-Mj4NLh6LNZg"
	privateKey, err := LoadEcPrivateKey(Base64UrlDecode(privKey))
	assert.Assert(t, err == nil, err)
	publicKey, err := LoadEcPublicKey(Base64UrlDecode(pubKey))
	assert.Assert(t, err == nil, err)
	encryptionKey, err := EcSharedKeyWithNonce(publicKey, privateKey, Base64UrlDecode(recordUid))
	assert.Assert(t, err == nil, err)
	var expectedKey = Base64UrlDecode("TPKrsCKfsnmktwahlihr22EqRA1c_BcZn8FA3M_1HDc")
	assert.Assert(t, bytes.Equal(encryptionKey, expectedKey), "Incorrect RSA encryption")
}

func TestDecryptAesV1(t *testing.T) {
	data := Base64UrlDecode("KvsOJmE4JNK1HwKSpkBeR5R9YDms86uOb3wjNvc4LbUnZhKQtDxWifgA99tH2ZuP")
	key := Base64UrlDecode("pAZmcxEoV2chXsFQ6bzn7Lop8yO4F8ERIuS7XpFtr7Y")

	block, err := DecryptAesV1Full(data, key, true)
	assert.Assert(t, err == nil, err)

	decrypted := Base64UrlEncode(block)
	assert.Assert(t, decrypted == "6lf4FGVyhDRnRhJ91TrahjIW8lTqGA", "Incorrect decrypted text")
}

func TestEncryptAesV1(t *testing.T) {
	data := Base64UrlDecode("6lf4FGVyhDRnRhJ91TrahjIW8lTqGA")
	key := Base64UrlDecode("pAZmcxEoV2chXsFQ6bzn7Lop8yO4F8ERIuS7XpFtr7Y")
	iv := Base64UrlDecode("KvsOJmE4JNK1HwKSpkBeRw")
	block, err := EncryptAesV1Full(data, key, iv, true)
	assert.Assert(t, err == nil, err)

	encrypted := Base64UrlEncode(block)
	assert.Assert(t, encrypted == "KvsOJmE4JNK1HwKSpkBeR5R9YDms86uOb3wjNvc4LbUnZhKQtDxWifgA99tH2ZuP",
		"Incorrect decrypted text")
}

func TestEncryptAesV2(t *testing.T) {
	key := Base64UrlDecode("c-EeCGlAO7F9QoJThlFBrhSCLYMe1H6GtKP-rezDnik")
	nonce := Base64UrlDecode("Nt9_Y37C_43eRCRQ")
	data := Base64UrlDecode("nm-8mRG7xYwUG2duaOZzw-ttuqfetWjVIzoridJF0EJOGlDLs1ZWQ7F9mOJ0Hxuy" +
		"dFyojxdxVo1fGwbfwf0Jew07HhGGE5UZ_s57rQvhizDW3F3z9a7EqHRon0EilCbMhIzE")

	enc, err := EncryptAesV2Full(data, key, nonce)
	assert.Assert(t, err == nil, err)

	expectedData := "Nt9_Y37C_43eRCRQCptb64zFaJVLcXF1udabOr_fyGXkpjpYeCAI7zVQD4JjewB" +
		"CP1Xp7D6dx-pxdRWkhDEnVhJ3fzezi8atmmzvf2ICfkDK0IHHB8iNSx_R1Ru8To" +
		"zb-IdavT3wKi7nKSJLDdt-dk-Mw7bCewpZtg4wY-1UQw"
	realData := Base64UrlEncode(enc)
	assert.Assert(t, expectedData == realData, "Incorrect encrypted text")

	dec, err := DecryptAesV2(enc, key)
	assert.Assert(t, err == nil, err)

	assert.Assert(t, Base64UrlEncode(dec) == Base64UrlEncode(data) ,"Incorrect decrypted text")
}

func TestKeyDeriveV1Hash(t *testing.T) {
	password := "q2rXmNBFeLwAEX55hVVTfg"
	salt := Base64UrlDecode("Ozv5_XSBgw-XSrDosp8Y1A")
	var iterations uint32 = 1000
	expectedKey := "nu911pKhOIeX_lToXa4uIUuMPg1pj_3ZGpGmd7OjvRs"
	keyHash := DeriveKeyHashV1(password, salt, iterations)

	assert.Assert(t, Base64UrlEncode(keyHash) == expectedKey, "Incorrect derived V1 key hash")
}

func TestKeyDerivationV2(t *testing.T) {
	password := "q2rXmNBFeLwAEX55hVVTfg"
	domain := "1oZZl0fKjU4"
	salt := Base64UrlDecode("Ozv5_XSBgw-XSrDosp8Y1A")
	var iterations uint32 = 1000
	expectedKey := "rXE9OHv_gcvUHdWuBIkyLsRDXT1oddQCzf6PrIECl2g"

	keyHash := DeriveKeyHashV2(domain, password, salt, iterations)
	assert.Assert(t, Base64UrlEncode(keyHash) == expectedKey, "Incorrect derived V2 key hash")
}

func TestEncryptionParams(t *testing.T) {
	dataKey := GenerateAesKey()
	salt := GetRandomBytes(16)
	password := "123456"
	var iterations uint32 = 1000
	params, err := CreateEncryptionParams(password, salt, iterations, dataKey)
	assert.Assert(t, err == nil)
	dk, err := DecryptEncryptionParams(params, password)
	assert.Assert(t, err == nil)
	assert.Assert(t, bytes.Equal(dataKey, dk))
}

func TestLoadPrivateKey(t *testing.T) {
	pk, err := LoadRsaPrivateKey(Base64UrlDecode(testPrivateKey))
	rsaKey := pk.(*rsa.PrivateKey)
	rrr := rsaKey.Public()
	www := rrr.(*rsa.PublicKey)
	eee := x509.MarshalPKCS1PublicKey(www)
	ddd := Base64UrlEncode(eee)
	assert.Assert(t, ddd != "")

	assert.Assert(t, err == nil, err)
	assert.Assert(t, pk != nil, "Cannot load private key")
}

func TestLoadPublicKey(t *testing.T) {
	pk, err := LoadRsaPublicKey(Base64UrlDecode(testPublicKey))
	assert.Assert(t, err == nil, err)
	assert.Assert(t, pk != nil, "Cannot load private key")
}

func TestLocalRsa(t *testing.T) {
	privateKey, err := LoadRsaPrivateKey(Base64UrlDecode(testPrivateKey))
	assert.Assert(t, err == nil, err)

	publicKey, err := LoadRsaPublicKey(Base64UrlDecode(testPublicKey))
	assert.Assert(t, err == nil, err)

	data := GetRandomBytes(100)
	encData, err := EncryptRsa(data, publicKey)
	assert.Assert(t, err == nil, err)

	decData, err := DecryptRsa(encData, privateKey)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, bytes.Equal(decData, data), "Incorrect RSA encryption")
}


func TestStreamEncrypt(t *testing.T) {
	key := GenerateAesKey()

	data := GetRandomBytes(100)
	buf := bytes.NewBuffer(data)
	encryptor := NewAesStreamEncryptor(buf, key)
	buf1 := new(bytes.Buffer)
	var err error = nil
	var res int
	buf2 := make([]byte, 49)
	for err == nil {
		res, err = encryptor.Read(buf2)
		if res > 0 {
			_, _ = buf1.Write(buf2[0:res])
		} else {
			break
		}
	}
	decData, err := DecryptAesV1(buf1.Bytes(), key)
	assert.Assert(t, bytes.Equal(decData, data), "Incorrect stream encryption")
}

func TestStreamDecrypt(t *testing.T) {
	key := GenerateAesKey()

	data := GetRandomBytes(100)
	encData, err := EncryptAesV1(data, key)

	buf := bytes.NewBuffer(encData)
	decryptor := NewAesStreamDecryptor(buf, key)
	buf1 := new(bytes.Buffer)
	var res int
	buf2 := make([]byte, 49)
	for err == nil {
		res, err = decryptor.Read(buf2)
		if res > 0 {
			_, _ = buf1.Write(buf2[0:res])
		} else {
			break
		}
	}
	assert.Assert(t, bytes.Equal(buf1.Bytes(), data), "Incorrect stream encryption")
}

