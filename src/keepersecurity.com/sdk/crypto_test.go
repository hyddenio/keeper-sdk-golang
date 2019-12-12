package sdk

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"gotest.tools/assert"
	"testing"
)

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

func TestAesGcmEncryption(t *testing.T) {
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

func TestKeyDeriveV2Hash(t *testing.T) {
	domain := "1oZZl0fKjU4"
	password := "q2rXmNBFeLwAEX55hVVTfg"
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
	pk, err := LoadPrivateKey(Base64UrlDecode(testPrivateKey))
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
	pk, err := LoadPublicKey(Base64UrlDecode(testPublicKey))
	assert.Assert(t, err == nil, err)
	assert.Assert(t, pk != nil, "Cannot load private key")
}

func TestLocalRsa(t *testing.T) {
	privateKey, err := LoadPrivateKey(Base64UrlDecode(testPrivateKey))
	assert.Assert(t, err == nil, err)

	publicKey, err := LoadPublicKey(Base64UrlDecode(testPublicKey))
	assert.Assert(t, err == nil, err)

	data := GetRandomBytes(100)
	encData, err := EncryptRsa(data, publicKey)
	assert.Assert(t, err == nil, err)

	decData, err := DecryptRsa(encData, privateKey)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, bytes.Equal(decData, data), "Incorrect RSA encryption")
}

const testPublicKey = "MIIBCgKCAQEAqR0AjmBXo371pYmvS1NM8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HD" +
	"Gl3-ylAbI02vIzKue-gDbjo1wUGp2qhANc1VxllLSWnkJmwbuGUTEWp4ANjusoMh" +
	"PvEwna1XPdlrSMdsKokjbP9xbguPdvXx5oBaqArrrGEg-36Vi7miA_g_UT4DKcry" +
	"glD4Xx0H9t5Hav-frz2qcEsyh9FC0fNyon_uveEdP2ac-kax8vO5EeVfBzOdw-WP" +
	"aBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm038JuMwHChTK29H9EOlqbOOuzYA1ENzL8" +
	"8hELpe-kl4RmpNS94BJDssikFFbjoiAVfwIDAQAB"

const testPrivateKey =
	"MIIEogIBAAKCAQEAqR0AjmBXo371pYmvS1NM8nXlbAv5qUbPYuV6KVwKjN3T8WX5" +
		"K6HDGl3-ylAbI02vIzKue-gDbjo1wUGp2qhANc1VxllLSWnkJmwbuGUTEWp4ANju" +
		"soMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx5oBaqArrrGEg-36Vi7miA_g_UT4D" +
		"KcryglD4Xx0H9t5Hav-frz2qcEsyh9FC0fNyon_uveEdP2ac-kax8vO5EeVfBzOd" +
		"w-WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm038JuMwHChTK29H9EOlqbOOuzYA1E" +
		"NzL88hELpe-kl4RmpNS94BJDssikFFbjoiAVfwIDAQABAoIBABB9KW64ahMg7-ai" +
		"FBtuFdSWNjZgvIkKxHHKGi0qMkUl4-JnpPHiJdnOTGeBhAPfMTJnYKfoKV14A4HC" +
		"W0NcoFYenTxnvHV-A6bTZ6iFAmTyUp0SicOSEY3Hiov1OMppBpLkDuHe2TtpdK_c" +
		"JLLerCVjYnN8DRqTpdmfsAkdonRseXyhRhwO6yFwVy9TEc9_OFuqGMOsy5_VIts6" +
		"pG0saJJUQlOuLTxHwtPdloqjI8l3yMiDfXvJF2_epb_PYpKkAQZy_UWM5u4P_pnb" +
		"UdImyYo6HBmnq-qO07J7b3yOSAzWhklBD7cMh1ucSOyF9-u03mLOfx2-SXq4tIuU" +
		"Lz3RHZECgYEA0Rj-ipCKEPwQORViDFYYk1txzFSVKVX9Q-ozl6i93kTXx8GF7vkX" +
		"L6SaEbKDA2EARuczr1gjymlvgRAwbsX7bDylSF6EsmPZ-EccNe4GoXmfbgMFDqGr" +
		"3jVUmwEYwkte6EvP2Ha2GDwIuXFhcXWxgbbQxGGEcS5niei1mV0jv-sCgYEAzwv9" +
		"BIYkeBC6_kejD2VwNzC1Jl97vg2It2URTZUGPFvcXh1Ed_i1itXwJ7wBjyBdwLJM" +
		"IWjZcAYKET9NdBps2loATbOHrw4zFEqjKr_X-xSVU4bunipoY40fhl6a15ngUZ49" +
		"3OJe_YtXEBHTVHorltIYuugu0zKk6uKbU_bt770CgYAR8_5u8UgZezr9W7umaYIE" +
		"rPZRX_XKrcpoGWTCocdjnS-VxCT2xsZZ3d0opdYf5SU78T_7zyqLh4_-WeB-slsL" +
		"CQ3777mfA3nEmn5ulvhUxveMX5AAmJsEIjoYcPiqPgRxF4lKAa9S11y8Z2LBdiR-" +
		"ia7VHbZcbWqQab2l5FxcbwKBgCz_Ov7XtGdPo4QNx5daAVhNQqFTUQ5N3K-WzHri" +
		"71cA09S0YaP9Ll88_ZN1HZWggB-X4EnGgrMA7QEwk8Gu2Idf1f8NDGj0Gg_H5Mwu" +
		"o17S610azxMavlMcYYSPXPGMZJ74WBOAMwrBVKuOZDJQ1tZRVMSSH1MRB5xwoTdP" +
		"TAi1AoGAXqJUfDAjtLR0wFoLlV0GWGOObKkPZFCbFdv0_CY2dk0nKnSsYRCogiFP" +
		"t9XhZG5kawEtdfqiNBDyeNVLu6FaZnRkid_tUqMKfCYLjNDq31OD1Pwvyuh6Hs1P" +
		"hL2-nt6t9b7JMyzKjWq_OPuTPH0QErL3oiFbTaZ4fDXplH_6Snw"

/*
func TestOtherRsa(t *testing.T) {
	privateKey, _, err := loadRsaKeys()
	assert.Assert(t, err == nil, err)

	data := Base64UrlDecode("fDxt4nJLZPrRSMozaD1Vkt1QNS5bdAoEGmXv1mbE3DWo5HWJ13RBPuRQr7gqiZ542BLN_R8n8lmJrZ5RIVnvgB93y7SSuD9BxpP55RZ6twAl0vXBeVpPn9CTAgTHy8kM_U4h_g")
	dotnetEncrypted := "XUcJfak5bGW9UyqjkF8CAfT196VYMEFTu-HsZdWgkgDy9faufL3TLiX5B9pAAl8" +
		"Ms3W4ZHGhVx7pdU_7lFTP7VYCr-ODwhbh4Qjp7tAxdlhh5GbXM-IuvcG1Fx1ZEx" +
		"UPp9VdB7jlKF7--gdxXuezqktQxs8X2JRFVUBsJho8zBXLfdzILPjdoSiq_3R9S" +
		"Jp_KhVOJfT1CB6iUap2BOqUfXkISbO57RUJ7-0IthcrNVSx2nqlNSGFSfAMzTYK" +
		"_kAEmAf7HJ_Zl0ff3e_9qSEu_l1iNpnySPAersLd6_jjnqJWcI5I6oO9MmEGsoa" +
		"NCr6rWBxMmpjLcB3siaDCNT9laQ"
	encData := Base64UrlDecode(dotnetEncrypted)
	decData, err := DecryptRsa(encData, privateKey)

	assert.Assert(t, err == nil, err)
	assert.Assert(t, bytes.Equal(decData, data), "Incorrect RSA encryption")
}


const privateKey = `
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,7359ABCB9854B5CB781E4910662C5EF1

u1i/Mj22bT6AegV38qTsz0mK/QFbGpveS9dq4GXkYVA5JjqowcVsl1HUq2mIhDmW
wYRhkqGWD6IJkt++mDIpv74VKYYuzxTVvt4V46LS/mXn9xqO8g8Cy1qxWznRBPZe
a6/qziQpSI1R4PltIcD1gQHPIJiHINOi4Zi1GT6FTRzZwQ+08rOFfRchvP/rG8hX
KgLywsk9p44exMNJBJhOVTs6UeC4zGdMxNN++Qa+3o+6G8FVgyR4KNGqcFVoYGe6
L5K5KoJz4LwhUy3NDL9TSftxqvXsbiFtUw4BSEYjdyDYQz/ytpFkyGJIzn7vutx+
XbEIMRi6RR2qObI9TdiA5w7sOthvCiGbpzqlH6b++pIRNYiUPe+Ec8SeEbkM8wZB
IFx6xCpDKZQPyCnHngwYIw/iCXqO5UyJjDCnDHOVpMi/BbMJsKp7U+qcrUmN9gUr
VMFRlUZpps5Im3wu3gebZ6Fu41JYK2LqcgEOnh0EbeeZIvH3+uv/QIHdJPYSbsMU
Ns2KJQc+n4PsZa7kZf/CGAq926Y302o9SV2pX1GAcwoHJWkfukZhpt3ikJSrnHVD
FAIZbA0xt4XdbDMVg5T6Er+q1IO1zrZeQ/NLsRR+/JLz3+DvtIKrVMTLtGbl/VV4
rROt9l6YnF2F8CMaMz68v+19vzo1zEob/WD/8Ye3YQq66meJ/+NjwyTmMrZxsO/l
FHeDgDs1r2Nc1uC2/n1UiiZyFTaBzkj/5QUnpBm33V/P63+pN6cw0qEvjNEwdIOC
d5Ohky1d1ayhSeVHkx1ZYcSTriicgWcWTOV+zckJ+VAqvSCZV4A+NMqZGVzPhMgC
h9GWvIXfMDhXIDzBsQz2W3zseJFSzL4av8b/AxTDapOeS9M8FzsbEDJC7YfiLVWK
6bFOLr2dg5Lm41iyWmp7NK2+IUFN15DgMIbHcpfD24F+cs73hjE3E56rsb8dBifG
Q1izqwFiopK+1z9C/EWBmmY3AcyqjXEQl3DWnL2IbYnhmm/SN040BGVZKJcUBUlk
b7RPQF+uZWlM8EWLTqCZQUfl3bogxOcFryyElBPDVRq4Z/x4di2FuUbmI/Mbs1g7
PiBWKIC8CHk3sLezXgMn1thkKsRI3xN+jZcGTZ6lhTVKUAbbW8mqRzBtyjPHbjUC
9PRSeJRDc10ZYnyWhLXa2lSgY12obXNuxLi8eKg6VuBnVzh4CvjOmJY3NlA5xsUi
YLl49YLLQqBU2IwrgqYm+7n2D8PmnhwPUPj2shNoIi9gtAhx8n0pyypgzd8iTtQZ
3IxO1zaNjJOal4er299DcoBsZ5cZ7EU6ltwtUCNqGyaVWwSqjAKtiPGpjT/eEAeL
KLzX+F5r+dUUsy5m8ds+6TUWDxLaqT8PcugnUxT8f3JokODv7JHSiogB1ETeczKS
RJfJH63edAQLxl+rayIqsTuUntmMNgE3olQWexCChX9b8xW6OzVgw8jU6WX0OGOB
5qkDxT9de8CpseIymuDX8AYIpPxIHJdigTBBfYp34hPAKuBpAwDPNS1FiOZYYZSB
84VHEOeXkUpBgAGQwphDZITltMDnssSGPbCX9EHM5+mNVkmQw+SDJbcgXm0jNVtC
-----END RSA PRIVATE KEY-----`

const privateKeyPassword = "E,{-qhsm;<cq]3D(3H5K/"
const publicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR0AjmBXo371pYmvS1NM
8nXlbAv5qUbPYuV6KVwKjN3T8WX5K6HDGl3+ylAbI02vIzKue+gDbjo1wUGp2qhA
Nc1VxllLSWnkJmwbuGUTEWp4ANjusoMhPvEwna1XPdlrSMdsKokjbP9xbguPdvXx
5oBaqArrrGEg+36Vi7miA/g/UT4DKcryglD4Xx0H9t5Hav+frz2qcEsyh9FC0fNy
on/uveEdP2ac+kax8vO5EeVfBzOdw+WPaBtUO1h7rSZ6xKOm6x1OahNTUFy7Cgm0
38JuMwHChTK29H9EOlqbOOuzYA1ENzL88hELpe+kl4RmpNS94BJDssikFFbjoiAV
fwIDAQAB
-----END PUBLIC KEY-----`

func loadRsaKeys() (private crypto.PrivateKey, public crypto.PublicKey, err error) {
	if block, _ := pem.Decode([]byte(privateKey)); block != nil {
		var der []byte
		if der, err = x509.DecryptPEMBlock(block, []byte(privateKeyPassword)); err == nil {
			if private, err = x509.ParsePKCS1PrivateKey(der); err == nil {
				if block, _ = pem.Decode([]byte(publicKey)); block != nil {
					public, err = x509.ParsePKIXPublicKey(block.Bytes)
					return
				}
			}
		}
	}
	err = errors.New("Cannot decode private keys")
	return
}
*/
