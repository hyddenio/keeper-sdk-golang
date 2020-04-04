package mock

import (
	"crypto"
	"keepersecurity.com/sdk"
	"strings"
)

type mockMethodCalled struct {
	methodCalled           map[string]int
}
func (mc *mockMethodCalled) resetMethodCalled() {
	mc.methodCalled = nil
}
func (mc *mockMethodCalled) getMethodCalled(request string) int {
	if mc.methodCalled != nil {
		key := strings.ToLower(request)
		return mc.methodCalled[key]
	}
	return 0
}
func (mc *mockMethodCalled) incMethodCalled(request string) {
	if mc.methodCalled == nil {
		mc.methodCalled = make(map[string]int)

	}
	key := strings.ToLower(request)
	cnt := mc.methodCalled[key]
	mc.methodCalled[key] = cnt + 1
}

type vaultTestContext struct {
	username            string
	dataKey             []byte
	clientKey           []byte
	sessionToken        string
	limitedSessionToken string
	isEnterpriseAdmin   bool
	privateKey          crypto.PrivateKey
	publicKey           crypto.PublicKey
	publicKeyData       []byte
	encryptedPrivateKey []byte
	twoFactorToken      string
	twoFactorCode       string
	password            string
	authSalt            []byte
	authIterations      uint32
	authHash            string
	encryptionParams    string
}

func NewVaultTestContext() *vaultTestContext {
	vc := &vaultTestContext{
		username:             "unit.test@keepersecurity.com",
		authIterations:      1000,
		authSalt:            sdk.GetRandomBytes(16),
		dataKey:             sdk.GenerateAesKey(),
		clientKey:           sdk.GenerateAesKey(),
		sessionToken:        sdk.Base64UrlEncode(sdk.GetRandomBytes(64)),
		limitedSessionToken: sdk.Base64UrlEncode(sdk.GetRandomBytes(32)),
		twoFactorToken:      sdk.Base64UrlEncode(sdk.GetRandomBytes(64)),
		twoFactorCode:       "123456",
		password:            sdk.GenerateUid(),
	}
	pk := sdk.Base64UrlDecode(testPrivateKey)
	vc.privateKey, _ = sdk.LoadPrivateKey(pk)
	vc.encryptedPrivateKey, _ = sdk.EncryptAesV1(pk, vc.dataKey)
	vc.publicKeyData = sdk.Base64UrlDecode(testPublicKey)
	vc.publicKey, _ = sdk.LoadPublicKey(vc.publicKeyData)
	vc.authHash = sdk.Base64UrlEncode(sdk.DeriveKeyHashV1(vc.password, vc.authSalt, vc.authIterations))
	vc.encryptionParams, _ = sdk.CreateEncryptionParams(vc.password, sdk.GetRandomBytes(16), vc.authIterations, vc.dataKey)
	return vc
}

var defaultVaultContext = NewVaultTestContext()

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
