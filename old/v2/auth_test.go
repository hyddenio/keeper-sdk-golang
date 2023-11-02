package v2

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"gotest.tools/assert"
	auth2 "keepersecurity.com/sdk/auth"
	"keepersecurity.com/sdk/protobuf"
	"keepersecurity.com/sdk/utils"
)

func TestAuth_LoginSuccess(t *testing.T) {
	a, mock := newTestAuth()
	err := a.Login(mock.context.username, mock.context.password)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, a.AuthContext().SessionToken == mock.context.sessionToken)
	assert.Assert(t, bytes.Equal(a.AuthContext().DataKey, mock.context.dataKey))
	assert.Assert(t, bytes.Equal(a.AuthContext().ClientKey, mock.context.clientKey))
	assert.Assert(t, a.AuthContext().PrivateKey != nil)
	settings := a.SettingsStorage().GetSettings()
	assert.Assert(t, settings.LastUsername() == mock.context.username)
	userSettings := auth2.GetUserSettings(settings, mock.context.username)
	assert.Assert(t, userSettings != nil)
	assert.Assert(t, userSettings.Username() == mock.context.username)
}

func TestAuth_RefreshSessionToken(t *testing.T) {
	a, mock := newTestAuth()
	err := a.Login(mock.context.username, mock.context.password)
	assert.Assert(t, err == nil, err)

	a.AuthContext().SessionToken = "BadSessionToken"
	err = a.Login(mock.context.username, mock.context.password)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, a.AuthContext().SessionToken == mock.context.sessionToken)
}

func TestAuth_LoginSuccessEncryptedDataKey(t *testing.T) {
	a, mock := newTestAuth()
	mock.asEncryptedDataKey = true
	err := a.Login(mock.context.username, mock.context.password)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, a.IsAuthenticated())
}

func TestAuth_LoginSuccess2faDeviceToken(t *testing.T) {
	a, mock := newTestAuth()
	mock.has2fa = true
	settings := auth2.NewSettings(nil)
	settings.lastUsername = mock.context.username
	settings.MergeUserSettings(&auth2.UserSettings{
		username:       mock.context.username,
		twoFactorToken: mock.context.twoFactorToken,
	})
	a.SettingsStorage().PutSettings(settings)
	err := a.Login(mock.context.username, mock.context.password)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, a.IsAuthenticated())
}

func TestAuth_LoginSuccess2faOneTime(t *testing.T) {
	a, mock := newTestAuth()
	mock.has2fa = true
	mock.resetMethodCalled()
	err := a.Login(mock.context.username, mock.context.password)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, a.IsAuthenticated())
	assert.Assert(t, mock.getMethodCalled("GetTwoFactorCode") == 1)

	settings := a.SettingsStorage().GetSettings()
	user := auth2.GetUserSettings(settings, mock.context.username)
	assert.Assert(t, user != nil)
	assert.Assert(t, user.Username() == mock.context.username)
	assert.Assert(t, user.TwoFactorToken() == mock.context.twoFactorToken)
}

func TestAuth_LoginSuccess2faCancel(t *testing.T) {
	a, mock := newTestAuth()
	mock.has2fa = true
	mock.cancel2fa = true
	err := a.Login(mock.context.username, mock.context.password)
	assert.Assert(t, err != nil)
	assert.Assert(t, !a.IsAuthenticated())
	apiError, _ := err.(*auth2.KeeperApiError)
	assert.Assert(t, apiError != nil)
	assert.Assert(t, apiError.resultCode == "need_totp")
}

func TestAuth_LoginFailedInvalidPassword(t *testing.T) {
	a, mock := newTestAuth()
	err := a.Login(mock.context.username, "123456")
	assert.Assert(t, err != nil)
	assert.Assert(t, !a.IsAuthenticated())
	apiError, _ := err.(*auth2.KeeperApiError)
	assert.Assert(t, apiError != nil)
	assert.Assert(t, apiError.resultCode == "auth_failed")
}

func TestAuth_LoginFailedInvalidUser(t *testing.T) {
	a, mock := newTestAuth()
	err := a.Login("wrong.user@keepersecurity.com", mock.context.username)
	assert.Assert(t, err != nil)
	assert.Assert(t, !a.IsAuthenticated())
	apiError, _ := err.(*auth2.KeeperApiError)
	assert.Assert(t, apiError != nil)
	assert.Assert(t, apiError.resultCode == "Failed_to_find_user")
}

func TestAuth_LoginAuthExpired(t *testing.T) {
	a, mock := newTestAuth()
	mock.authExpired = true
	err := a.Login(mock.context.username, mock.context.password)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, !mock.authExpired)
	assert.Assert(t, mock.getMethodCalled("GetNewPassword") == 1)
	assert.Assert(t, mock.getMethodCalled("change_master_password") == 1)
}

func TestAuth_LoginAccountTransferExpired(t *testing.T) {
	a, mock := newTestAuth()
	mock.accountTransferExpired = true
	err := a.Login(mock.context.username, mock.context.password)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, !mock.accountTransferExpired)
	assert.Assert(t, mock.getMethodCalled("share_account") == 1)
}

///////////////////////////////////////////////
func newTestAuth() (a Auth, m *endpointMock) {
	m = newEndpointMock()
	a = &auth{
		ui:              m,
		settingsStorage: auth2.NewSettingsStorage(nil),
		endpoint:        m,
		context:         new(AuthContext),
	}
	return
}

type mockMethodCalled struct {
	methodCalled map[string]int
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

type endpointMock struct {
	server                 string
	deviceToken            []byte
	keyId                  int32
	context                *vaultTestContext
	asEncryptedDataKey     bool
	has2fa                 bool
	cancel2fa              bool
	authExpired            bool
	accountTransferExpired bool
	mockMethodCalled
}

func newEndpointMock() *endpointMock {
	return &endpointMock{
		server:      "mock.keepersecurity.com",
		deviceToken: nil,
		keyId:       1,
		context:     defaultVaultContext,
	}
}

func (am *endpointMock) Confirmation(information string) bool {
	am.incMethodCalled("Confirmation")
	return true
}
func (am *endpointMock) GetNewPassword(matcher PasswordRuleMatcher) string {
	am.incMethodCalled("GetNewPassword")
	am.context.password = auth2.GenerateUid()
	return am.context.password
}
func (am *endpointMock) GetTwoFactorCode(channel TwoFactorChannel) (string, TwoFactorCodeDuration) {
	am.incMethodCalled("GetTwoFactorCode")
	if am.cancel2fa {
		am.cancel2fa = false
		return "", EveryLogin
	}
	return am.context.twoFactorCode, EveryLogin
}

func (am *endpointMock) ClientVersion() string {
	return "mock1.0.0"
}
func (am *endpointMock) Server() string {
	return am.server
}
func (am *endpointMock) DeviceToken() []byte {
	return am.deviceToken
}
func (am *endpointMock) ServerKeyId() int32 {
	return am.keyId
}
func (am *endpointMock) SetServerParams(server string, deviceId []byte, keyId int32) {
	am.server = server
	am.deviceToken = deviceId
	am.keyId = keyId
}
func (am *endpointMock) GetDeviceToken() ([]byte, error) {
	if am.deviceToken == nil {
		am.deviceToken = auth2.GenerateAesKey()
	}
	return am.deviceToken, nil
}
func (am *endpointMock) InvalidateDeviceToken() {
	am.deviceToken = nil
}
func (am *endpointMock) ExecuteRest(endpoint string, _ *protobuf.ApiRequestPayload) ([]byte, error) {
	switch endpoint {
	case "authentication/pre_login":
		rs := &protobuf.PreLoginResponse{
			Status: 0,
			Salt: []*protobuf.Salt{{
				Iterations: int32(am.context.authIterations),
				Salt:       am.context.authSalt,
				Algorithm:  1,
				Uid:        []byte("uid"),
				Name:       "name",
			}},
			TwoFactorChannel: nil,
		}
		return proto.Marshal(rs)
	}
	return nil, errors.New(fmt.Sprint("EndpointMock.ExecuteRest not implemented: ", endpoint))
}
func (am *endpointMock) GetNewUserParams(string) (*protobuf.NewUserMinimumParams, error) {
	return &protobuf.NewUserMinimumParams{
		MinimumIterations:        1000,
		PasswordMatchRegex:       []string{".{6,}"},
		PasswordMatchDescription: []string{"default"},
	}, nil
}

func (am *endpointMock) ExecuteV2Command(rq interface{}, rs interface{}) (err error) {
	if toCmd, ok := rq.(auth2.ToKeeperApiCommand); ok {
		apiRq := toCmd.GetKeeperApiCommand()
		if apiRq.Command == "" {
			if cmdName, ok := rq.(auth2.ICommand); ok {
				apiRq.Command = cmdName.Command()
			}
		}

		am.incMethodCalled(toCmd.GetKeeperApiCommand().Command)
	}

	switch command := rq.(type) {
	case *auth2.LoginCommand:
		if response, ok := rs.(*auth2.LoginResponse); ok {
			response.Result = "fail"
			if command.Username == am.context.username {
				if command.AuthResponse == am.context.authHash {
					response.Result = "success"
					if am.has2fa {
						switch command.TwoFactorType {
						case "device_token":
							if command.TwoFactorToken != am.context.twoFactorToken {
								response.Result = "fail"
								response.ResultCode = "invalid_device_token"
							}
						case "one_time":
							if command.TwoFactorToken != am.context.twoFactorCode {
								response.Result = "fail"
								response.ResultCode = "invalid_totp"
							} else {
								response.DeviceToken = am.context.twoFactorToken
								if command.DeviceTokenExpiresInDays != nil && *command.DeviceTokenExpiresInDays > 0 {
									response.DtScope = "expiration"
								} else {
									response.DtScope = "session"
								}
							}
						default:
							response.Result = "fail"
							response.ResultCode = "need_totp"
						}
					}
				} else {
					response.ResultCode = "auth_failed"
				}
			} else {
				response.ResultCode = "Failed_to_find_user"
			}

			if response.Result == "success" {
				am.has2fa = false
				response.ResultCode = "auth_success"
				response.SessionToken = am.context.sessionToken
				for _, inc := range command.Include {
					switch inc {
					case "keys":
						response.Keys = new(auth2.AccountKeys)
						if am.asEncryptedDataKey {
							am.asEncryptedDataKey = false
							key := auth2.DeriveKeyHashV2("data_key", am.context.password, am.context.authSalt, am.context.authIterations)
							encDataKey, _ := auth2.EncryptAesV2(am.context.dataKey, key)
							response.Keys.EncryptedDataKey = auth2.Base64UrlEncode(encDataKey)
						} else {
							response.Keys.EncryptionParams = am.context.encryptionParams
						}
						response.Keys.EncryptedPrivateKey = auth2.Base64UrlEncode(am.context.encryptedPrivateKey)
					case "client_key":
						ck, _ := auth2.EncryptAesV1(am.context.clientKey, am.context.dataKey)
						response.ClientKey = auth2.Base64UrlEncode(ck)
					case "is_enterprise_admin":
						response.IsEnterpriseAdmin = &am.context.isEnterpriseAdmin
					case "settings":
						response.Settings = &auth2.AccountSettings{
							PasswordRulesIntro: "fake",
							PasswordRules: []*auth2.PasswordRules{&auth2.PasswordRules{
								Match:       true,
								Pattern:     ".{6,}",
								Description: "default",
							}},
							Channel: "two_factor_disabled",
						}
					}
				}
				if am.authExpired {
					response.ResultCode = "auth_expired"
					response.Result = "fail"
					response.SessionToken = am.context.limitedSessionToken
				} else if am.accountTransferExpired {
					response.ResultCode = "auth_expired_transfer"
					response.Result = "fail"
					response.SessionToken = am.context.limitedSessionToken
					if pk, ok := am.context.publicKey.(*rsa.PublicKey); ok {
						response.Settings.ShareAccountTo = []*auth2.AccountShareTo{
							{
								RoleId:    123456789,
								PublicKey: auth2.Base64UrlEncode(x509.MarshalPKCS1PublicKey(pk)),
							},
						}
					}
				}
			} else {
				switch response.ResultCode {
				case "auth_failed":
					response.Message = "Invalid username and/or password"
					response.Salt = auth2.Base64UrlEncode(am.context.authSalt)
					response.Iterations = int32(am.context.authIterations)
				case "need_totp", "invalid_device_token", "invalid_totp":
					response.Channel = "two_factor_channel_google"
				}
			}
		}
	case *auth2.ChangeMasterPasswordCommand:
		if response, ok := rs.(*auth2.KeeperApiResponse); ok {
			if command.SessionToken == am.context.limitedSessionToken {
				data := auth2.Base64UrlDecode(command.AuthVerifier)
				am.context.authSalt = data[4:20]
				var authVerifier = data[20:]
				hash := sha256.New()
				hash.Write(authVerifier)
				authVerifier = hash.Sum(nil)
				am.context.authHash = auth2.Base64UrlEncode(authVerifier)
				am.context.encryptionParams = command.EncryptionParams
				am.authExpired = false
				response.Result = "success"
			} else {
				response.ResultCode = "auth_expired"
				response.Result = "fail"
			}
		}
	case *auth2.ShareAccountCommand:
		if toApiRs, ok := rs.(auth2.ToKeeperApiResponse); ok {
			apiRs := toApiRs.GetKeeperApiResponse()
			apiRs.Result = "success"
			am.accountTransferExpired = false
		}
	default:
		err = errors.New("not implemented")
	}
	return
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
		username:            "unit.test@keepersecurity.com",
		authIterations:      1000,
		authSalt:            auth2.GetRandomBytes(16),
		dataKey:             auth2.GenerateAesKey(),
		clientKey:           auth2.GenerateAesKey(),
		sessionToken:        auth2.Base64UrlEncode(auth2.GetRandomBytes(64)),
		limitedSessionToken: auth2.Base64UrlEncode(auth2.GetRandomBytes(32)),
		twoFactorToken:      auth2.Base64UrlEncode(auth2.GetRandomBytes(64)),
		twoFactorCode:       "123456",
		password:            auth2.GenerateUid(),
	}
	pk := auth2.Base64UrlDecode(utils.testPrivateKey)
	vc.privateKey, _ = auth2.LoadPrivateKey(pk)
	vc.encryptedPrivateKey, _ = auth2.EncryptAesV1(pk, vc.dataKey)
	vc.publicKeyData = auth2.Base64UrlDecode(utils.testPublicKey)
	vc.publicKey, _ = auth2.LoadPublicKey(vc.publicKeyData)
	vc.authHash = auth2.Base64UrlEncode(auth2.DeriveKeyHashV1(vc.password, vc.authSalt, vc.authIterations))
	vc.encryptionParams, _ = auth2.CreateEncryptionParams(vc.password, auth2.GetRandomBytes(16), vc.authIterations, vc.dataKey)
	return vc
}

var defaultVaultContext = NewVaultTestContext()
