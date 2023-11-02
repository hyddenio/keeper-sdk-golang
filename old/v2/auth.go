package v2

import (
	"bytes"
	"crypto"
	"regexp"
	"strings"

	"google.golang.org/protobuf/proto"
	"keepersecurity.com/sdk"
	auth2 "keepersecurity.com/sdk/auth"
	protobuf "keepersecurity.com/sdk/protobuf/authentication"
)

type Auth interface {
	Ui() AuthUI
	SettingsStorage() auth2.ISettingsStorage
	Endpoint() auth2.KeeperEndpoint
	AuthContext() *AuthContext
	IsAuthenticated() bool
	Login(string, string) error
	Logout()
	ExecuteAuthCommand(interface{}, interface{}, bool) error
}

type AuthContext struct {
	Username              string
	DataKey               []byte
	ClientKey             []byte
	PrivateKey            crypto.PrivateKey
	IsEnterpriseAdmin     bool
	SessionToken          string
	Settings              *auth2.AccountSettings
	Enforcements          *auth2.AccountEnforcements
	persistTwoFactorToken bool
	twoFactorToken        string
	authResponse          string
	authSalt              []byte
	authIterations        uint32
}

func (context *AuthContext) refreshSessionToken(endpoint auth2.KeeperEndpoint) (sessionToken string, err error) {
	loginRq := &auth2.LoginCommand{
		Version:      2,
		Username:     context.Username,
		AuthResponse: context.authResponse,
	}
	if context.twoFactorToken != "" {
		loginRq.TwoFactorToken = context.twoFactorToken
		loginRq.TwoFactorType = "device_token"
	}
	loginRs := &auth2.LoginResponse{}
	err = endpoint.ExecuteV2Command(loginRq, loginRs)
	if err == nil {
		if loginRs.IsSuccess() {
			sessionToken = loginRs.SessionToken
		} else {
			err = auth2.NewKeeperApiError(loginRs.GetKeeperApiResponse())
		}
	}
	return
}

func (context *AuthContext) executeAuthCommand(endpoint auth2.KeeperEndpoint, rq interface{}, rs interface{}, throwOnError bool) (err error) {
	var authCommand *auth2.AuthorizedCommand = nil
	if tc, ok := rq.(auth2.ToAuthorizedCommand); ok {
		authCommand = tc.GetAuthorizedCommand()
		authCommand.Username = context.Username
		authCommand.SessionToken = context.SessionToken
	}
	if err = endpoint.ExecuteV2Command(rq, rs); err != nil {
		return
	}
	if toRs, ok := rs.(auth2.ToKeeperApiResponse); ok {
		authRs := toRs.GetKeeperApiResponse()
		if !authRs.IsSuccess() && authRs.ResultCode == "auth_failed" {
			context.SessionToken = ""
			var sessionToken string
			if sessionToken, err = context.refreshSessionToken(endpoint); err == nil {
				context.SessionToken = sessionToken
				if authCommand != nil {
					authCommand.SessionToken = context.SessionToken
				}
				if err = endpoint.ExecuteV2Command(rq, rs); err != nil {
					return
				}
				if toRs, ok = rs.(auth2.ToKeeperApiResponse); ok {
					authRs = toRs.GetKeeperApiResponse()
				}
			}
		}
		if !authRs.IsSuccess() && throwOnError {
			err = auth2.NewKeeperApiError(authRs)
		}
	}
	return
}

type primaryCredentials struct {
	username   string
	password   string
	salt       []byte
	iterations uint32
}

type secondaryCredentials struct {
	secondFactorType     string
	secondFactorToken    string
	secondFactorDuration *TwoFactorCodeDuration
}

type auth struct {
	ui              AuthUI
	settingsStorage auth2.ISettingsStorage
	endpoint        auth2.KeeperEndpoint
	context         *AuthContext
}

func NewAuth(ui AuthUI, settings auth2.ISettingsStorage) Auth {
	if settings == nil {
		settings = auth2.NewSettingsStorage(nil)
	}
	auth := &auth{
		ui:              ui,
		settingsStorage: settings,
		endpoint:        auth2.NewKeeperEndpoint(),
		context:         new(AuthContext),
	}
	sets := settings.GetSettings()
	if sets.LastServer() != "" {
		var server = sets.LastServer()
		var deviceId []byte = nil
		var keyId int32 = 1
		sers := auth2.GetServerSettings(sets, sets.LastServer())
		if sers != nil {
			server = sers.Server()
			deviceId = sers.DeviceId()
			keyId = sers.ServerKeyId()
		}
		auth.Endpoint().SetServerParams(server, deviceId, keyId)
	}

	return auth
}

func (a *auth) Ui() AuthUI {
	return a.ui
}
func (a *auth) SettingsStorage() auth2.ISettingsStorage {
	return a.settingsStorage
}
func (a *auth) Endpoint() auth2.KeeperEndpoint {
	return a.endpoint
}
func (a *auth) AuthContext() *AuthContext {
	return a.context
}
func (a *auth) IsAuthenticated() bool {
	return a.context != nil && len(a.context.SessionToken) > 0
}

var twoFactorErrorCodes = map[string]struct{}{
	"need_totp":            sdk.empty,
	"invalid_device_token": sdk.empty,
	"invalid_totp":         sdk.empty,
}
var expireErrorCodes = map[string]struct{}{
	"auth_expired":          sdk.empty,
	"auth_expired_transfer": sdk.empty,
}

func (a *auth) fixPostLoginErrors(loginRs *auth2.LoginResponse, context *AuthContext) (result *AuthContext, err error) {
	if a.ui != nil {
		switch loginRs.ResultCode {
		case "auth_expired":
			prompt := "Do you want to change your password?"
			if a.ui.Confirmation(loginRs.Message + "\n\n" + prompt) {
				var intro string
				var rules []*auth2.PasswordRules
				if context.Settings != nil {
					intro = context.Settings.PasswordRulesIntro
					rules = context.Settings.PasswordRules
				} else if context.Enforcements != nil {
					intro = context.Enforcements.PasswordRulesIntro
					rules = context.Enforcements.PasswordRules
				}
				matcher := &ruleMatcher{
					ruleIntro: intro,
					rules:     make([]passwordRule, len(rules)),
				}
				for i, r := range rules {
					matcher.rules[i] = passwordRule{
						description: r.Description,
						isMatch:     r.Match,
						pattern:     r.Pattern,
					}
					matcher.rules[i].regexp, _ = regexp.Compile(r.Pattern)
				}
				if password := a.ui.GetNewPassword(matcher); password != "" {
					failedRules := matcher.MatchFailedRules(password)
					if len(failedRules) == 0 {
						var primary *primaryCredentials
						if primary, err = context.changeMasterPassword(a.endpoint, password); err == nil {
							var secondary *secondaryCredentials
							if context.twoFactorToken != "" {
								secondary = &secondaryCredentials{
									secondFactorType:  "device_token",
									secondFactorToken: context.twoFactorToken,
								}
							}
							return a.executeLoginCommand(primary, secondary)
						}
					} else {
						err = auth2.NewKeeperError(failedRules[0])
					}
				}
			}
		case "auth_expired_transfer":
			prompt := "Do you accept Account Transfer policy?"
			if a.ui.Confirmation(loginRs.Message + "\n\n" + prompt) {
				if context.shareAccount(a.endpoint) == nil {
					var sessionToken string
					if sessionToken, err = context.refreshSessionToken(a.endpoint); err == nil {
						context.SessionToken = sessionToken
						result = context
						return
					}
				}
			}
		default:
			break
		}
	} else {
		err = auth2.NewKeeperError("cannot fix login issues in UI-less mode")
	}
	if err == nil {
		err = auth2.NewKeeperApiError(loginRs.GetKeeperApiResponse())
	}
	return
}

func (a *auth) executeLoginCommand(primary *primaryCredentials, secondary *secondaryCredentials) (result *AuthContext, err error) {
	var authHash = auth2.Base64UrlEncode(auth2.DeriveKeyHashV1(primary.password, primary.salt, primary.iterations))
	loginRq := &auth2.LoginCommand{
		Version:             2,
		Include:             []string{"keys", "settings", "enforcements", "is_enterprise_admin", "client_key"},
		Username:            strings.ToLower(primary.username),
		AuthResponse:        authHash,
		PlatformDeviceToken: auth2.Base64UrlEncode(a.endpoint.DeviceToken()),
	}
	if secondary != nil {
		loginRq.TwoFactorToken = secondary.secondFactorToken
		loginRq.TwoFactorType = secondary.secondFactorType
		if secondary.secondFactorDuration != nil {
			var d = int32(*secondary.secondFactorDuration)
			loginRq.DeviceTokenExpiresInDays = &d
		}
	}
	var ok bool
	loginRs := new(auth2.LoginResponse)
	if err = a.endpoint.ExecuteV2Command(loginRq, loginRs); err != nil {
		return
	}
	if !loginRs.IsSuccess() {
		if _, ok = twoFactorErrorCodes[loginRs.ResultCode]; ok {
			var channel = Other
			switch loginRs.Channel {
			case "two_factor_channel_google":
				channel = Authenticator
			case "two_factor_channel_duo":
				channel = DuoSecurity
			}
			tfaCode, duration := a.ui.GetTwoFactorCode(channel)
			if tfaCode != "" {
				secondary = &secondaryCredentials{
					secondFactorType:     "one_time",
					secondFactorToken:    tfaCode,
					secondFactorDuration: &duration,
				}
				return a.executeLoginCommand(primary, secondary)
			}
			err = auth2.NewKeeperApiError(loginRs.GetKeeperApiResponse())
		} else if _, ok = expireErrorCodes[loginRs.ResultCode]; ok {
		} else {
			err = auth2.NewKeeperApiError(loginRs.GetKeeperApiResponse())
		}
	}
	if err == nil {
		if loginRs.Keys != nil {
			result = new(AuthContext)
			result.Username = loginRq.Username
			result.SessionToken = loginRs.SessionToken
			result.Settings = loginRs.Settings
			result.Enforcements = loginRs.Enforcements
			result.authResponse = authHash
			result.authSalt = primary.salt
			result.authIterations = primary.iterations
			if loginRs.DeviceToken != "" {
				result.twoFactorToken = loginRs.DeviceToken
				result.persistTwoFactorToken = loginRs.DtScope == "expiration"
			}
			if loginRs.IsEnterpriseAdmin != nil {
				result.IsEnterpriseAdmin = *loginRs.IsEnterpriseAdmin
			}

			if loginRs.Keys.EncryptedDataKey != "" {
				key := auth2.DeriveKeyHashV2("data_key", primary.password, primary.salt, primary.iterations)
				result.DataKey, _ = auth2.DecryptAesV2(auth2.Base64UrlDecode(loginRs.Keys.EncryptedDataKey), key)
			}
			if result.DataKey == nil && loginRs.Keys.EncryptionParams != "" {
				result.DataKey, err = auth2.DecryptEncryptionParams(loginRs.Keys.EncryptionParams, primary.password)
			}
			if result.DataKey != nil {
				if loginRs.Keys.EncryptedPrivateKey != "" {
					var pkData = auth2.Base64UrlDecode(loginRs.Keys.EncryptedPrivateKey)
					if pkData, err = auth2.DecryptAesV1(pkData, result.DataKey); err == nil {
						result.PrivateKey, err = auth2.LoadPrivateKey(pkData)
					}
				}
				if loginRs.ClientKey != "" {
					var clientKey = auth2.Base64UrlDecode(loginRs.ClientKey)
					result.ClientKey, _ = auth2.DecryptAesV1(clientKey, result.DataKey)
				}
			} else {
				err = auth2.NewKeeperError("missing data key")
			}
			if err == nil {
				if loginRs.IsSuccess() {
					if result.ClientKey == nil {
						var clientKey = auth2.GenerateAesKey()
						var encClientKey []byte
						if encClientKey, err = auth2.EncryptAesV1(clientKey, result.DataKey); err == nil {
							cmd := &auth2.SetClientKeyCommand{
								ClientKey: auth2.Base64UrlEncode(encClientKey),
							}
							rs := new(auth2.SetClientKeyResponse)
							if err = a.ExecuteAuthCommand(cmd, rs, false); err == nil {
								if !rs.IsSuccess() {
									if rs.ResultCode == "exists" {
										encClientKey = auth2.Base64UrlDecode(rs.ClientKey)
										clientKey, _ = auth2.DecryptAesV1(encClientKey, result.DataKey)
										err = nil
									}
								}
							}
						}
						result.ClientKey = clientKey
					}
					return
				} else {
					return a.fixPostLoginErrors(loginRs, result)
				}
			}
			err = auth2.NewKeeperApiError(loginRs.GetKeeperApiResponse())
		}
	}

	return
}

func (a *auth) Login(username string, password string) (err error) {
	if username == "" || password == "" {
		return auth2.NewKeeperError("empty username and/or password")
	}
	var preLogin *protobuf.PreLoginResponse
	if preLogin, err = a.GetPreLogin(username); err != nil {
		return
	}

	var salt = preLogin.Salt[0]
	var primary = &primaryCredentials{
		username:   username,
		password:   password,
		salt:       salt.Salt,
		iterations: uint32(salt.Iterations),
	}
	var secondary *secondaryCredentials
	configuration := a.settingsStorage.GetSettings()
	userConf := auth2.GetUserSettings(configuration, username)
	if userConf != nil {
		var token = userConf.TwoFactorToken()
		if token != "" {
			secondary = &secondaryCredentials{
				secondFactorType:  "device_token",
				secondFactorToken: token,
			}
		}
	}
	var context *AuthContext
	if context, err = a.executeLoginCommand(primary, secondary); err == nil {
		a.context = context
		a.StoreConfigurationIfChanged(configuration)
	}
	return
}

func (a *auth) Logout() {
	a.context = new(AuthContext)
}

func (a *auth) GetPreLogin(username string) (rs *protobuf.PreLoginResponse, err error) {
	var deviceToken []byte
	for attempt := 0; attempt < 5; attempt++ {
		deviceToken, err = a.endpoint.GetDeviceToken()
		rq := &protobuf.PreLoginRequest{
			AuthRequest: &protobuf.AuthRequest{
				ClientVersion:        a.endpoint.ClientVersion(),
				Username:             strings.ToLower(username),
				EncryptedDeviceToken: deviceToken,
			},
			LoginType: protobuf.LoginType_NORMAL,
		}
		var rqBody, rsBody []byte
		if rqBody, err = proto.Marshal(rq); err == nil {
			payload := &protobuf.ApiRequestPayload{
				Payload: rqBody,
			}
			if rsBody, err = a.endpoint.ExecuteRest("authentication/pre_login", payload); err == nil {
				preLoginRs := new(protobuf.PreLoginResponse)
				if err = proto.Unmarshal(rsBody, preLoginRs); err == nil {
					return preLoginRs, nil
				} else {
					return nil, err
				}
			} else {
				switch v := err.(type) {
				case *auth2.KeeperInvalidDeviceToken:
					a.endpoint.InvalidateDeviceToken()
					continue
				case *auth2.KeeperRegionRedirect:
					conf := a.settingsStorage.GetSettings()
					serverConf := auth2.GetServerSettings(conf, a.endpoint.Server())
					if serverConf != nil {
						if serverConf.ServerKeyId() != a.endpoint.ServerKeyId() ||
							!bytes.Equal(serverConf.DeviceId(), a.endpoint.DeviceToken()) {
							newServerConf := auth2.NewServerSettings(serverConf.Server())
							newServerConf.SetDeviceId(a.endpoint.DeviceToken())
							newServerConf.SetServerKeyId(a.endpoint.ServerKeyId())
							newConf := auth2.NewSettings(conf)
							newConf.MergeServerSettings(newServerConf)
							a.settingsStorage.PutSettings(newConf)
						}
					}
					var newServer = v.RegionHost()
					var newDeviceToken []byte = nil
					var newServerKeyId int32 = 1
					serverConf = auth2.GetServerSettings(conf, a.endpoint.Server())
					if serverConf != nil {
						newDeviceToken = serverConf.DeviceId()
						newServerKeyId = serverConf.ServerKeyId()
					}
					a.endpoint.SetServerParams(newServer, newDeviceToken, newServerKeyId)
					continue
				default:
					return
				}
			}
		}
	}
	err = auth2.NewKeeperInvalidDeviceToken("Too many attempts")
	return
}

func (a *auth) StoreConfigurationIfChanged(configuration auth2.ISettings) {
	shouldSaveConfig := configuration.LastServer() == "" || configuration.LastUsername() == "" ||
		configuration.LastServer() != a.endpoint.Server() || configuration.LastUsername() != a.context.Username
	serverConf := auth2.GetServerSettings(configuration, a.endpoint.Server())
	shouldSaveServer := serverConf == nil || !bytes.Equal(serverConf.DeviceId(), a.endpoint.DeviceToken()) ||
		serverConf.ServerKeyId() != a.endpoint.ServerKeyId()
	userConf := auth2.GetUserSettings(configuration, a.context.Username)
	shouldSaveUser := userConf == nil || userConf.TwoFactorToken() != a.context.twoFactorToken

	if shouldSaveUser || shouldSaveServer || shouldSaveConfig {
		newSettings := auth2.NewSettings(configuration)
		if shouldSaveConfig {
			newSettings.lastUsername = a.context.Username
			newSettings.lastServer = a.endpoint.Server()
		}
		if shouldSaveUser {
			newUser := auth2.NewUserSettings(a.context.Username)
			if a.context.persistTwoFactorToken {
				newUser.twoFactorToken = a.context.twoFactorToken
			}
			newSettings.MergeUserSettings(newUser)
		}
		if shouldSaveServer {
			newServer := auth2.NewServerSettings(a.endpoint.Server())
			newServer.deviceId = a.endpoint.DeviceToken()
			newServer.serverKeyId = a.endpoint.ServerKeyId()
			newSettings.MergeServerSettings(newServer)
		}

		a.settingsStorage.PutSettings(newSettings)
	}
}

func (a *auth) ExecuteAuthCommand(rq interface{}, rs interface{}, throwOnError bool) (err error) {
	return a.context.executeAuthCommand(a.endpoint, rq, rs, throwOnError)
}

type passwordRule struct {
	isMatch     bool
	pattern     string
	description string
	regexp      *regexp.Regexp
}
type ruleMatcher struct {
	ruleIntro string
	rules     []passwordRule
}

func (matcher *ruleMatcher) MatchFailedRules(password string) []string {
	result := make([]string, 0)
	for _, rule := range matcher.rules {
		if !rule.regexp.Match([]byte(password)) {
			result = append(result, rule.description)
		}
	}
	return result
}
func (matcher *ruleMatcher) GetRuleIntro() string {
	return matcher.ruleIntro
}

func (context *AuthContext) changeMasterPassword(endpoint auth2.KeeperEndpoint, password string) (credentials *primaryCredentials, err error) {
	authSalt := auth2.GetRandomBytes(16)
	authVerifier := auth2.CreateAuthVerifier(password, authSalt, context.authIterations)
	keySalt := auth2.GetRandomBytes(16)
	var encryptionParameters string
	if encryptionParameters, err = auth2.CreateEncryptionParams(password, keySalt, context.authIterations, context.DataKey); err == nil {
		cmd := &auth2.ChangeMasterPasswordCommand{
			AuthVerifier:     authVerifier,
			EncryptionParams: encryptionParameters,
		}
		rs := new(auth2.KeeperApiResponse)
		if err = context.executeAuthCommand(endpoint, cmd, rs, true); err == nil {
			credentials = &primaryCredentials{
				username:   context.Username,
				password:   password,
				salt:       authSalt,
				iterations: context.authIterations,
			}
		}
	}
	return
}

func (context *AuthContext) shareAccount(endpoint auth2.KeeperEndpoint) (err error) {
	for _, st := range context.Settings.ShareAccountTo {
		var key crypto.PublicKey
		if key, err = auth2.LoadPublicKey(auth2.Base64UrlDecode(st.PublicKey)); err != nil {
			return
		}
		var transferKey []byte
		if transferKey, err = auth2.EncryptRsa(context.DataKey, key); err != nil {
			return
		}
		cmd := &auth2.ShareAccountCommand{
			ToRoleId:    st.RoleId,
			TransferKey: auth2.Base64UrlEncode(transferKey),
		}
		rs := new(auth2.KeeperApiResponse)
		if err = context.executeAuthCommand(endpoint, cmd, rs, true); err != nil {
			return
		}
	}
	return
}
