package sdk

import (
	"bytes"
	"crypto"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"keepersecurity.com/sdk/protobuf"
	"regexp"
	"strings"
)

type AuthContext struct {
	Username string
	DataKey []byte
	ClientKey []byte
	PrivateKey crypto.PrivateKey
	IsEnterpriseAdmin bool
	SessionToken string
	Enforcements *AccountEnforcements
	Settings *AccountSettings
	twoFactorToken string
	authResponse string
}

type Auth interface {
	Ui() AuthUI
	SettingsStorage() ISettingsStorage
	Endpoint() KeeperEndpoint
	AuthContext() *AuthContext
	IsAuthenticated() bool
	Login(string, string) error
	Logout()
	ExecuteAuthCommand(interface{}, interface{}, bool) error
}
func ExecRq(auth Auth, rq interface{}) error {
	return auth.ExecuteAuthCommand(rq, new(KeeperApiResponse), true)
}


type auth struct {
	ui              AuthUI
	settingsStorage ISettingsStorage
	endpoint        KeeperEndpoint
	context         *AuthContext
}

func NewAuth(ui AuthUI, settings ISettingsStorage) Auth {
	if settings == nil {
		settings = NewSettingsStorage(nil)
	}
	auth := &auth{
		ui:              ui,
		settingsStorage: settings,
		endpoint:        NewKeeperEndpoint(),
		context:         new(AuthContext),
	}
	sets := settings.GetSettings()
	if sets.LastServer() != "" {
		var server = sets.LastServer()
		var deviceId []byte = nil
		var keyId int32 = 1
		sers := sets.GetServerSettings(sets.LastServer())
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
func (a *auth) SettingsStorage() ISettingsStorage {
	return a.settingsStorage
}
func (a *auth) Endpoint() KeeperEndpoint {
	return a.endpoint
}
func (a *auth) AuthContext() *AuthContext {
	return a.context
}
func (a *auth) IsAuthenticated() bool {
	return a.context != nil && len(a.context.SessionToken) > 0
}
func (a *auth) Login(username string, password string) (err error) {
	if username == "" || password == "" {
		return NewKeeperError("empty username and/or password")
	}
	configuration := a.settingsStorage.GetSettings()
	userConf := configuration.GetUserSettings(username)
	var token string
	if userConf != nil {
		token = userConf.TwoFactorToken()
	}
	var tokenType = "device_token"
	var tokenDuration int32 = Every30Days

	var authHash string
	var preLogin *protobuf.PreLoginResponse

	for attempt := 0; attempt < 5; attempt++ {
		if preLogin == nil {
			if preLogin, err = a.GetPreLogin(username); err != nil {
				return
			}
			authHash = ""
		}

		authParams := preLogin.Salt[0]
		var iterations = uint32(authParams.Iterations)
		salt := authParams.Salt
		if authHash == "" {
			authHash = Base64UrlEncode(DeriveKeyHashV1(password, salt, iterations))
		}
		loginRq := &LoginCommand{
			Version:      2,
			Include:      []string{"keys", "settings", "enforcements", "is_enterprise_admin", "client_key"},
			Username:     strings.ToLower(username),
			AuthResponse: authHash,
		}
		if token != "" {
			loginRq.TwoFactorToken = token
			loginRq.TwoFactorType = tokenType
			if tokenType == "one_time" {
				loginRq.DeviceTokenExpiresInDays = &tokenDuration
			}
		}
		loginRs := new(LoginResponse)
		if err = a.endpoint.ExecuteV2Command(loginRq, loginRs); err != nil {
			return
		}
		if !loginRs.IsSuccess() && loginRs.ResultCode == "auth_failed" {
			return NewKeeperApiError(loginRs.GetKeeperApiResponse())
		}
		if loginRs.DeviceToken != "" {
			token = loginRs.DeviceToken
			tokenType = "device_token"
		}

		if loginRs.SessionToken != "" {
			a.context.SessionToken = loginRs.SessionToken
			a.context.Username = loginRq.Username
			a.context.Settings = loginRs.Settings
		}
		if loginRs.Keys != nil {
			var dataKey []byte
			if loginRs.Keys.EncryptedDataKey != "" {
				key := DeriveKeyHashV2("data_key", password, salt, iterations)
				dataKey, _ = DecryptAesV2(Base64UrlDecode(loginRs.Keys.EncryptedDataKey), key)
			}
			if dataKey == nil && loginRs.Keys.EncryptionParams != "" {
				dataKey, err = DecryptEncryptionParams(loginRs.Keys.EncryptionParams, password)
			}
			if dataKey == nil {
				return NewKeeperError("Missing data key")
			}
			a.context.DataKey = dataKey
			if loginRs.Keys.EncryptedPrivateKey != "" {
				pkData, err := DecryptAesV1(Base64UrlDecode(loginRs.Keys.EncryptedPrivateKey), a.context.DataKey)
				if err == nil {
					a.context.PrivateKey, err = LoadPrivateKey(pkData)
					if err != nil {
						glog.Warning("Cannot decrypt Private Key")
						err = nil
					}
				} else {
					glog.Warning("Cannot decrypt Private Key")
					err = nil
				}
			}
		}

		if loginRs.IsSuccess() {
			var clientKey []byte
			if loginRs.ClientKey != "" {
				clientKey = Base64UrlDecode(loginRs.ClientKey)
			} else {
				ck := GenerateAesKey()
				if clientKey, err = EncryptAesV1(ck, a.context.DataKey); err == nil {
					cmd := &SetClientKeyCommand{
						ClientKey: Base64UrlEncode(clientKey),
					}
					rs := new(SetClientKeyResponse)
					if err = a.ExecuteAuthCommand(cmd, rs, false); err == nil {
						if !rs.IsSuccess() {
							if rs.ResultCode == "exists" {
								clientKey = Base64UrlDecode(rs.ClientKey)
							}
						}
					}
				}
			}
			if clientKey != nil {
				a.context.ClientKey, _ = DecryptAesV1(clientKey, a.context.DataKey)
			}
			a.context.twoFactorToken = token
			a.context.authResponse = authHash
			if loginRs.IsEnterpriseAdmin != nil {
				a.context.IsEnterpriseAdmin = *loginRs.IsEnterpriseAdmin
			}
			a.context.Enforcements = loginRs.Enforcements

			a.StoreConfigurationIfChanged(configuration)
			return
		} else {
			if a.ui != nil {
				switch loginRs.ResultCode {
				case "need_totp", "invalid_device_token", "invalid_totp":
					var channel = Other
					switch loginRs.Channel {
					case "two_factor_channel_google":
						channel = Authenticator
					case "two_factor_channel_duo":
						channel = DuoSecurity
					}

					tfaCode, duration := a.ui.GetTwoFactorCode(channel)
					if tfaCode != "" {
						token = tfaCode
						tokenType = "one_time"
						tokenDuration = int32(duration)
						continue
					}
				case "auth_expired":
					prompt := "Do you want to change your password?"
					if a.ui.Confirmation(loginRs.Message + "\n\n" + prompt) {
						params := preLogin.Salt[0]
						if newPassword, err := a.ChangeMasterPassword(uint32(params.Iterations)); err == nil {
							preLogin = nil
							authHash = ""
							password = newPassword
							continue
						}
					}
				case "auth_expired_transfer":
					prompt := "Do you accept Account Transfer policy?"
					if a.ui.Confirmation(loginRs.Message + "\n\n" + prompt) {
						if a.ShareAccount(a.context.Settings.ShareAccountTo) == nil {
							continue
						}
					}
				}
			}
			return NewKeeperApiError(loginRs.GetKeeperApiResponse())
		}
	}
	return NewKeeperError("Too many attempts")
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
			if rsBody, err = a.endpoint.ExecuteRest("authentication/pre_login", rqBody); err == nil {
				preLoginRs := new(protobuf.PreLoginResponse)
				if err = proto.Unmarshal(rsBody, preLoginRs); err == nil {
					return preLoginRs, nil
				} else {
					return nil, err
				}
			} else {
				switch v := err.(type) {
				case *KeeperInvalidDeviceToken:
					a.endpoint.InvalidateDeviceToken()
					continue
				case *KeeperRegionRedirect:
					conf := a.settingsStorage.GetSettings()
					serverConf := conf.GetServerSettings(a.endpoint.Server())
					if serverConf != nil {
						if serverConf.ServerKeyId() != a.endpoint.ServerKeyId() ||
							!bytes.Equal(serverConf.DeviceId(), a.endpoint.DeviceToken()) {
							newServerConf := NewServerSettings(serverConf.Server())
							newServerConf.SetDeviceId(a.endpoint.DeviceToken())
							newServerConf.SetServerKeyId(a.endpoint.ServerKeyId())
							newConf := NewSettings(conf)
							newConf.MergeServerSettings(newServerConf)
							a.settingsStorage.PutSettings(newConf)
						}
					}
					var newServer = v.RegionHost()
					var newDeviceToken []byte = nil
					var newServerKeyId int32 = 1
					serverConf = conf.GetServerSettings(a.endpoint.Server())
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
	err = NewKeeperInvalidDeviceToken("Too many attempts")
	return
}

func (a *auth) StoreConfigurationIfChanged(configuration ISettings) {
	shouldSaveConfig := configuration.LastServer() == "" || configuration.LastUsername() == "" ||
		configuration.LastServer() != a.endpoint.Server() || configuration.LastUsername() != a.context.Username
	serverConf := configuration.GetServerSettings(a.endpoint.Server())
	shouldSaveServer := serverConf == nil || !bytes.Equal(serverConf.DeviceId(), a.endpoint.DeviceToken()) ||
		serverConf.ServerKeyId() != a.endpoint.ServerKeyId()
	userConf := configuration.GetUserSettings(a.context.Username)
	shouldSaveUser := userConf == nil || userConf.TwoFactorToken() != a.context.twoFactorToken

	if shouldSaveUser || shouldSaveServer || shouldSaveConfig {
		newSettings := NewSettings(configuration)
		if shouldSaveConfig {
			newSettings.lastUsername = a.context.Username
			newSettings.lastServer = a.endpoint.Server()
		}
		if shouldSaveUser {
			newUser := NewUserSettings(a.context.Username)
			newUser.twoFactorToken = a.context.twoFactorToken
			newSettings.MergeUserSettings(newUser)
		}
		if shouldSaveServer {
			newServer := NewServerSettings(a.endpoint.Server())
			newServer.deviceId = a.endpoint.DeviceToken()
			newServer.serverKeyId = a.endpoint.ServerKeyId()
			newSettings.MergeServerSettings(newServer)
		}

		a.settingsStorage.PutSettings(newSettings)
	}
}

func (a *auth) RefreshSessionToken() (err error) {
	loginRq := &LoginCommand{
		Version:      2,
		Include:      nil,
		AuthResponse: a.context.authResponse,
		Username:     a.context.Username,
	}
	if a.context.twoFactorToken != "" {
		loginRq.TwoFactorToken = a.context.twoFactorToken
		loginRq.TwoFactorType = "device_token"
	}
	loginRs := &LoginResponse{}
	err = a.endpoint.ExecuteV2Command(loginRq, loginRs)
	if err == nil {
		a.context.SessionToken = loginRs.SessionToken
	}
	return
}

func (a *auth) sendKeeperCommand(rq interface{}) (err error) {
	return a.ExecuteAuthCommand(rq, new(KeeperApiResponse), true)
}

func (a *auth) ExecuteAuthCommand(rq interface{}, rs interface{}, throwOnError bool) (err error) {
	var authCommand *AuthorizedCommand = nil
	if tc, ok := rq.(ToAuthorizedCommand); ok {
		authCommand = tc.GetAuthorizedCommand()
		authCommand.Username = a.context.Username
		authCommand.SessionToken = a.context.SessionToken
	}
	if err = a.endpoint.ExecuteV2Command(rq, rs); err != nil {
		return
	}
	if toRs, ok := rs.(ToKeeperApiResponse); ok {
		authRs := toRs.GetKeeperApiResponse()
		if !authRs.IsSuccess() && authRs.ResultCode == "auth_failed" {
			a.context.SessionToken = ""
			err = a.RefreshSessionToken()
			if err == nil {
				if authCommand != nil {
					authCommand.SessionToken = a.context.SessionToken
				}
				if err = a.endpoint.ExecuteV2Command(rq, rs); err != nil {
					return
				}
				if toRs, ok = rs.(ToKeeperApiResponse); ok {
					authRs = toRs.GetKeeperApiResponse()
				}
			}
		}
		if !authRs.IsSuccess() && throwOnError {
			err = NewKeeperApiError(authRs)
		}
	}
	return
}

type passwordRule struct {
	isMatch bool
	pattern string
	description string
	regexp *regexp.Regexp
}
type ruleMatcher struct {
	ruleIntro string
	rules []passwordRule
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

func (a *auth) ChangeMasterPassword(iterations uint32) (password string, err error) {
	var intro string
	var rules []*PasswordRules
	if a.context.Settings != nil {
		intro = a.context.Settings.PasswordRulesIntro
		rules = a.context.Settings.PasswordRules
	}
	if rules == nil {
		if userParams, err := a.endpoint.GetNewUserParams(a.context.Username); err == nil {
			rules = make([]*PasswordRules, 0)
			for i, regex := range userParams.PasswordMatchRegex {
				rules = append(rules, &PasswordRules{
					Match:       true,
					Pattern:     regex,
					Description: userParams.PasswordMatchDescription[i],
				})
			}
		}
	}

	matcher := & ruleMatcher{
		ruleIntro: intro,
		rules: make([]passwordRule, len(rules)),
	}
	for i, r := range rules {
		matcher.rules[i] = passwordRule{
			description: r.Description,
			isMatch: r.Match,
			pattern: r.Pattern,
		}
		matcher.rules[i].regexp, _ = regexp.Compile(r.Pattern)
	}
	password = a.ui.GetNewPassword(matcher)
	if password != "" {
		rules := matcher.MatchFailedRules(password)
		if len(rules) == 0 {
			authSalt := GetRandomBytes(16)
			authVerifier := CreateAuthVerifier(password, authSalt, iterations)
			keySalt := GetRandomBytes(16)
			if encryptionParameters, err := CreateEncryptionParams(password, keySalt, iterations, a.context.DataKey); err == nil {
				cmd := & ChangeMasterPasswordCommand{
					AuthVerifier:     authVerifier,
					EncryptionParams: encryptionParameters,
				}
				rs := new(KeeperApiResponse)
				err = a.ExecuteAuthCommand(cmd, rs, true)
			}
		} else {
			err = NewKeeperError(rules[0])
		}
	}
	return
}

func (a *auth) ShareAccount(shareTo []*AccountShareTo) error {
	for _, st := range shareTo {
		if key, err := LoadPublicKey(Base64UrlDecode(st.PublicKey)); err == nil {
			if tk, err := EncryptRsa(a.context.DataKey, key); err == nil {
				cmd := &ShareAccountCommand{
					ToRoleId:    st.RoleId,
					TransferKey: Base64UrlEncode(tk),
				}
				rs := new(KeeperApiResponse)
				if err = a.ExecuteAuthCommand(cmd, rs, true); err != nil {
					return err
				}
			} else {
				return err
			}
		} else {
			return err
		}
	}
	return nil
}