package auth_impl

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_account_summary"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_auth"
	"github.com/keeper-security/keeper-sdk-golang/sdk/internal/proto_sync_down"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"time"
)

type ssoLoginInfo struct {
	isCloud      bool
	ssoProvider  string
	ssoUrl       string
	idpSessionId string
}

func (sso *ssoLoginInfo) IsCloud() bool {
	return sso.isCloud
}
func (sso *ssoLoginInfo) SsoProvider() string {
	return sso.ssoProvider
}
func (sso *ssoLoginInfo) SsoUrl() string {
	return sso.ssoUrl
}
func (sso *ssoLoginInfo) IdpSessionId() string {
	return sso.idpSessionId
}

type loginContext struct {
	Username          string
	Passwords         []string
	CloneCode         []byte
	DeviceToken       []byte
	DevicePrivateKey  *ecdh.PrivateKey
	MessageSessionUid []byte
	AccountType       auth.AccountAuthType
	SsoLoginInfo      *ssoLoginInfo
}

type loginAuth struct {
	endpoint          auth.IKeeperEndpoint
	loginContext      *loginContext
	alternatePassword bool
	resumeSession     bool
	loginStep         auth.ILoginStep
	onNextStep        func()
	onRegionChanged   func(string)
	pushNotifications auth.IPushEndpoint
}

func NewLoginAuth(endpoint auth.IKeeperEndpoint) auth.ILoginAuth {
	return &loginAuth{
		endpoint:          endpoint,
		loginContext:      &loginContext{},
		loginStep:         newReadyStep(),
		resumeSession:     false,
		alternatePassword: false,
	}
}
func (la *loginAuth) Endpoint() auth.IKeeperEndpoint {
	return la.endpoint
}
func (la *loginAuth) Step() auth.ILoginStep {
	return la.loginStep
}
func (la *loginAuth) AlternatePassword() bool {
	return la.alternatePassword
}
func (la *loginAuth) SetAlternatePassword(alternatePassword bool) {
	la.alternatePassword = alternatePassword
}
func (la *loginAuth) ResumeSession() bool {
	return la.resumeSession
}
func (la *loginAuth) SetResumeSession(resumeSession bool) {
	la.resumeSession = resumeSession
}
func (la *loginAuth) setLoginStep(step auth.ILoginStep) {
	if la.loginStep != nil {
		if la.loginStep != step {
			_ = la.loginStep.Close()
			la.loginStep = nil
		} else {
			return
		}
	}
	la.loginStep = step
	if la.onNextStep != nil {
		la.onNextStep()
	}
}
func (la *loginAuth) Close() (err error) {
	la.setLoginStep(newReadyStep())
	if la.pushNotifications != nil {
		if !la.pushNotifications.IsClosed() {
			err = la.pushNotifications.Close()
		}
		la.pushNotifications = nil
	}
	return
}
func (la *loginAuth) OnNextStep() func() {
	return la.onNextStep
}
func (la *loginAuth) SetOnNextStep(onNextStep func()) {
	la.onNextStep = onNextStep
}
func (la *loginAuth) OnRegionChanged() func(string) {
	return la.onRegionChanged
}
func (la *loginAuth) SetOnRegionChanged(onRegionChanged func(string)) {
	la.onRegionChanged = onRegionChanged
}
func (la *loginAuth) Login(username string, passwords ...string) {
	la.loginContext = &loginContext{
		Username:          username,
		Passwords:         passwords,
		MessageSessionUid: api.GetRandomBytes(16),
		AccountType:       auth.AuthType_Regular,
	}
	var err error
	var config auth.IKeeperConfiguration
	if config, err = la.endpoint.ConfigurationStorage().Get(); err == nil {
		if len(la.loginContext.Username) == 0 {
			la.loginContext.Username = config.LastLogin()
			if len(la.loginContext.Username) == 0 {
				la.setLoginStep(newErrorStep(api.NewKeeperError("Username is required")))
				return
			}

		}
		var uc = config.Users().Get(la.loginContext.Username)
		if uc != nil {
			if uc.Password() != "" {
				la.loginContext.Passwords = append(la.loginContext.Passwords, uc.Password())
			}
			var us = uc.Server()
			if us != "" {
				if us != la.endpoint.Server() {
					la.endpoint.SetServer(us)
				}
			}
		}
	}
	if err = la.ensureDeviceTokenLoaded(); err == nil {
		if err = la.startLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, false); err != nil {
			var rr *api.RegionRedirectError
			var idt *api.KeeperInvalidDeviceToken
			if errors.As(err, &rr) {
				err = la.redirectToRegion(rr.RegionHost())
			} else if errors.As(err, &idt) {
				if la.loginContext.DeviceToken != nil {
					var dt = api.Base64UrlEncode(la.loginContext.DeviceToken)
					config.Devices().Delete(dt)
					err = la.endpoint.ConfigurationStorage().Put(config)
				} else {
					err = nil
				}
			}
			if err == nil {
				if err = la.ensureDeviceTokenLoaded(); err == nil {
					err = la.startLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, false)
				}
			}
		}
	}
	if err != nil {
		la.setLoginStep(newErrorStep(err))
	}
}

func (la *loginAuth) LoginSso(providerName string) {
	var rq = &proto_auth.SsoServiceProviderRequest{
		Name:          providerName,
		ClientVersion: la.endpoint.ClientVersion(),
		Locale:        la.endpoint.Locale(),
	}
	var rs = new(proto_auth.SsoServiceProviderResponse)
	var err error
	if err = la.executeRest("enterprise/get_sso_service_provider", rq, rs, nil); err != nil {
		var rr *api.RegionRedirectError
		if errors.As(err, &rr) {
			err = la.redirectToRegion(rr.RegionHost())
			err = la.executeRest("enterprise/get_sso_service_provider", rq, rs, nil)
		}
	}
	if err != nil {
		la.setLoginStep(newErrorStep(err))
		return
	}
	var ssoInfo = &ssoLoginInfo{
		isCloud:     rs.GetIsCloud(),
		ssoProvider: rs.GetName(),
		ssoUrl:      rs.GetSpUrl(),
	}
	la.loginContext = &loginContext{
		MessageSessionUid: api.GetRandomBytes(16),
		SsoLoginInfo:      ssoInfo,
	}
	if ssoInfo.isCloud {
		la.loginContext.AccountType = auth.AuthType_SsoCloud
	} else {
		la.loginContext.AccountType = auth.AuthType_OnsiteSso
	}
	if err = la.ensureDeviceTokenLoaded(); err == nil {
		err = la.onSsoRedirect(nil)
	}
	if err != nil {
		la.setLoginStep(newErrorStep(err))
	}
}

func (la *loginAuth) redirectToRegion(server string) (err error) {
	la.endpoint.SetServer(server)
	if la.onRegionChanged != nil {
		la.onRegionChanged(server)
	}
	return
}
func (la *loginAuth) executeRest(path string, request proto.Message, response proto.Message, sessionToken []byte) (err error) {
	var logger = api.GetLogger()
	var data []byte
	if request != nil {
		if data, err = proto.Marshal(request); err != nil {
			logger.Warn("Marshal protobuf error", zap.Error(err))
			return
		}
		if logger.Level().Enabled(zap.DebugLevel) {
			logger.Debug("[RQ] "+path, zap.String("request", protojson.Format(request)))
		}
	}
	if data, err = la.Endpoint().CommunicateKeeper(path, data, sessionToken); err != nil {
		return
	}
	if response != nil {
		if data != nil {
			if err = proto.Unmarshal(data, response); err != nil {
				logger.Warn("Unmarshal protobuf error", zap.Error(err))
				return
			}
			if logger.Level().Enabled(zap.DebugLevel) {
				logger.Debug("[RS] "+path, zap.String("response", protojson.Format(response)))
			}
		} else {
			logger.Warn("API path does not support response", zap.String("path", path))
			err = api.NewKeeperError(fmt.Sprintf("API path %s does not support response", path))
		}
	}
	return
}

func (la *loginAuth) ensureDeviceTokenLoaded() (err error) {
	var context = la.loginContext
	context.CloneCode = nil
	var config auth.IKeeperConfiguration
	if config, err = la.endpoint.ConfigurationStorage().Get(); err != nil {
		return
	}
	var server = la.endpoint.Server()
	var attempt = 0
	for attempt < 6 {
		attempt += 1
		if context.DeviceToken != nil && context.DevicePrivateKey != nil {
			var deviceToken = api.Base64UrlEncode(context.DeviceToken)
			var dc = config.Devices().Get(deviceToken)
			if dc != nil {
				var dsc = dc.ServerInfo().Get(server)
				if dsc != nil {
					var cloneCode = dsc.CloneCode()
					if cloneCode != "" {
						context.CloneCode = api.Base64UrlDecode(dsc.CloneCode())
					}
					return
				}
			} else {
				var idc = auth.NewDeviceConfiguration(deviceToken, api.UnloadEcPrivateKey(context.DevicePrivateKey))
				config.Devices().Put(idc)
				dc = config.Devices().Get(deviceToken)
			}
			if dc != nil {
				if err = la.registerDeviceInRegion(context.DeviceToken, context.DevicePrivateKey); err == nil {
					var idc = auth.CloneDeviceConfiguration(dc)
					var idsc = auth.NewDeviceServerConfiguration(server)
					idc.ServerInfo().Put(idsc)
					config.Devices().Put(idc)
					err = la.endpoint.ConfigurationStorage().Put(config)
					return
				} else {
					config.Devices().Delete(deviceToken)
				}
			}
			context.DeviceToken = nil
			context.DevicePrivateKey = nil
		} else {
			if context.Username != "" {
				var uc = config.Users().Get(context.Username)
				if uc != nil {
					var lastDevice = uc.LastDevice()
					if lastDevice != nil {
						var dc = config.Devices().Get(lastDevice.DeviceToken())
						if dc != nil {
							var pk *ecdh.PrivateKey
							if pk, err = api.LoadEcPrivateKey(dc.DeviceKey()); err == nil {
								context.DeviceToken = api.Base64UrlDecode(dc.DeviceToken())
								context.DevicePrivateKey = pk
								continue
							} else {
								config.Devices().Delete(dc.DeviceToken())
								err = nil
							}
						}
						var iuc = auth.CloneUserConfiguration(uc)
						iuc.SetLastDevice(nil)
						config.Users().Put(iuc)
					}
				}
			}
			var toDelete []string
			config.Devices().List(func(dc auth.IDeviceConfiguration) bool {
				var pk *ecdh.PrivateKey
				if pk, err = api.LoadEcPrivateKey(dc.DeviceKey()); err == nil {
					context.DeviceToken = api.Base64UrlDecode(dc.DeviceToken())
					context.DevicePrivateKey = pk
					return false
				}
				toDelete = append(toDelete, dc.Id())
				err = nil
				return true
			})
			for _, dt := range toDelete {
				config.Devices().Delete(dt)
			}
			if context.DeviceToken == nil || context.DevicePrivateKey == nil {
				break
			}
		}
	}
	context.DeviceToken, context.DevicePrivateKey, err = la.registerDevice()
	if err == nil {
		var idc = auth.NewDeviceConfiguration(api.Base64UrlEncode(context.DeviceToken),
			api.UnloadEcPrivateKey(context.DevicePrivateKey))
		config.Devices().Put(idc)
		err = la.endpoint.ConfigurationStorage().Put(config)
	}
	return
}

func (la *loginAuth) registerDevice() (deviceToken []byte, devicePrivateKey *ecdh.PrivateKey, err error) {
	var publicKey *ecdh.PublicKey
	var privateKey *ecdh.PrivateKey
	if privateKey, publicKey, err = api.GenerateEcKey(); err == nil {
		var rq = &proto_auth.DeviceRegistrationRequest{
			ClientVersion:   la.endpoint.ClientVersion(),
			DeviceName:      la.endpoint.DeviceName(),
			DevicePublicKey: api.UnloadEcPublicKey(publicKey),
		}
		var rs = new(proto_auth.Device)
		if err = la.executeRest("authentication/register_device", rq, rs, nil); err == nil {
			deviceToken = rs.EncryptedDeviceToken
			devicePrivateKey = privateKey
		}
	}
	return
}

func (la *loginAuth) registerDeviceInRegion(deviceToken []byte, devicePrivateKey *ecdh.PrivateKey) (err error) {
	var rq = &proto_auth.RegisterDeviceInRegionRequest{
		EncryptedDeviceToken: deviceToken,
		ClientVersion:        la.endpoint.ClientVersion(),
		DeviceName:           la.endpoint.DeviceName(),
		DevicePublicKey:      api.UnloadEcPublicKey(api.GetEcPublicKey(devicePrivateKey)),
	}
	err = la.executeRest("authentication/register_device_in_region", rq, nil, nil)
	if err != nil {
		var kae *api.KeeperApiError
		var idt *api.KeeperInvalidDeviceToken
		if errors.As(err, &kae) {
			if kae.ResultCode() == "exists" {
				err = nil
			}
		} else if errors.As(err, &idt) {
			if idt.Message() == "public key already exists" {
				err = nil
			}
		}
	}
	return
}
func (la *loginAuth) resumeLogin(method proto_auth.LoginMethod, loginToken []byte) error {
	var request = &proto_auth.StartLoginRequest{
		Username:             la.loginContext.Username,
		ClientVersion:        la.endpoint.ClientVersion(),
		EncryptedDeviceToken: la.loginContext.DeviceToken,
		EncryptedLoginToken:  loginToken,
		MessageSessionUid:    la.loginContext.MessageSessionUid,
		LoginMethod:          method,
		ForceNewLogin:        false,
	}
	return la.processStartLogin(request)
}

func (la *loginAuth) startLogin(method proto_auth.LoginMethod, newLogin bool) error {
	if newLogin {
		la.resumeSession = false
	}
	var request = &proto_auth.StartLoginRequest{
		ClientVersion:        la.endpoint.ClientVersion(),
		EncryptedDeviceToken: la.loginContext.DeviceToken,
		MessageSessionUid:    la.loginContext.MessageSessionUid,
		LoginMethod:          method,
		ForceNewLogin:        newLogin,
	}
	if la.loginContext.CloneCode != nil && la.resumeSession && method == proto_auth.LoginMethod_EXISTING_ACCOUNT {
		request.CloneCode = la.loginContext.CloneCode
	} else {
		request.CloneCode = la.loginContext.CloneCode
	}
	if la.alternatePassword {
		request.LoginType = proto_auth.LoginType_ALTERNATE
	} else {
		request.LoginType = proto_auth.LoginType_NORMAL
	}

	return la.processStartLogin(request)
}
func (la *loginAuth) processStartLogin(request *proto_auth.StartLoginRequest) (err error) {
	var logger = api.GetLogger()
	var response = new(proto_auth.LoginResponse)
	if err = la.executeRest("authentication/start_login", request, response, nil); err == nil {
		switch response.LoginState {
		case proto_auth.LoginState_LOGGED_IN:
			if la.loginContext.DevicePrivateKey == nil {
				logger.Warn("Login context does not have device private key")
				err = api.NewKeeperInvalidDeviceToken("Missing private key")
				return
			}
			err = la.onLoggedIn(response, func(encryptedDataKey []byte) ([]byte, error) {
				return api.DecryptEc(encryptedDataKey, la.loginContext.DevicePrivateKey)
			})
			if err != nil {
				return
			}
			if la.loginContext.SsoLoginInfo == nil {
				logger.Info("Successfully authenticated with Persistent Login")
			} else {
				logger.Info("Successfully authenticated with SSO")
			}
		case proto_auth.LoginState_REQUIRES_USERNAME:
			if len(la.loginContext.Username) > 0 {
				err = la.resumeLogin(proto_auth.LoginMethod_EXISTING_ACCOUNT, response.EncryptedLoginToken)
			} else {
				err = api.NewKeeperError("Username is required")
			}
		case proto_auth.LoginState_REGION_REDIRECT:
			err = api.NewKeeperRegionRedirect(response.GetStateSpecificValue(), "")
		case proto_auth.LoginState_DEVICE_APPROVAL_REQUIRED:
			err = la.onDeviceApprovalRequired(response)
		case proto_auth.LoginState_REQUIRES_2FA:
			err = la.onRequires2fa(response)
		case proto_auth.LoginState_REQUIRES_AUTH_HASH:
			err = la.onRequiresAuthHash(response)
		case proto_auth.LoginState_REDIRECT_CLOUD_SSO:
		case proto_auth.LoginState_REDIRECT_ONSITE_SSO:
			la.loginContext.SsoLoginInfo = &ssoLoginInfo{
				isCloud: response.LoginState == proto_auth.LoginState_REDIRECT_CLOUD_SSO,
				ssoUrl:  response.GetUrl(),
			}
			err = la.onSsoRedirect(response.EncryptedLoginToken)
		case proto_auth.LoginState_REQUIRES_DEVICE_ENCRYPTED_DATA_KEY:
			err = la.onRequestDataKey(response.EncryptedLoginToken)
		case proto_auth.LoginState_DEVICE_ACCOUNT_LOCKED:
		case proto_auth.LoginState_DEVICE_LOCKED:
			err = api.NewKeeperInvalidDeviceToken("Locked")
		default:
			var loginState = proto_auth.LoginState.String(response.LoginState)
			err = api.NewKeeperError(fmt.Sprintf("State %s: Not implemented", loginState))
		}
	}
	return
}

func (la *loginAuth) postLogin(authContext *authContext) error {
	var logger = api.GetLogger()
	var rq = &proto_account_summary.AccountSummaryRequest{
		SummaryVersion: 1,
	}
	var rs = new(proto_account_summary.AccountSummaryElements)
	var err error
	if err = la.executeRest("login/account_summary", rq, rs, authContext.sessionToken); err != nil {
		return err
	}
	authContext.settings = rs.Settings
	authContext.license = rs.License
	authContext.enforcements = rs.Enforcements
	authContext.isEnterpriseAdmin = rs.IsEnterpriseAdmin
	var data []byte
	if len(rs.ClientKey) > 0 {
		if data, err = api.DecryptAesV1(rs.ClientKey, authContext.dataKey); err == nil {
			authContext.clientKey = data
		} else {
			logger.Warn("Decrypt client key error", zap.Error(err))
		}
	}
	if len(rs.KeysInfo.EncryptedPrivateKey) > 0 {
		if data, err = api.DecryptAesV1(rs.KeysInfo.EncryptedPrivateKey, authContext.dataKey); err == nil {
			if authContext.rsaPrivateKey, err = api.LoadRsaPrivateKey(data); err != nil {
				logger.Warn("Parse RSA private key error", zap.Error(err))
			}
		} else {
			logger.Warn("Decrypt RSA private key error", zap.Error(err))
		}
	}
	if len(rs.KeysInfo.EncryptedEccPrivateKey) > 0 {
		if data, err = api.DecryptAesV2(rs.KeysInfo.EncryptedEccPrivateKey, authContext.dataKey); err == nil {
			if authContext.ecPrivateKey, err = api.LoadEcPrivateKey(data); err != nil {
				logger.Warn("Parse EC private key error", zap.Error(err))
			}
		} else {
			logger.Warn("Decrypt EC private key error", zap.Error(err))
		}
	}
	if len(rs.KeysInfo.EccPublicKey) > 0 {
		if authContext.ecPublicKey, err = api.LoadEcPublicKey(rs.KeysInfo.EccPublicKey); err != nil {
			logger.Warn("Parse EC public key error", zap.Error(err))
		}
	}

	if authContext.sessionRestriction == auth.SessionRestriction_Unrestricted {
		if authContext.license.AccountType == 2 {
			var rs1 = new(proto_sync_down.EnterprisePublicKeyResponse)
			err = la.executeRest("enterprise/get_enterprise_public_key", nil, rs1, authContext.sessionToken)
			if err == nil {
				if len(rs1.EnterpriseECCPublicKey) > 0 {
					if authContext.enterpriseEcPublicKey, err = api.LoadEcPublicKey(rs1.EnterpriseECCPublicKey); err != nil {
						logger.Warn("Parse Enterprise EC public key error", zap.Error(err))
					}
				}
				if len(rs1.EnterprisePublicKey) > 0 {
					if authContext.enterpriseRsaPublicKey, err = api.LoadRsaPublicKey(rs1.EnterprisePublicKey); err != nil {
						logger.Warn("Parse Enterprise RSA public key error", zap.Error(err))
					}
				}
			}
		}
	}
	return nil
}

func (la *loginAuth) storeConfiguration() (err error) {
	var config auth.IKeeperConfiguration
	if config, err = la.endpoint.ConfigurationStorage().Get(); err != nil {
		return
	}
	config.SetLastLogin(la.loginContext.Username)
	config.SetLastServer(la.endpoint.Server())
	var deviceToken = api.Base64UrlEncode(la.loginContext.DeviceToken)
	var iuc = config.Users().Get(la.loginContext.Username)
	var uc *auth.UserConfiguration
	if iuc == nil {
		uc = auth.NewUserConfiguration(la.loginContext.Username)
		uc.SetServer(la.endpoint.Server())
		uc.SetLastDevice(auth.NewUserDeviceConfiguration(deviceToken))
	} else {
		var udc = iuc.LastDevice()
		if udc == nil || udc.DeviceToken() != deviceToken {
			uc = auth.CloneUserConfiguration(iuc)
			uc.SetLastDevice(auth.NewUserDeviceConfiguration(deviceToken))
		}
	}
	if uc != nil {
		config.Users().Put(uc)
	}

	var isc = config.Servers().Get(la.endpoint.Server())
	var cs *auth.ServerConfiguration
	if isc == nil {
		cs = auth.NewServerConfiguration(la.endpoint.Server())
		cs.SetServerKeyId(la.endpoint.ServerKeyId())
	} else {
		if isc.ServerKeyId() != la.endpoint.ServerKeyId() {
			cs = auth.CloneServerConfiguration(isc)
			cs.SetServerKeyId(la.endpoint.ServerKeyId())
		}
	}
	if cs != nil {
		config.Servers().Put(cs)
	}

	var idc = config.Devices().Get(deviceToken)
	var dc *auth.DeviceConfiguration
	if idc == nil {
		var devicePrivateKey = api.UnloadEcPrivateKey(la.loginContext.DevicePrivateKey)
		dc = auth.NewDeviceConfiguration(deviceToken, devicePrivateKey)
	} else {
		dc = auth.CloneDeviceConfiguration(idc)
	}
	if dc != nil {
		var idsc = dc.ServerInfo().Get(la.endpoint.Server())
		var dcs *auth.DeviceServerConfiguration
		if idsc == nil {
			dcs = auth.NewDeviceServerConfiguration(la.endpoint.Server())
		} else {
			dcs = auth.CloneDeviceServerConfiguration(idsc)
		}
		dcs.SetCloneCode(api.Base64UrlEncode(la.loginContext.CloneCode))
		dc.ServerInfo().Put(dcs)
		config.Devices().Put(dc)
	}

	err = la.endpoint.ConfigurationStorage().Put(config)
	return
}

func (la *loginAuth) ensurePushNotifications() {
	if la.pushNotifications != nil {
		return
	}
	var rq = &proto_auth.WssConnectionRequest{
		MessageSessionUid:    la.loginContext.MessageSessionUid,
		EncryptedDeviceToken: la.loginContext.DeviceToken,
		DeviceTimeStamp:      time.Now().UnixMilli(),
	}
	var push auth.IPushEndpoint
	var err error
	if push, err = la.endpoint.ConnectToPushServer(rq); err != nil {
		api.GetLogger().Warn("Connect to push server error", zap.Error(err))
	} else {
		push = &auth.PushEndpoint{}
	}
	la.pushNotifications = push
}

func getSessionTokenScope(sessionTokenType proto_auth.SessionTokenType) auth.SessionRestriction {
	if sessionTokenType == proto_auth.SessionTokenType_ACCOUNT_RECOVERY {
		return auth.SessionRestriction_AccountRecovery
	}
	if sessionTokenType == proto_auth.SessionTokenType_SHARE_ACCOUNT {
		return auth.SessionRestriction_ShareAccount
	}
	if sessionTokenType == proto_auth.SessionTokenType_ACCEPT_INVITE {
		return auth.SessionRestriction_AcceptInvite
	}
	if sessionTokenType == proto_auth.SessionTokenType_PURCHASE || sessionTokenType == proto_auth.SessionTokenType_RESTRICT {
		return auth.SessionRestriction_AccountExpired
	}
	return auth.SessionRestriction_Unrestricted
}

func sdkActionToProto(action auth.TwoFactorPushAction) proto_auth.TwoFactorPushType {
	switch action {
	case auth.TwoFactorAction_DuoPush:
		return proto_auth.TwoFactorPushType_TWO_FA_PUSH_DUO_PUSH
	case auth.TwoFactorAction_DuoTextMessage:
		return proto_auth.TwoFactorPushType_TWO_FA_PUSH_DUO_TEXT
	case auth.TwoFactorAction_DuoVoiceCall:
		return proto_auth.TwoFactorPushType_TWO_FA_PUSH_DUO_CALL
	case auth.TwoFactorAction_TextMessage:
		return proto_auth.TwoFactorPushType_TWO_FA_PUSH_SMS
	case auth.TwoFactorAction_KeeperDna:
		return proto_auth.TwoFactorPushType_TWO_FA_PUSH_DNA
	default:
		return proto_auth.TwoFactorPushType_TWO_FA_PUSH_NONE
	}
}

func protoTfaChannelToSdk(channel proto_auth.TwoFactorChannelType) auth.TwoFactorChannel {
	switch channel {
	case proto_auth.TwoFactorChannelType_TWO_FA_CT_TOTP:
		return auth.TwoFactorChannel_Authenticator
	case proto_auth.TwoFactorChannelType_TWO_FA_CT_SMS:
		return auth.TwoFactorChannel_TextMessage
	case proto_auth.TwoFactorChannelType_TWO_FA_CT_DUO:
		return auth.TwoFactorChannel_DuoSecurity
	case proto_auth.TwoFactorChannelType_TWO_FA_CT_RSA:
		return auth.TwoFactorChannel_RSASecurID
	case proto_auth.TwoFactorChannelType_TWO_FA_CT_DNA:
		return auth.TwoFactorChannel_KeeperDNA
	case proto_auth.TwoFactorChannelType_TWO_FA_CT_WEBAUTHN:
		return auth.TwoFactorChannel_SecurityKey
	case proto_auth.TwoFactorChannelType_TWO_FA_CT_BACKUP:
		return auth.TwoFactorChannel_Backup
	default:
		return auth.TwoFactorChannel_Other
	}
}

func sdkTfaChannelToProto(channel auth.TwoFactorChannel) proto_auth.TwoFactorChannelType {
	switch channel {
	case auth.TwoFactorChannel_Authenticator:
		return proto_auth.TwoFactorChannelType_TWO_FA_CT_TOTP
	case auth.TwoFactorChannel_TextMessage:
		return proto_auth.TwoFactorChannelType_TWO_FA_CT_SMS
	case auth.TwoFactorChannel_DuoSecurity:
		return proto_auth.TwoFactorChannelType_TWO_FA_CT_DUO
	case auth.TwoFactorChannel_RSASecurID:
		return proto_auth.TwoFactorChannelType_TWO_FA_CT_RSA
	case auth.TwoFactorChannel_KeeperDNA:
		return proto_auth.TwoFactorChannelType_TWO_FA_CT_DNA
	case auth.TwoFactorChannel_SecurityKey:
		return proto_auth.TwoFactorChannelType_TWO_FA_CT_U2F
	default:
		return proto_auth.TwoFactorChannelType_TWO_FA_CT_NONE
	}
}

func sdkTfaDurationToProto(duration auth.TwoFactorDuration) proto_auth.TwoFactorExpiration {
	switch duration {
	case auth.TwoFactorDuration_EveryLogin:
		return proto_auth.TwoFactorExpiration_TWO_FA_EXP_IMMEDIATELY
	case auth.TwoFactorDuration_Every12Hour:
		return proto_auth.TwoFactorExpiration_TWO_FA_EXP_12_HOURS
	case auth.TwoFactorDuration_EveryDay:
		return proto_auth.TwoFactorExpiration_TWO_FA_EXP_24_HOURS
	case auth.TwoFactorDuration_Every30Days:
		return proto_auth.TwoFactorExpiration_TWO_FA_EXP_30_DAYS
	case auth.TwoFactorDuration_Forever:
		return proto_auth.TwoFactorExpiration_TWO_FA_EXP_NEVER
	}
	return proto_auth.TwoFactorExpiration_TWO_FA_EXP_IMMEDIATELY
}
func protoTfaDurationToSdk(duration proto_auth.TwoFactorExpiration) auth.TwoFactorDuration {
	switch duration {
	case proto_auth.TwoFactorExpiration_TWO_FA_EXP_IMMEDIATELY:
		return auth.TwoFactorDuration_EveryLogin
	case proto_auth.TwoFactorExpiration_TWO_FA_EXP_12_HOURS:
		return auth.TwoFactorDuration_Every12Hour
	case proto_auth.TwoFactorExpiration_TWO_FA_EXP_24_HOURS:
		return auth.TwoFactorDuration_EveryDay
	case proto_auth.TwoFactorExpiration_TWO_FA_EXP_30_DAYS:
		return auth.TwoFactorDuration_Every30Days
	case proto_auth.TwoFactorExpiration_TWO_FA_EXP_NEVER:
		return auth.TwoFactorDuration_Forever
	}
	return auth.TwoFactorDuration_EveryLogin
}

func sdkTfaChannelToProtoTfaValue(channel auth.TwoFactorChannel) proto_auth.TwoFactorValueType {
	switch channel {
	case auth.TwoFactorChannel_Authenticator:
		return proto_auth.TwoFactorValueType_TWO_FA_CODE_TOTP
	case auth.TwoFactorChannel_DuoSecurity:
		return proto_auth.TwoFactorValueType_TWO_FA_CODE_DUO
	case auth.TwoFactorChannel_TextMessage:
		return proto_auth.TwoFactorValueType_TWO_FA_CODE_SMS
	case auth.TwoFactorChannel_RSASecurID:
		return proto_auth.TwoFactorValueType_TWO_FA_CODE_RSA
	case auth.TwoFactorChannel_SecurityKey:
		return proto_auth.TwoFactorValueType_TWO_FA_RESP_WEBAUTHN
	case auth.TwoFactorChannel_KeeperDNA:
		return proto_auth.TwoFactorValueType_TWO_FA_CODE_DNA
	default:
		return proto_auth.TwoFactorValueType_TWO_FA_CODE_NONE
	}
}
