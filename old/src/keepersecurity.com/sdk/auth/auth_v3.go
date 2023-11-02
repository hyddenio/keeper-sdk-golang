package auth

import (
	"container/list"
	"crypto"
	"encoding/json"
	authentication2 "keepersecurity.com/sdk/pkg/authentication"
	"net/url"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"keepersecurity.com/sdk/auth/impl"
	"keepersecurity.com/sdk/protobuf/account_summary"
	"keepersecurity.com/sdk/protobuf/authentication"
	"keepersecurity.com/sdk/protobuf/push"
	"keepersecurity.com/sdk/protobuf/sso_cloud"
)

type loginContext struct {
	username          string
	deviceToken       []byte
	deviceKey         crypto.PrivateKey
	accountAuthType   authentication2.AuthType
	messageSessionUid []byte
	cloneCode         []byte
	passwordQueue     *list.List
	ssoLoginInfo      *ssoLoginInfo
	attempt           int
}

func newLoginContext() *loginContext {
	return &loginContext{
		messageSessionUid: GetRandomBytes(16),
		accountAuthType:   authentication2.AuthType_Regular,
		passwordQueue:     list.New(),
		attempt:           0,
	}
}
func (a *impl.auth) prepareForLogin() (err error) {
	var username string
	username = a.loginContext.username
	var userConfig IUserConfiguration
	userConfig = a.storage.Users().Get(username)
	if userConfig != nil {
		var lastDevice = userConfig.LastDevice()
		if lastDevice != nil && lastDevice.DeviceToken() != "" {
			a.loginContext.deviceToken = Base64UrlDecode(lastDevice.DeviceToken())
		}
		if userConfig.Server() != a.endpoint.Server() {
			a.endpoint.SetServer(userConfig.Server())
		}
	}

	var deviceTokenKey string
	var deviceConfig IDeviceConfiguration
	var deviceToken []byte
	var deviceKey crypto.PrivateKey
	if a.loginContext.deviceToken != nil {
		deviceTokenKey = Base64UrlEncode(a.loginContext.deviceToken)
		var dc = a.storage.Devices().Get(deviceTokenKey)
		if dc != nil && dc.DeviceKey() != nil {
			if deviceKey, err = LoadEcPrivateKey(dc.DeviceKey()); err == nil {
				deviceToken = a.loginContext.deviceToken
			} else {
				a.storage.Devices().Delete(deviceTokenKey)
				err = nil
			}
		}

	}

	for deviceToken == nil {
		deviceConfig = nil
		deviceKey = nil
		a.storage.Devices().List(func(dc IDeviceConfiguration) bool {
			deviceConfig = dc
			return false
		})
		if deviceConfig == nil {
			break
		}
		if deviceConfig.DeviceKey() != nil {
			if deviceKey, err = LoadEcPrivateKey(deviceConfig.DeviceKey()); err == nil {
				deviceToken = Base64UrlDecode(deviceConfig.DeviceToken())
				break
			}
		}

		a.storage.Devices().Delete(deviceConfig.DeviceToken())
	}

	err = nil
	var configModified = false
	if deviceToken == nil || deviceKey == nil {
		if deviceToken, deviceKey, err = a.registerDevice(); err != nil {
			return
		}
		var keyBytes []byte
		if keyBytes, err = UnloadEcPrivateKey(deviceKey); err != nil {
			return
		}
		deviceConfig = NewDeviceConfiguration(Base64UrlEncode(deviceToken), keyBytes)
		deviceConfig.ServerInfo().Put(NewDeviceServerConfiguration(a.endpoint.Server()))
		a.storage.Devices().Put(deviceConfig)
		configModified = true
	}
	deviceTokenKey = Base64UrlEncode(deviceToken)
	deviceConfig = a.storage.Devices().Get(deviceTokenKey)
	if deviceConfig == nil {
		err = NewKeeperError("Unexpected")
		return
	}
	var deviceServerConfig = deviceConfig.ServerInfo().Get(a.endpoint.Server())
	if deviceServerConfig == nil {
		if err = a.registerDeviceInRegion(deviceToken, deviceKey); err != nil {
			return
		}
		deviceConfig.ServerInfo().Put(NewDeviceServerConfiguration(a.endpoint.Server()))
		configModified = true
	}

	if configModified {
		a.storage.Devices().Put(deviceConfig)
	}

	a.loginContext.deviceToken = deviceToken
	a.loginContext.deviceKey = deviceKey
	if deviceServerConfig.CloneCode() != "" {
		a.loginContext.cloneCode = Base64UrlDecode(deviceServerConfig.CloneCode())
	}

	if a.pushEndpoint != nil {
		a.pushEndpoint.Close()
		a.pushEndpoint = nil
	}

	var pushChannel = make(chan bool, 1)
	go func() {
		pushRequest := &push.WssConnectionRequest{
			EncryptedDeviceToken: deviceToken,
			MessageSessionUid:    a.loginContext.messageSessionUid,
			DeviceTimeStamp:      time.Now().Unix() * 1000,
		}
		var ps IPushEndpoint
		var e error
		if ps, e = a.endpoint.ConnectToPushServer(pushRequest); e == nil {
			a.pushEndpoint = ps
		}
		pushChannel <- e == nil
	}()

	select {
	case <-pushChannel:
	case <-time.After(1 * time.Second):
	}

	return
}

func (a *impl.auth) registerDeviceInRegion(deviceToken []byte, deviceKey crypto.PrivateKey) (err error) {
	var publicKey crypto.PublicKey
	if publicKey, err = GetEcPublicKey(deviceKey); err != nil {
		return
	}
	var publicBytes []byte
	if publicBytes, err = UnloadEcPublicKey(publicKey); err != nil {
		return
	}
	request := &authentication.RegisterDeviceInRegionRequest{
		ClientVersion:        a.endpoint.ClientVersion(),
		DeviceName:           a.endpoint.DeviceName(),
		EncryptedDeviceToken: deviceToken,
		DevicePublicKey:      publicBytes,
	}
	if err = a.ExecuteRest("authentication/register_device_in_region", request, nil); err != nil {
		switch e := err.(type) {
		case *KeeperApiError:
			if e.resultCode == "exists" || e.message == "public key already exists" {
				err = nil
			}
			break
		}
	}
	return
}

func (a *impl.auth) registerDevice() (deviceToken []byte, deviceKey crypto.PrivateKey, err error) {
	var publicKey crypto.PublicKey
	if deviceKey, publicKey, err = GenerateEcKey(); err == nil {
		var pk []byte
		if pk, err = UnloadEcPublicKey(publicKey); err == nil {
			request := &authentication.DeviceRegistrationRequest{
				DeviceName:      a.endpoint.DeviceName(),
				ClientVersion:   a.endpoint.ClientVersion(),
				DevicePublicKey: pk,
			}
			var response = new(authentication.Device)
			if err = a.ExecuteRest("authentication/register_device", request, response); err == nil {
				deviceToken = response.EncryptedDeviceToken
			}
		}
	}
	return
}

func (a *impl.auth) startLogin(loginToken []byte, loginMethod authentication.LoginMethod) {
	var err error
	if a.loginContext.deviceToken == nil {
		if err = a.prepareForLogin(); err != nil {
			var es impl.IErrorStep
			switch e := err.(type) {
			case *KeeperApiError:
				es = impl.newErrorStep(e.resultCode, e.message)
				break
			default:
				es = impl.newErrorStep("other", e.Error())
				break
			}
			a.setNextStep(es)
			return
		}
	}

	request := &authentication.StartLoginRequest{
		ClientVersion:        a.endpoint.ClientVersion(),
		EncryptedDeviceToken: a.loginContext.deviceToken,
		MessageSessionUid:    a.loginContext.messageSessionUid,
		LoginMethod:          loginMethod,
	}
	if a.alternatePassword {
		request.LoginType = authentication.LoginType_ALTERNATE
	}
	if loginToken != nil {
		request.EncryptedLoginToken = loginToken
	} else if a.resumeSession && a.loginContext.cloneCode != nil {
		request.CloneCode = a.loginContext.cloneCode
	} else if a.loginContext.username != "" {
		request.Username = a.loginContext.username
	} else {
		a.setNextStep(impl.newErrorStep("requires_username", "username required."))
		return
	}

	response := new(authentication.LoginResponse)

	if err = a.ExecuteRest("authentication/start_login", request, response); err != nil {
		switch e := err.(type) {
		case *KeeperRegionRedirect:
			a.loginContext.attempt++
			a.loginContext.deviceToken = nil
			a.endpoint.SetServer(e.regionHost)
			a.startLogin(loginToken, loginMethod)
			return
		case *KeeperApiError:
			if e.resultCode == "device_not_registered" || e.resultCode == "bad_request" {
				dt := Base64UrlEncode(a.loginContext.deviceToken)
				var deviceConfig = a.storage.Devices().Get(dt)
				if deviceConfig != nil {
					if e.resultCode == "device_not_registered" {
						dsc := CloneDeviceConfiguration(deviceConfig)
						dsc.ServerInfo().Delete(a.endpoint.Server())
						a.storage.Devices().Put(dsc)
					} else {
						a.storage.Devices().Delete(dt)
					}
				}
				if es, ok := a.storage.(IExternalConfigurationStorage); ok {
					es.Flush()
				}
				a.loginContext.attempt++
				a.loginContext.deviceToken = nil
				a.startLogin(loginToken, loginMethod)
			} else {
				var step = impl.newErrorStep(e.resultCode, e.message)
				a.setNextStep(step)
			}
			return
		}
		var step = impl.newErrorStep("other", err.Error())
		a.setNextStep(step)
		return
	}

	switch response.LoginState {
	case authentication.LoginState_LOGGED_IN:
		a.loginContext.cloneCode = response.CloneCode
		a.storeConfigurationIfChanged()
		if response.EncryptedDataKeyType == authentication.EncryptedDataKeyType_BY_DEVICE_PUBLIC_KEY {
			var dk []byte
			if dk, err = DecryptEc(response.EncryptedDataKey, a.loginContext.deviceKey); err == nil {
				a.onConnected(a.loginContext, response, dk)
				return
			}
		}
		var message = "Unsupported data key encryption method"
		if err != nil {
			message = err.Error()
		}
		var step = impl.newErrorStep("data_key_decrypt", message)
		a.setNextStep(step)
		return

	case authentication.LoginState_REQUIRES_USERNAME:
		a.loginContext.cloneCode = nil
		a.resumeSession = false
		a.loginContext.attempt++
		a.startLogin(loginToken, loginMethod)
		return

	case authentication.LoginState_REGION_REDIRECT:
		a.loginContext.attempt++
		a.loginContext.deviceToken = nil
		a.endpoint.SetServer(response.StateSpecificValue)
		a.startLogin(loginToken, loginMethod)
		return

	case authentication.LoginState_DEVICE_ACCOUNT_LOCKED, authentication.LoginState_DEVICE_LOCKED:
		dt := Base64UrlEncode(a.loginContext.deviceToken)
		a.storage.Devices().Delete(dt)
		if es, ok := a.storage.(IExternalConfigurationStorage); ok {
			es.Flush()
		}
		a.loginContext.attempt++
		a.loginContext.deviceToken = nil
		a.startLogin(loginToken, loginMethod)
		return

	case authentication.LoginState_REQUIRES_2FA:
		a.on2FARequired(response)
		return

	case authentication.LoginState_REQUIRES_AUTH_HASH:
		a.onAuthRequired(response)
		return

	case authentication.LoginState_DEVICE_APPROVAL_REQUIRED:
		a.onDeviceApprovalRequired(response)
		return

	case authentication.LoginState_REDIRECT_CLOUD_SSO,
		authentication.LoginState_REDIRECT_ONSITE_SSO:
		var isCloudSso = response.LoginState == authentication.LoginState_REDIRECT_CLOUD_SSO
		a.onSsoRedirect(isCloudSso, a.loginContext.username, false, response.Url, response.EncryptedLoginToken)
		return

	case authentication.LoginState_REQUIRES_DEVICE_ENCRYPTED_DATA_KEY:
		a.onDataKeyRequired(response)
		return
	}

}

func (a *impl.auth) onDataKeyRequired(response *authentication.LoginResponse) {
	var loginToken = response.EncryptedLoginToken
	var ssoStep = impl.newSsoDataKeyStep()
	ssoStep.onRequestDataKey = func(channel authentication2.DataKeyShareChannel) (err error) {
		switch channel {
		case authentication2.DataKeyShare_KeeperPush:
			{
				rq := &authentication.TwoFactorSendPushRequest{
					EncryptedLoginToken: loginToken,
					PushType:            authentication.TwoFactorPushType_TWO_FA_PUSH_KEEPER,
				}
				a.ExecuteRest("authentication/2fa_send_push", rq, nil)
			}
			break
		case authentication2.DataKeyShare_AdminApproval:
			{
				rq := &authentication.DeviceVerificationRequest{
					ClientVersion:        a.endpoint.ClientVersion(),
					Username:             a.loginContext.username,
					EncryptedDeviceToken: a.loginContext.deviceToken,
					MessageSessionUid:    a.loginContext.messageSessionUid,
				}
				rs := &authentication.DeviceVerificationResponse{}
				if err = a.ExecuteRest("authentication/request_device_admin_approval", rq, rs); err != nil {
					return
				}
				if rs.DeviceStatus == authentication.DeviceStatus_DEVICE_OK {
					a.startLogin(loginToken, authentication.LoginMethod_AFTER_SSO)
				}
			}
			break
		}
		return
	}

	var cb = a.createDataKeyNotificationCallback(loginToken)
	ssoStep.onClose = func() error {
		if a.pushEndpoint != nil {
			a.pushEndpoint.RemoveCallback(cb)
		}
		return nil
	}
	if a.pushEndpoint != nil {
		a.pushEndpoint.RegisterCallback(cb)
	}
	a.setNextStep(ssoStep)
}
func (a *impl.auth) createDataKeyNotificationCallback(loginToken []byte) func(*NotificationEvent) bool {
	return func(e *NotificationEvent) bool {
		if (e.Message == "device_approved" && e.Approved) || e.Command == "device_verified" {
			a.startLogin(loginToken, authentication.LoginMethod_AFTER_SSO)
			return true
		}
		return false
	}
}

func (a *impl.auth) onSsoRedirect(isCloudSso bool, name string, isProvider bool, spUrl string, loginToken []byte) {
	var err error

	ssoStep := impl.newSsoTokenStep(name, isProvider, isCloudSso)

	var ssoUrl *url.URL
	if ssoUrl, err = url.Parse(spUrl); err != nil {
		a.setNextStep(impl.newErrorStep("sso_prepare", err.Error()))
		return
	}

	var data []byte
	var query = ssoUrl.Query()
	if isCloudSso {
		rq := &sso_cloud.SsoCloudRequest{
			ClientVersion:     a.endpoint.ClientVersion(),
			MessageSessionUid: a.loginContext.messageSessionUid,
			Embedded:          true,
		}
		if data, err = proto.Marshal(rq); err != nil {
			a.setNextStep(impl.newErrorStep("sso_prepare", err.Error()))
			return
		}
		var transmissionKey = GenerateAesKey()
		var apiRq *authentication.ApiRequest
		if apiRq, err = a.endpoint.PrepareApiRequest(data, transmissionKey, nil); err != nil {
			a.setNextStep(impl.newErrorStep("sso_prepare", err.Error()))
			return
		}
		if data, err = proto.Marshal(apiRq); err != nil {
			a.setNextStep(impl.newErrorStep("sso_prepare", err.Error()))
			return
		}
		query.Add("payload", Base64UrlEncode(data))
		ssoStep.onSetSsoToken = a.prepareCloudSsoAuth(loginToken, transmissionKey, spUrl)
	} else {
		query.Add("embedded", "")
		var privateKey crypto.PrivateKey
		var publicKey crypto.PublicKey
		if privateKey, publicKey, err = GenerateRsaKey(); err != nil {
			a.setNextStep(impl.newErrorStep("sso_prepare", err.Error()))
			return
		}
		if data, err = UnloadRsaPublicKey(publicKey); err != nil {
			a.setNextStep(impl.newErrorStep("sso_prepare", err.Error()))
			return
		}
		query.Add("key", Base64UrlEncode(data))
		ssoStep.onSetSsoToken = a.prepareOnsiteSsoAuth(loginToken, privateKey, spUrl)
	}
	ssoUrl.RawQuery = query.Encode()
	ssoStep.ssoLoginUrl = ssoUrl.String()
	if !isProvider {
		ssoStep.onLoginWithPassword = func() {
			a.alternatePassword = true
			a.Login(a.loginContext.username)
		}
	}
	a.setNextStep(ssoStep)
}

func (a *impl.auth) prepareCloudSsoAuth(loginToken []byte, key []byte, url string) func(string) error {
	return func(token string) (err error) {
		var rsBytes = Base64UrlDecode(token)
		if rsBytes, err = DecryptAesV2(rsBytes, key); err != nil {
			return
		}
		rs := &sso_cloud.SsoCloudResponse{}
		if err = proto.Unmarshal(rsBytes, rs); err != nil {
			return
		}
		a.loginContext.username = rs.Email
		a.prepareForLogin()
		a.loginContext.ssoLoginInfo = &ssoLoginInfo{
			ssoProvider:  rs.ProviderName,
			spBaseUrl:    url,
			idpSessionId: rs.IdpSessionId,
		}
		var tok = loginToken
		if rs.EncryptedLoginToken != nil {
			tok = rs.EncryptedLoginToken
		}
		a.startLogin(tok, authentication.LoginMethod_AFTER_SSO)
		return
	}
}

func (a *impl.auth) prepareOnsiteSsoAuth(loginToken []byte, privateKey crypto.PrivateKey, url string) func(string) error {
	return func(token string) (err error) {
		var ssoToken = &authentication2.SsoToken{}
		if err = json.Unmarshal([]byte(token), ssoToken); err != nil {
			return
		}
		a.loginContext.username = ssoToken.Email
		a.prepareForLogin()
		var password []byte
		if ssoToken.Password != "" {
			if password, err = DecryptRsa(Base64UrlDecode(ssoToken.Password), privateKey); err == nil {
				a.loginContext.passwordQueue.PushBack(string(password))
			}
		}
		if ssoToken.NewPassword != "" {
			if password, err = DecryptRsa(Base64UrlDecode(ssoToken.NewPassword), privateKey); err == nil {
				a.loginContext.passwordQueue.PushBack(string(password))
			}
		}
		a.loginContext.ssoLoginInfo = &ssoLoginInfo{
			ssoProvider:  ssoToken.ProviderName,
			spBaseUrl:    url,
			idpSessionId: ssoToken.SessionId,
		}
		var tok = loginToken
		// TODO
		/*
		   if ssoToken.LoginToken != "" {
		     tok = Base64UrlDecode(ssoToken.LoginToken)
		   }
		*/
		a.startLogin(tok, authentication.LoginMethod_AFTER_SSO)
		return
	}
}

func (a *impl.auth) onDeviceApprovalRequired(response *authentication.LoginResponse) {
	var loginToken = response.EncryptedLoginToken
	var emailSent = false
	var das = impl.newDeviceApprovalStep()
	das.onSendPush = func(channel authentication2.DeviceApprovalChannel) (err error) {
		switch channel {
		case authentication2.DeviceApproval_Email:
			{
				var emailChannel = "email"
				if emailSent {
					emailChannel = "email_resend"
				}
				rq := &authentication.DeviceVerificationRequest{
					ClientVersion:        a.endpoint.ClientVersion(),
					Username:             a.loginContext.username,
					EncryptedDeviceToken: a.loginContext.deviceToken,
					MessageSessionUid:    a.loginContext.messageSessionUid,
					VerificationChannel:  emailChannel,
				}
				err = a.ExecuteRest("authentication/request_device_verification", rq, nil)
			}
			break
		case authentication2.DeviceApproval_TwoFactorAuth, authentication2.DeviceApproval_KeeperPush:
			{
				var pushType = authentication.TwoFactorPushType_TWO_FA_PUSH_KEEPER
				if channel == authentication2.DeviceApproval_TwoFactorAuth {
					pushType = authentication.TwoFactorPushType_TWO_FA_PUSH_NONE
				}
				rq := &authentication.TwoFactorSendPushRequest{
					EncryptedLoginToken: loginToken,
					PushType:            pushType,
					ExpireIn:            das.duration,
				}
				err = a.ExecuteRest("authentication/2fa_send_push", rq, nil)
			}
			break
		}
		return
	}
	das.onSendCode = func(channel authentication2.DeviceApprovalChannel, code string) (err error) {
		switch channel {
		case authentication2.DeviceApproval_Email:
			{
				rq := &authentication.ValidateDeviceVerificationCodeRequest{
					ClientVersion:        a.endpoint.ClientVersion(),
					Username:             a.loginContext.username,
					VerificationCode:     code,
					MessageSessionUid:    a.loginContext.messageSessionUid,
					EncryptedDeviceToken: a.loginContext.deviceToken,
				}
				if err = a.ExecuteRest("authentication/validate_device_verification_code", rq, nil); err == nil {
					a.startLogin(loginToken, authentication.LoginMethod_EXISTING_ACCOUNT)
				}
			}
			break
		case authentication2.DeviceApproval_TwoFactorAuth:
			{
				rq := &authentication.TwoFactorValidateRequest{
					EncryptedLoginToken: loginToken,
					ValueType:           authentication.TwoFactorValueType_TWO_FA_CODE_NONE,
					Value:               code,
					ExpireIn:            das.duration,
				}
				rs := &authentication.TwoFactorValidateResponse{}
				if err = a.ExecuteRest("authentication/2fa_validate", rq, rs); err == nil {
					a.startLogin(rs.EncryptedLoginToken, authentication.LoginMethod_EXISTING_ACCOUNT)
				}
			}
			break
		}
		return
	}
	var cb = a.createDeviceApprovalNotificationCallback(loginToken)
	das.onClose = func() error {
		if a.pushEndpoint != nil {
			a.pushEndpoint.RemoveCallback(cb)
		}
		return nil
	}
	if a.pushEndpoint != nil {
		a.pushEndpoint.RegisterCallback(cb)
	}
	a.setNextStep(das)
}
func (a *impl.auth) createDeviceApprovalNotificationCallback(loginToken []byte) func(*NotificationEvent) bool {
	return func(e *NotificationEvent) bool {
		if e.Event == "received_totp" || (e.Message == "device_approved" && e.Approved) || e.Command == "device_verified" {
			var tok = loginToken
			if e.EncryptedLoginToken != "" {
				tok = Base64UrlDecode(e.EncryptedLoginToken)
			}
			a.startLogin(tok, authentication.LoginMethod_EXISTING_ACCOUNT)
			return true
		}
		return false
	}
}

func (a *impl.auth) onAuthRequired(response *authentication.LoginResponse) {
	var loginToken = response.EncryptedLoginToken
	var salt *authentication.Salt
	if len(response.Salt) > 0 {
		var firstSalt = response.Salt[0]
		var name = "master"
		if a.alternatePassword {
			name = "alternate"
		}
		for _, s := range response.Salt {
			if strings.EqualFold(s.Name, name) {
				salt = s
				break
			}
		}
		if salt == nil {
			salt = firstSalt
		}
	}
	var authStep = impl.newPasswordStep()
	authStep.onVerifyPassword = func(password string) (err error) {
		authResponse := DeriveKeyHashV1(password, salt.Salt, uint32(salt.Iterations))
		rq := &authentication.ValidateAuthHashRequest{
			PasswordMethod:      authentication.PasswordMethod_ENTERED,
			AuthResponse:        authResponse,
			EncryptedLoginToken: loginToken,
		}
		rs := &authentication.LoginResponse{}
		if err = a.ExecuteRest("authentication/validate_auth_hash", rq, rs); err == nil {
			var dk []byte
			if dk, err = DecryptEncryptionParams(rs.EncryptedDataKey, password); err == nil {
				a.onConnected(a.loginContext, rs, dk)
			}
		}
		return
	}
	authStep.onVerifyBio = func(bioKey []byte) (err error) {
		authResponse := CreateBioAuthHash(bioKey)
		rq := &authentication.ValidateAuthHashRequest{
			PasswordMethod:      authentication.PasswordMethod_BIOMETRICS,
			AuthResponse:        authResponse,
			EncryptedLoginToken: loginToken,
		}
		rs := &authentication.LoginResponse{}
		if err = a.ExecuteRest("authentication/validate_auth_hash", rq, rs); err == nil {
			var dk []byte
			if dk, err = DecryptAesV2(response.EncryptedDataKey, bioKey); err == nil {
				a.onConnected(a.loginContext, response, dk)
			}
		}
		return
	}

	for a.loginContext.passwordQueue.Len() > 0 {
		var elem = a.loginContext.passwordQueue.Front()
		a.loginContext.passwordQueue.Remove(elem)
		if password, ok := elem.Value.(string); ok {
			if err := authStep.onVerifyPassword(password); err == nil {
				return
			}
		}
	}

	a.setNextStep(authStep)
}

func (a *impl.auth) on2FARequired(response *authentication.LoginResponse) {
	var loginToken = response.EncryptedLoginToken
	var tfaStep = impl.newTwoFactorStep(response.Channels)
	tfaStep.onSendPush = func(channel *authentication.TwoFactorChannelInfo, push authentication.TwoFactorPushType) (err error) {
		request := &authentication.TwoFactorSendPushRequest{
			EncryptedLoginToken: loginToken,
			PushType:            push,
			ChannelUid:          channel.ChannelUid,
			ExpireIn:            tfaStep.duration,
		}
		err = a.ExecuteRest("authentication/2fa_send_push", request, nil)
		return
	}
	tfaStep.onSendCode = func(channel *authentication.TwoFactorChannelInfo, code string) (err error) {
		valueType := authentication.TwoFactorValueType_TWO_FA_CODE_NONE
		switch channel.ChannelType {
		case authentication.TwoFactorChannelType_TWO_FA_CT_TOTP:
			valueType = authentication.TwoFactorValueType_TWO_FA_CODE_TOTP
			break
		case authentication.TwoFactorChannelType_TWO_FA_CT_SMS:
			valueType = authentication.TwoFactorValueType_TWO_FA_CODE_SMS
			break
		case authentication.TwoFactorChannelType_TWO_FA_CT_DUO:
			valueType = authentication.TwoFactorValueType_TWO_FA_CODE_DUO
			break
		case authentication.TwoFactorChannelType_TWO_FA_CT_DNA:
			valueType = authentication.TwoFactorValueType_TWO_FA_CODE_DNA
			break
		case authentication.TwoFactorChannelType_TWO_FA_CT_RSA:
			valueType = authentication.TwoFactorValueType_TWO_FA_CODE_RSA
			break
		}
		rq := &authentication.TwoFactorValidateRequest{
			EncryptedLoginToken: loginToken,
			ValueType:           valueType,
			Value:               code,
			ChannelUid:          channel.ChannelUid,
			ExpireIn:            tfaStep.duration,
		}
		rs := &authentication.TwoFactorValidateResponse{}
		if err = a.ExecuteRest("authentication/2fa_validate", rq, rs); err == nil {
			a.startLogin(rs.EncryptedLoginToken, authentication.LoginMethod_EXISTING_ACCOUNT)
		}
		return
	}
	var cb = a.createTwoFactorNotificationCallback()
	tfaStep.onClose = func() error {
		if a.pushEndpoint != nil {
			a.pushEndpoint.RemoveCallback(cb)
		}
		return nil
	}
	if a.pushEndpoint != nil {
		a.pushEndpoint.RegisterCallback(cb)
	}
	a.setNextStep(tfaStep)
}
func (a *impl.auth) createTwoFactorNotificationCallback() func(*NotificationEvent) bool {
	return func(e *NotificationEvent) bool {
		if e.Event == "received_totp" {
			if e.EncryptedLoginToken != "" {
				var token = Base64UrlDecode(e.EncryptedLoginToken)
				a.startLogin(token, authentication.LoginMethod_EXISTING_ACCOUNT)
				return true
			}
			if e.Passcode != "" {
				if ts, ok := a.step.(impl.ITwoFactorStep); ok {
					for _, ch := range ts.Channels() {
						if ts.IsCodeChannel(ch) {
							if len(ts.PushActionsFor(ch)) > 0 {
								if ts.SendCode(ch, e.Passcode) == nil {
									return true
								}
							}
						}
					}
				}
			}
		}
		return false
	}
}

func (a *impl.auth) onConnected(loginContext *loginContext, response *authentication.LoginResponse, dataKey []byte) {
	loginContext.username = response.PrimaryUsername
	context := &impl.authContext{
		username:           response.PrimaryUsername,
		deviceToken:        a.loginContext.deviceToken,
		deviceKey:          a.loginContext.deviceKey,
		sessionToken:       response.EncryptedSessionToken,
		sessionRestriction: SessionRestrictionFromResponse(response.SessionTokenType),
		dataKey:            dataKey,
		accountAuthType:    a.loginContext.accountAuthType,
		ssoLoginInfo:       a.loginContext.ssoLoginInfo,
	}

	if response.EncryptedDataKeyType == authentication.EncryptedDataKeyType_BY_PASSWORD {
		context.validateParams = response.EncryptedDataKey
	}
	if a.pushEndpoint != nil {
		a.pushEndpoint.Write(response.EncryptedSessionToken)
	}
	var conn *impl.keeperConnection = &impl.keeperConnection{
		authEndpoint: impl.authEndpoint{
			endpoint:     a.Endpoint(),
			pushEndpoint: a.PushNotifications(),
			uiCallback:   a.uiCallback,
		},
		context: context,
	}

	var summaryRequest = &account_summary.AccountSummaryRequest{
		SummaryVersion: 1,
	}
	var summaryResponse = &account_summary.AccountSummaryElements{}
	var err = conn.ExecuteAuthRest("login/account_summary", summaryRequest, summaryResponse)
	if err != nil {
		a.setNextStep(impl.newErrorStep("account_summary", err.Error()))
		return
	}

	context.isEnterpriseAdmin = summaryResponse.IsEnterpriseAdmin

	// keys
	var data []byte
	if len(summaryResponse.ClientKey) > 0 {
		if data, err = DecryptAesV1(summaryResponse.ClientKey, dataKey); err == nil {
			context.clientKey = data
		} else {
			glog.Warning("Error decrypting client key", err)
		}
	} else {
		// TODO create client key
	}

	var privateKey crypto.PrivateKey
	if summaryResponse.KeysInfo != nil {
		if summaryResponse.KeysInfo.EncryptedPrivateKey != nil {
			if data, err = DecryptAesV1(summaryResponse.KeysInfo.EncryptedPrivateKey, dataKey); err == nil {
				if privateKey, err = LoadRsaPrivateKey(data); err == nil {
					context.rsaPrivateKey = privateKey
				}
			}
			if err != nil {
				glog.Warning("Error decrypting RSA private key", err)
				err = nil
			}
		}
		if summaryResponse.KeysInfo.EncryptedEccPrivateKey != nil {
			if data, err = DecryptAesV2(summaryResponse.KeysInfo.EncryptedEccPrivateKey, dataKey); err == nil {
				if privateKey, err = LoadEcPrivateKey(data); err == nil {
					context.ecPrivateKey = privateKey
				}
			}
			if err != nil {
				glog.Warning("Error decrypting EC private key", err)
				err = nil
			}
		}
	}

	// enforcements
	context.enforcements = make(map[string]interface{})
	for _, e := range summaryResponse.Enforcements.Booleans {
		context.enforcements[e.Key] = e.Value
	}
	for _, e := range summaryResponse.Enforcements.Strings {
		context.enforcements[e.Key] = e.Value
	}
	for _, e := range summaryResponse.Enforcements.Longs {
		context.enforcements[e.Key] = e.Value
	}
	for _, e := range summaryResponse.Enforcements.Jsons {
		var js = make(map[string]interface{})
		if err = json.Unmarshal([]byte(e.Value), js); err == nil {
			context.enforcements[e.Key] = js
		}
	}

	// settings
	context.settings = &AccountSettings{
		PasswordRulesIntro:         summaryResponse.Settings.PasswordRulesIntro,
		Channel:                    summaryResponse.Settings.Channel,
		SsoUser:                    &summaryResponse.Settings.SsoUser,
		MasterPasswordLastModified: &summaryResponse.Settings.MasterPasswordLastModified,
		EmailVerified:              summaryResponse.Settings.EmailVerified,
	}
	for _, r := range summaryResponse.Settings.Rules {
		context.settings.PasswordRules = append(context.settings.PasswordRules, &PasswordRules{
			Match:       r.Match,
			Pattern:     r.Pattern,
			Description: r.Description,
		})
	}
	for _, e := range summaryResponse.Settings.ShareAccountTo {
		context.settings.ShareAccountTo = append(context.settings.ShareAccountTo, &AccountShareTo{
			RoleId:    e.RoleId,
			PublicKey: Base64UrlEncode(e.PublicKey),
		})
	}
	if summaryResponse.Settings.MustPerformAccountShareBy > 0 {
		f := float64(summaryResponse.Settings.MustPerformAccountShareBy)
		context.settings.MustPerformAccountShareBy = &f
	}

	// license
	context.license = &AccountLicense{
		AccountType:                   summaryResponse.License.AccountType,
		ProductTypeId:                 summaryResponse.License.ProductTypeId,
		ProductTypeName:               summaryResponse.License.ProductTypeName,
		ExpirationDate:                summaryResponse.License.ExpirationDate,
		SecondsUntilExpiration:        float64(summaryResponse.License.SecondsUntilExpiration),
		FilePlanType:                  summaryResponse.License.FilePlanType,
		StorageExpirationDate:         summaryResponse.License.StorageExpirationDate,
		SecondsUntilStorageExpiration: float64(summaryResponse.License.SecondsUntilStorageExpiration),
	}

	a.setNextStep(impl.newConnectedStep(conn))
}

func (a *impl.auth) storeConfigurationIfChanged() {
	if !strings.EqualFold(a.loginContext.username, a.storage.LastLogin()) {
		a.storage.SetLastLogin(a.loginContext.username)
	}
	if !strings.EqualFold(a.endpoint.Server(), a.storage.LastServer()) {
		a.storage.SetLastLogin(a.endpoint.Server())
	}
	var serverConf = a.storage.Servers().Get(a.endpoint.Server())
	if serverConf == nil || serverConf.ServerKeyId() != a.endpoint.ServerKeyId() {
		var sc *ServerConfiguration
		if serverConf == nil {
			sc = NewServerConfiguration(a.endpoint.Server())
		} else {
			sc = CloneServerConfiguration(serverConf)
		}
		sc.ServerKeyId_ = a.endpoint.ServerKeyId()
		a.storage.Servers().Put(sc)
	}

	var userConf = a.storage.Users().Get(a.loginContext.username)
	var uc *UserConfiguration
	if userConf == nil {
		uc = NewUserConfiguration(a.loginContext.username)
	} else {
		uc = CloneUserConfiguration(userConf)
	}
	if a.loginContext.ssoLoginInfo != nil {
		uc.SsoProvider_ = a.loginContext.ssoLoginInfo.ssoProvider
	} else {
		uc.SsoProvider_ = ""
	}
	var deviceToken = Base64UrlEncode(a.loginContext.deviceToken)
	uc.LastDevice_ = NewUserDeviceConfiguration(deviceToken)
	a.storage.Users().Put(uc)

	var deviceConf = a.storage.Devices().Get(deviceToken)
	if deviceConf != nil {
		var dc = CloneDeviceConfiguration(deviceConf)
		var dsConf = dc.serverInfo.Get(a.endpoint.Server())
		var dsc *DeviceServerConfiguration
		if dsConf == nil {
			dsc = NewDeviceServerConfiguration(a.endpoint.Server())
		} else {
			dsc = CloneDeviceServerConfiguration(dsConf)
		}
		dsc.CloneCode_ = Base64UrlEncode(a.loginContext.cloneCode)
		dc.serverInfo.Put(dsc)
		a.storage.Devices().Put(dc)
	}
	if ec, ok := a.storage.(IExternalConfigurationStorage); ok {
		ec.Flush()
	}
}

func SessionRestrictionFromResponse(tokenType authentication.SessionTokenType) authentication2.SessionRestriction {
	var result authentication2.SessionRestriction = 0
	if tokenType&authentication.SessionTokenType_ACCOUNT_RECOVERY != 0 {
		result |= authentication2.SessionRestriction_AccountRecovery
	}
	if tokenType&authentication.SessionTokenType_SHARE_ACCOUNT != 0 {
		result |= authentication2.SessionRestriction_ShareAccount
	}
	if tokenType&authentication.SessionTokenType_ACCEPT_INVITE != 0 {
		result |= authentication2.SessionRestriction_AcceptInvite
	}
	if tokenType&authentication.SessionTokenType_PURCHASE != 0 {
		result |= authentication2.SessionRestriction_AccountExpired
	}
	if tokenType&authentication.SessionTokenType_RESTRICT != 0 {
		result |= authentication2.SessionRestriction_AccountExpired
	}
	return result
}
