package impl

import (
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"github.com/golang/glog"
	"google.golang.org/protobuf/proto"
	"keepersecurity.com/sdk/auth"
	"keepersecurity.com/sdk/protobuf/authentication"
	"keepersecurity.com/sdk/protobuf/sso_cloud"
)

type authEndpoint struct {
	endpoint     auth.IKeeperEndpoint
	pushEndpoint auth.IPushEndpoint
	uiCallback   auth.IAuthUiCallback
}

func (a *authEndpoint) UiCallback() auth.IAuthUiCallback {
	return a.uiCallback
}
func (a *authEndpoint) SetUiCallback(value auth.IAuthUiCallback) {
	a.uiCallback = value
}

func (a *authEndpoint) ExecuteV2Command(rq interface{}, rs interface{}) (err error) {
	if toCmd, ok := rq.(auth.ToKeeperApiCommand); ok {
		apiRq := toCmd.GetKeeperApiCommand()
		apiRq.ClientVersion = a.endpoint.ClientVersion()
		apiRq.Locale = a.endpoint.Locale()
		if apiRq.Command == "" {
			if cmdName, ok := rq.(auth.ICommand); ok {
				apiRq.Command = cmdName.Command()
			}
		}
	}
	var rqBody []byte
	if rqBody, err = json.Marshal(rq); err == nil {
		var rsBody []byte
		if rsBody, err = a.endpoint.ExecuteRest("vault/execute_v2_command", rqBody, nil); err == nil {
			err = json.Unmarshal(rsBody, rs)
		}
	}
	return
}

func (a *authEndpoint) executeRest(endpoint string, request proto.Message, response proto.Message, sessionToken []byte) (err error) {
	var payload []byte
	if payload, err = proto.Marshal(request); err != nil {
		return
	}
	glog.V(2).Info("Rest Endpoint", endpoint, "Request", request)
	var rsBody []byte
	if rsBody, err = a.endpoint.ExecuteRest(endpoint, payload, sessionToken); err != nil {
		return
	}
	if response != nil && len(rsBody) > 0 {
		if err = proto.Unmarshal(rsBody, response); err == nil {
			glog.V(2).Info("Rest Endpoint", endpoint, "Response", response)
		}
	}
	return
}

func (a *authEndpoint) ExecuteRest(endpoint string, request proto.Message, response proto.Message) (err error) {
	return a.executeRest(endpoint, request, response, nil)
}

type AuthState = int

const (
	AuthState_NotConnected AuthState = iota
	AuthState_DeviceApproval
	AuthState_TwoFactor
	AuthState_Password
	AuthState_SsoToken
	AuthState_SsoDataKey
	AuthState_Connected
	AuthState_Error
)

type IAuthStep interface {
	AuthState() AuthState
	io.Closer
}
type genericAuthStep struct {
	state   AuthState
	onClose func() error
}

func (as *genericAuthStep) AuthState() AuthState {
	return as.state
}
func newGenericAuthStep(state AuthState) IAuthStep {
	return &genericAuthStep{
		state: state,
	}
}
func (g *genericAuthStep) Close() error {
	if g.onClose != nil {
		return g.onClose()
	}
	return nil
}

type ITwoFactorStep interface {
	IAuthStep
	Channels() []auth2.TwoFactorChannel
	Duration() auth2.TwoFactorDuration
	SetDuration(auth2.TwoFactorDuration)
	IsCodeChannel(auth2.TwoFactorChannel) bool
	PushActionsFor(auth2.TwoFactorChannel) []auth2.TwoFactorAction
	PhoneNumberFor(auth2.TwoFactorChannel) string
	SendPush(auth2.TwoFactorChannel, auth2.TwoFactorAction) error
	SendCode(auth2.TwoFactorChannel, string) error
}
type twoFactorStep struct {
	genericAuthStep
	channels   []*authentication.TwoFactorChannelInfo
	duration   authentication.TwoFactorExpiration
	onSendPush func(*authentication.TwoFactorChannelInfo, authentication.TwoFactorPushType) error
	onSendCode func(*authentication.TwoFactorChannelInfo, string) error
}

func newTwoFactorStep(channels []*authentication.TwoFactorChannelInfo) *twoFactorStep {
	return &twoFactorStep{
		genericAuthStep: genericAuthStep{
			state: AuthState_TwoFactor,
		},
		duration: authentication.TwoFactorExpiration_TWO_FA_EXP_IMMEDIATELY,
		channels: channels,
	}
}
func (ts *twoFactorStep) Channels() []auth2.TwoFactorChannel {
	var channels []auth2.TwoFactorChannel
	for _, e := range ts.channels {
		channels = append(channels, auth2.protoTfaChannelToSdk(e.ChannelType))
	}
	return channels
}
func (ts *twoFactorStep) Duration() auth2.TwoFactorDuration {
	return auth2.protoTfaDurationToSdk(ts.duration)
}
func (ts *twoFactorStep) SetDuration(value auth2.TwoFactorDuration) {
	ts.duration = auth2.sdkTfaDurationToProto(value)
}
func (ts *twoFactorStep) IsCodeChannel(channel auth2.TwoFactorChannel) bool {
	switch channel {
	case auth2.TwoFactorChannel_Authenticator:
	case auth2.TwoFactorChannel_TextMessage:
	case auth2.TwoFactorChannel_DuoSecurity:
	case auth2.TwoFactorChannel_RSASecurID:
	case auth2.TwoFactorChannel_KeeperDNA:
		return true
	}
	return false
}
func (ts *twoFactorStep) PushActionsFor(channel auth2.TwoFactorChannel) (actions []auth2.TwoFactorAction) {
	var info = ts.getChannelInfo(channel)
	if info == nil {
		return
	}

	switch info.ChannelType {
	case authentication.TwoFactorChannelType_TWO_FA_CT_SMS:
		actions = append(actions, auth2.TwoFactorAction_TextMessage)
		break
	case authentication.TwoFactorChannelType_TWO_FA_CT_DNA:
		actions = append(actions, auth2.TwoFactorAction_KeeperDna)
		break
	case authentication.TwoFactorChannelType_TWO_FA_CT_DUO:
		for _, c := range info.Capabilities {
			switch c {
			case "push":
				actions = append(actions, auth2.TwoFactorAction_DuoPush)
				break
			case "sms":
				actions = append(actions, auth2.TwoFactorAction_DuoTextMessage)
				break
			case "phone":
				actions = append(actions, auth2.TwoFactorAction_DuoVoiceCall)
				break
			}
		}
		actions = append(actions, auth2.TwoFactorAction_KeeperDna)
		break
	}
	return
}
func (ts *twoFactorStep) PhoneNumberFor(channel auth2.TwoFactorChannel) string {
	var ch = auth2.sdkTfaChannelToProto(channel)
	for _, e := range ts.channels {
		if ch == e.ChannelType {
			return e.PhoneNumber
		}
	}
	return ""
}
func (ts *twoFactorStep) getChannelInfo(channel auth2.TwoFactorChannel) *authentication.TwoFactorChannelInfo {
	var ch = auth2.sdkTfaChannelToProto(channel)
	for _, e := range ts.channels {
		if ch == e.ChannelType {
			return e
		}
	}
	return nil
}
func (ts *twoFactorStep) SendPush(channel auth2.TwoFactorChannel, action auth2.TwoFactorAction) (err error) {
	var info = ts.getChannelInfo(channel)

	if info != nil && ts.onSendPush != nil {
		var protoAction authentication.TwoFactorPushType = authentication.TwoFactorPushType_TWO_FA_PUSH_NONE
		switch action {
		case auth2.TwoFactorAction_TextMessage:
			protoAction = authentication.TwoFactorPushType_TWO_FA_PUSH_SMS
			break
		case auth2.TwoFactorAction_KeeperDna:
			protoAction = authentication.TwoFactorPushType_TWO_FA_PUSH_DNA
			break
		case auth2.TwoFactorAction_DuoPush:
			protoAction = authentication.TwoFactorPushType_TWO_FA_PUSH_DUO_PUSH
			break
		case auth2.TwoFactorAction_DuoTextMessage:
			protoAction = authentication.TwoFactorPushType_TWO_FA_PUSH_DUO_TEXT
			break
		case auth2.TwoFactorAction_DuoVoiceCall:
			protoAction = authentication.TwoFactorPushType_TWO_FA_PUSH_DUO_CALL
			break
		}

		err = ts.onSendPush(info, protoAction)
	}
	return
}
func (ts *twoFactorStep) SendCode(channel auth2.TwoFactorChannel, code string) (err error) {
	var info = ts.getChannelInfo(channel)

	if info != nil && ts.onSendCode != nil {
		err = ts.onSendCode(info, code)
	}
	return
}

type IPasswordStep interface {
	IAuthStep

	VerifyPassword(string) error
	VerifyBiometricKey([]byte) error
}
type passwordStep struct {
	genericAuthStep
	onVerifyPassword func(string) error
	onVerifyBio      func([]byte) error
}

func newPasswordStep() *passwordStep {
	return &passwordStep{
		genericAuthStep: genericAuthStep{
			state: AuthState_Password,
		},
	}
}
func (ps *passwordStep) VerifyPassword(password string) error {
	return ps.onVerifyPassword(password)
}
func (ps *passwordStep) VerifyBiometricKey(bioKey []byte) error {
	return ps.onVerifyBio(bioKey)
}

type ISsoTokenStep interface {
	IAuthStep
	LoginAs() string
	IsSsoProvider() bool
	SsoLoginUrl() string
	IsCloudSso() bool

	SetSsoToken(string) error
	LoginWithPassword()
}
type ssoTokenStep struct {
	genericAuthStep
	loginAs             string
	isSsoProvider       bool
	ssoLoginUrl         string
	isCloudSso          bool
	onSetSsoToken       func(string) error
	onLoginWithPassword func()
}

func newSsoTokenStep(name string, isProvider bool, isCloud bool) *ssoTokenStep {
	return &ssoTokenStep{
		genericAuthStep: genericAuthStep{
			state: AuthState_SsoToken,
		},
		loginAs:       name,
		isSsoProvider: isProvider,
		isCloudSso:    isCloud,
	}
}
func (sts *ssoTokenStep) LoginAs() string {
	return sts.loginAs
}
func (sts *ssoTokenStep) IsSsoProvider() bool {
	return sts.isSsoProvider
}
func (sts *ssoTokenStep) SsoLoginUrl() string {
	return sts.ssoLoginUrl
}
func (sts *ssoTokenStep) IsCloudSso() bool {
	return sts.isCloudSso
}
func (sts *ssoTokenStep) SetSsoToken(token string) error {
	return sts.onSetSsoToken(token)
}
func (sts *ssoTokenStep) LoginWithPassword() {
	sts.onLoginWithPassword()
}

type ISsoDataKeyStep interface {
	IAuthStep
	Channels() []auth2.DataKeyShareChannel
	RequestDataKey(auth2.DataKeyShareChannel) error
}
type ssoDataKeyStep struct {
	genericAuthStep
	channels         []auth2.DataKeyShareChannel
	onRequestDataKey func(auth2.DataKeyShareChannel) error
}

func newSsoDataKeyStep() *ssoDataKeyStep {
	var sso = &ssoDataKeyStep{
		genericAuthStep: genericAuthStep{
			state: AuthState_SsoDataKey,
		},
	}
	sso.channels = append(sso.channels, auth2.DataKeyShare_KeeperPush)
	sso.channels = append(sso.channels, auth2.DataKeyShare_AdminApproval)
	return sso
}
func (dks *ssoDataKeyStep) Channels() []auth2.DataKeyShareChannel {
	return dks.channels
}
func (dks *ssoDataKeyStep) RequestDataKey(channel auth2.DataKeyShareChannel) error {
	return dks.onRequestDataKey(channel)
}

type IErrorStep interface {
	IAuthStep
	Code() string
	Message() string
}
type errorStep struct {
	genericAuthStep
	code    string
	message string
}

func newErrorStep(code string, message string) IErrorStep {
	return &errorStep{
		genericAuthStep: genericAuthStep{
			state: AuthState_Error,
		},
		code:    code,
		message: message,
	}
}
func (e *errorStep) Code() string {
	return e.code
}
func (e *errorStep) Message() string {
	return e.message
}

type IConnectedStep interface {
	IAuthStep
	KeeperConnection() auth2.IKeeperConnection
}
type connectedStep struct {
	genericAuthStep
	keeperConnection auth2.IKeeperConnection
}

func newConnectedStep(keeperConnection auth2.IKeeperConnection) IConnectedStep {
	return &connectedStep{
		genericAuthStep: genericAuthStep{
			state: AuthState_Connected,
		},
		keeperConnection: keeperConnection,
	}
}
func (c *connectedStep) KeeperConnection() auth2.IKeeperConnection {
	return c.keeperConnection
}

type IAuthSync interface {
	auth2.IAuth
	Step() IAuthStep
	Cancel()
}

type authSync struct {
	authEndpoint
	storage           auth2.IConfigurationStorage
	step              IAuthStep
	resumeSession     bool
	alternatePassword bool
	loginContext      *auth2.loginContext
}

func NewAuth(storage auth2.IConfigurationStorage) IAuthSync {
	return NewAuthEndpoint(storage, nil)
}
func NewAuthEndpoint(storage auth2.IConfigurationStorage, endpoint auth2.IKeeperEndpoint) IAuthSync {
	if storage == nil {
		storage = auth2.NewJsonConfigurationFile("config.json")
	}
	if endpoint == nil {
		endpoint = auth2.NewKeeperEndpoint(storage.LastServer(), storage.Servers())
	}

	return &authSync{
		authEndpoint: authEndpoint{
			endpoint:     endpoint,
			pushEndpoint: nil,
		},
		storage: storage,
		step:    newGenericAuthStep(AuthState_NotConnected),
	}
}

func (a *authSync) Endpoint() auth2.IKeeperEndpoint {
	return a.endpoint
}

func (a *authSync) PushNotifications() auth2.IPushEndpoint {
	return a.pushEndpoint
}
func (a *authSync) SetPushNotifications(push auth2.IPushEndpoint) {
	a.pushEndpoint = push
}

func (a *authSync) Storage() auth2.IConfigurationStorage {
	return a.storage
}

func (a *authSync) ResumeSession() bool {
	return a.resumeSession
}
func (a *authSync) SetResumeSession(value bool) {
	a.resumeSession = value
}
func (a *authSync) AlternatePassword() bool {
	return a.alternatePassword
}
func (a *authSync) SetAlternatePassword(value bool) {
	a.alternatePassword = value
}

func (a *authSync) Step() IAuthStep {
	return a.step
}
func (a *authSync) Cancel() {
	var step = newGenericAuthStep(AuthState_NotConnected)
	a.setNextStep(step)
}

func (a *authSync) Login(username string, passwords ...string) {
	if a.step.AuthState() != AuthState_NotConnected {
		a.Cancel()
	}

	a.loginContext = auth2.newLoginContext()
	a.loginContext.username = username
	for _, password := range passwords {
		a.loginContext.passwordQueue.PushBack(password)
	}

	a.startLogin(nil, authentication.LoginMethod_EXISTING_ACCOUNT)
}

func (a *authSync) LoginSso(providerName string) (err error) {
	var providerRq = &authentication.SsoServiceProviderRequest{
		ClientVersion: a.endpoint.ClientVersion(),
		Locale:        a.endpoint.Locale(),
		Name:          providerName,
	}
	var providerRs = &authentication.SsoServiceProviderResponse{}
	if err = a.ExecuteRest("enterprise/get_sso_service_provider", providerRq, providerRs); err != nil {
		var ok bool
		var redirectError *authentication.KeeperRegionRedirect
		if redirectError, ok = err.(*auth2.KeeperRegionRedirect); ok {
			a.endpoint.SetServer(redirectError.regionHost)
			if err = a.ExecuteRest("enterprise/get_sso_service_provider", providerRq, providerRs); err != nil {
				return
			}
		} else {
			return
		}
	}
	if providerRs.Name == "" {
		err = auth2.NewKeeperError(fmt.Sprintf("Provider %s not found", providerName))
		return
	}

	a.loginContext = auth2.newLoginContext()
	a.onSsoRedirect(providerRs.IsCloud, providerRs.Name, true, providerRs.SpUrl, nil)
	return
}

func (a *authSync) setNextStep(step IAuthStep) {
	if a.step != nil {
		a.step.Close()
	}
	a.step = step
	if a.uiCallback != nil {
		var cb auth2.IAuthSyncCallback
		var ok bool
		if cb, ok = a.uiCallback.(auth2.IAuthSyncCallback); ok {
			cb.OnNextStep()
		}
	}
}

type authContext struct {
	username           string
	deviceToken        []byte
	deviceKey          crypto.PrivateKey
	dataKey            []byte
	sessionToken       []byte
	sessionRestriction auth2.SessionRestriction
	clientKey          []byte
	rsaPrivateKey      crypto.PrivateKey
	ecPrivateKey       crypto.PrivateKey
	isEnterpriseAdmin  bool
	license            *auth2.AccountLicense
	settings           *auth2.AccountSettings
	enforcements       map[string]interface{}
	accountAuthType    auth2.AuthType
	ssoLoginInfo       auth2.ISsoLoginInfo
	validateParams     []byte
}

func (ctx *authContext) Username() string {
	return ctx.username
}
func (ctx *authContext) DeviceToken() []byte {
	return ctx.deviceToken
}
func (ctx *authContext) DeviceKey() crypto.PrivateKey {
	return ctx.deviceKey
}
func (ctx *authContext) DataKey() []byte {
	return ctx.dataKey
}
func (ctx *authContext) SessionToken() []byte {
	return ctx.sessionToken
}
func (ctx *authContext) SessionRestriction() auth2.SessionRestriction {
	return ctx.sessionRestriction
}
func (ctx *authContext) ClientKey() []byte {
	return ctx.clientKey
}
func (ctx *authContext) RsaPrivateKey() crypto.PrivateKey {
	return ctx.rsaPrivateKey
}
func (ctx *authContext) EcPrivateKey() crypto.PrivateKey {
	return ctx.ecPrivateKey
}
func (ctx *authContext) IsEnterpriseAdmin() bool {
	return ctx.isEnterpriseAdmin
}
func (ctx *authContext) License() *auth2.AccountLicense {
	return ctx.license
}
func (ctx *authContext) Settings() *auth2.AccountSettings {
	return ctx.settings
}
func (ctx *authContext) Enforcements() map[string]interface{} {
	return ctx.enforcements
}
func (ctx *authContext) AccountAuthType() auth2.AuthType {
	return ctx.accountAuthType
}
func (ctx *authContext) SsoLoginInfo() auth2.ISsoLoginInfo {
	return ctx.ssoLoginInfo
}
func (ctx *authContext) CheckPasswordValid(password string) bool {
	if ctx.validateParams == nil {
		return false
	}
	if rnd, err := auth2.DecryptEncryptionParams(ctx.validateParams, password); err == nil {
		return len(rnd) == 32
	}
	return false
}

type keeperConnection struct {
	authEndpoint
	context *authContext
}

func (k *keeperConnection) Endpoint() auth2.IKeeperEndpoint {
	return k.endpoint
}
func (k *keeperConnection) AuthContext() auth2.IAuthContext {
	return k.context
}
func (k *keeperConnection) Close() error {
	return k.pushEndpoint.Close()
}
func (k *keeperConnection) PushNotifications() auth2.IPushEndpoint {
	return k.pushEndpoint
}
func (k *keeperConnection) ExecuteAuthCommand(rq interface{}, rs interface{}, throwOnError bool) (err error) {
	var authCommand *auth2.AuthorizedCommand = nil
	if tc, ok := rq.(auth2.ToAuthorizedCommand); ok {
		authCommand = tc.GetAuthorizedCommand()
		authCommand.Username = k.context.username
		authCommand.SessionToken = auth2.Base64UrlEncode(k.context.SessionToken())
	}
	if err = k.ExecuteV2Command(rq, rs); err != nil {
		return
	}
	if toRs, ok := rs.(auth2.ToKeeperApiResponse); ok {
		authRs := toRs.GetKeeperApiResponse()
		if !authRs.IsSuccess() && throwOnError {
			err = auth2.NewKeeperApiError(authRs.ResultCode, authRs.Message)
		}
	}
	return
}
func (k *keeperConnection) ExecuteAuthRest(endpoint string, request proto.Message, response proto.Message) error {
	return k.executeRest(endpoint, request, response, k.AuthContext().SessionToken())
}
func (k *keeperConnection) IsAuthenticated() bool {
	return k.context != nil && k.context.sessionToken != nil
}
func (k *keeperConnection) Logout() {
	if k.IsAuthenticated() {
		if k.context.ssoLoginInfo != nil {
			var ssoCb auth2.IAuthSsoCallback
			var ok bool
			if ssoCb, ok = k.uiCallback.(auth2.IAuthSsoCallback); ok {
				var rq = &sso_cloud.SsoCloudRequest{
					ClientVersion: k.endpoint.ClientVersion(),
					Username:      k.AuthContext().Username(),
					Embedded:      true,
					IdpSessionId:  k.context.ssoLoginInfo.IdpSessionId(),
				}
				var transmissionKey = auth2.GenerateAesKey()
				var data []byte
				var err error
				if data, err = proto.Marshal(rq); err == nil {
					var apiRq *authentication.ApiRequest
					if apiRq, err = k.endpoint.PrepareApiRequest(data, transmissionKey, k.context.sessionToken); err == nil {
						if data, err = proto.Marshal(apiRq); err == nil {
							var ssoUrl *url.URL
							if ssoUrl, err = url.Parse(k.context.ssoLoginInfo.SpBaseUrl()); err == nil {
								ssoUrl.Query().Add("payload", auth2.Base64UrlEncode(data))
								ssoCb.SsoLogout(ssoUrl.String())
							}
						}
					}
				}
			}
		}
		k.ExecuteAuthRest("vault/logout_v3", nil, nil)
		k.context.sessionToken = nil
	}
}
