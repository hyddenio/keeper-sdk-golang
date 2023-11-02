package impl

import (
	"testing"
	"time"

	"gotest.tools/assert"
	auth2 "keepersecurity.com/sdk/auth"
)

func TestAuth_LoginSuccessResumeSession(t *testing.T) {
	a, _ := auth2.NewMockAuth(false)

	a.SetResumeSession(true)
	a.Login(auth2.defaultKeeperContext.username)
	assert.Assert(t, a.Step().AuthState() == AuthState_Connected)
	var connStep = a.Step().(IConnectedStep)
	var conn = connStep.KeeperConnection()
	assert.Assert(t, conn != nil)
	settings := a.Storage()
	assert.Assert(t, settings.LastLogin() == auth2.defaultKeeperContext.username)
	userSettings := settings.Users().Get(auth2.defaultKeeperContext.username)
	assert.Assert(t, userSettings != nil)
	assert.Assert(t, userSettings.Username() == auth2.defaultKeeperContext.username)
}

func TestAuth_LoginSuccessRequestPassword(t *testing.T) {
	a, _ := auth2.NewMockAuth(false)

	a.SetResumeSession(false)
	a.Login(auth2.defaultKeeperContext.username)
	assert.Assert(t, a.Step().AuthState() == AuthState_Password)
	var pswdStep IPasswordStep
	var ok bool
	pswdStep, ok = a.Step().(IPasswordStep)
	assert.Assert(t, ok, "Incorrect step type")

	var err error
	err = pswdStep.VerifyPassword(auth2.defaultKeeperContext.password)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, a.Step().AuthState() == AuthState_Connected)
	var connStep = a.Step().(IConnectedStep)
	var conn = connStep.KeeperConnection()
	assert.Assert(t, conn != nil)
}

func TestAuth_LoginInvalidPassword(t *testing.T) {
	a, _ := auth2.NewMockAuth(false)

	a.SetResumeSession(false)
	a.Login(auth2.defaultKeeperContext.username)
	assert.Assert(t, a.Step().AuthState() == AuthState_Password)
	var pswdStep IPasswordStep
	var ok bool
	pswdStep, ok = a.Step().(IPasswordStep)
	assert.Assert(t, ok, "Incorrect step type")
	var err = pswdStep.VerifyPassword("invalid password")
	assert.Assert(t, err != nil)
	_, ok = err.(*auth2.KeeperAuthFailed)
	assert.Assert(t, ok, "Invalid error type")
	assert.Assert(t, a.Step().AuthState() == AuthState_Password)
}

func TestAuth_LoginSuccessSupplyPassword(t *testing.T) {
	a, _ := auth2.NewMockAuth(false)

	a.SetResumeSession(false)
	a.Login(auth2.defaultKeeperContext.username, auth2.defaultKeeperContext.password)
	assert.Assert(t, a.Step().AuthState() == AuthState_Connected)
}

func TestAuth_ApproveDeviceByEmailCode(t *testing.T) {
	a, e := auth2.NewMockAuth(true)
	e.NewDevice.Approved = false
	e.NewDevice.TwoFactor = true
	a.Login(auth2.defaultKeeperContext.username)
	assert.Assert(t, a.Step().AuthState() == AuthState_DeviceApproval)
	var approveStep = a.Step().(IDeviceApprovalStep)
	var err = approveStep.SendCode(auth2.DeviceApproval_Email, auth2.defaultKeeperContext.twoFactorCode)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, a.Step().AuthState() == AuthState_Password)
}

type uiCallback struct {
	onNextStep func()
}

func (cb *uiCallback) OnNextStep() {
	if cb.onNextStep != nil {
		cb.onNextStep()
	}
}
func TestAuth_ApproveDeviceByEmailPush(t *testing.T) {
	a, e := auth2.NewMockAuth(true)
	var cb = new(uiCallback)
	a.SetUiCallback(cb)

	e.NewDevice.Approved = false
	e.NewDevice.TwoFactor = true
	a.Login(auth2.defaultKeeperContext.username)
	assert.Assert(t, a.Step().AuthState() == AuthState_DeviceApproval)
	var approveStep = a.Step().(IDeviceApprovalStep)

	var done = make(chan bool, 1)
	cb.onNextStep = func() {
		done <- true
	}
	var err = approveStep.SendPush(auth2.DeviceApproval_Email)
	assert.Assert(t, err == nil, err)

	var result = false
	select {
	case result = <-done:
	case <-time.After(20 * time.Millisecond):
		result = false
	}
	assert.Assert(t, result, "Timeout")

	assert.Assert(t, a.Step().AuthState() == AuthState_Password)
}

func TestAuth_ApproveDeviceByKeeperPush(t *testing.T) {
	a, e := auth2.NewMockAuth(true)
	var cb = new(uiCallback)
	a.SetUiCallback(cb)

	e.NewDevice.Approved = false
	e.NewDevice.TwoFactor = true
	a.Login(auth2.defaultKeeperContext.username)
	assert.Assert(t, a.Step().AuthState() == AuthState_DeviceApproval)
	var approveStep = a.Step().(IDeviceApprovalStep)

	var done = make(chan bool, 1)
	cb.onNextStep = func() {
		done <- true
	}
	var err = approveStep.SendPush(auth2.DeviceApproval_KeeperPush)
	assert.Assert(t, err == nil, err)

	var result = false
	select {
	case result = <-done:
	case <-time.After(20 * time.Millisecond):
		result = false
	}
	assert.Assert(t, result, "Timeout")

	assert.Assert(t, a.Step().AuthState() == AuthState_Password)
}

func TestAuth_ApproveDeviceByTwoFactorCode(t *testing.T) {
	a, e := auth2.NewMockAuth(true)

	e.NewDevice.Approved = false
	e.NewDevice.TwoFactor = true
	a.Login(auth2.defaultKeeperContext.username)
	assert.Assert(t, a.Step().AuthState() == AuthState_DeviceApproval)
	var approveStep = a.Step().(IDeviceApprovalStep)
	var err = approveStep.SendCode(auth2.DeviceApproval_TwoFactorAuth, auth2.defaultKeeperContext.twoFactorCode)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, a.Step().AuthState() == AuthState_Password)
}

func TestAuth_TwoFactorVerification(t *testing.T) {
	a, e := auth2.NewMockAuth(true)

	e.NewDevice.Approved = true
	e.NewDevice.TwoFactor = false
	a.Login(auth2.defaultKeeperContext.username)
	assert.Assert(t, a.Step().AuthState() == AuthState_TwoFactor)
	var tfaStep = a.Step().(ITwoFactorStep)
	var err = tfaStep.SendCode(tfaStep.Channels()[0], auth2.defaultKeeperContext.twoFactorCode)
	assert.Assert(t, err == nil, err)
	assert.Assert(t, a.Step().AuthState() == AuthState_Password)
}

func TestAuth_TwoFactorVerificationFailure(t *testing.T) {
	a, e := auth2.NewMockAuth(true)

	e.NewDevice.Approved = true
	e.NewDevice.TwoFactor = false
	a.Login(auth2.defaultKeeperContext.username)
	assert.Assert(t, a.Step().AuthState() == AuthState_TwoFactor)
	var tfaStep = a.Step().(ITwoFactorStep)
	var err = tfaStep.SendCode(tfaStep.Channels()[0], "wrong code")
	assert.Assert(t, err != nil)
	_ = err.(*auth2.KeeperAuthFailed)
	assert.Assert(t, a.Step().AuthState() == AuthState_TwoFactor)
}

func TestAuth_LoginWithSsoUsername(t *testing.T) {
	a, _ := auth2.NewMockAuth(true)
	a.Login(auth2.defaultKeeperContext.sso_username)
	assert.Assert(t, a.Step().AuthState() == AuthState_SsoToken)
}
