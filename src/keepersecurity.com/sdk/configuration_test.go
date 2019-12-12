package sdk

import (
	"gotest.tools/assert"
	"testing"
)

func TestPasswordIsNotStored(t *testing.T) {
	storage := NewSettingsStorage(nil)
	sett := storage.GetSettings()
	settings := NewSettings(sett)
	userSett := NewUserSettings("unit-test@keepersecurity.com")
	userSett.password = "password"
	userSett.twoFactorToken = "token"
	settings.MergeUserSettings(userSett)
	user := settings.GetUserSettings("unit-test@keepersecurity.com")
	assert.Assert(t, user != nil)
	assert.Assert(t, user.Password() != "")

	storage.PutSettings(settings)
	sett = storage.GetSettings()
	user = sett.GetUserSettings("unit-test@keepersecurity.com")
	assert.Assert(t, user != nil)
	assert.Assert(t, user.Password() == "")
}
