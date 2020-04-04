package mock

import (
	"flag"
	"gotest.tools/assert"
	"keepersecurity.com/sdk"
	"keepersecurity.com/sdk/sqldb"
	"keepersecurity.com/sqlite"
	"testing"
)

const (
	testUsername = "test@keepersecurity.com"
	testServer = "test.keepersecurity.com"
	testTwoFactorToken = "two factor token"
	testDeviceId = "device id"
	testServerKeyId = 4
)

func TestConfigurationtStorage(t *testing.T) {
	_ = flag.Lookup("stderrthreshold").Value.Set("WARNING")
	var err error
	var db sqldb.Database
	db, err = sqlite.OpenSqliteDatabase(":memory:")
	assert.Assert(t, err == nil, err)

	var storage sdk.ISettingsStorage
	storage, err = sqldb.NewSqlSettingsStorageForEnvironment(db, "test")
	assert.Assert(t, err == nil, err)
	settings := storage.GetSettings()
	var sett = sdk.NewSettings(settings)
	sett.SetLastUsername(testUsername)
	sett.SetLastServer(testServer)

	var user = sdk.NewUserSettings(testUsername)
	user.SetTwoFactorToken(testTwoFactorToken)
	sett.MergeUserSettings(user)
	var server = sdk.NewServerSettings(testServer)
	server.SetServerKeyId(testServerKeyId)
	server.SetDeviceId([]byte(testDeviceId))
	sett.MergeServerSettings(server)

	storage.PutSettings(sett)
	settings = storage.GetSettings()
	assert.Assert(t, settings != nil, err)
	assert.Assert(t, settings.LastUsername() == testUsername)
	assert.Assert(t, settings.LastServer() == testServer)
	var u = sdk.GetUserSettings(settings, testUsername)
	assert.Assert(t, u != nil)
	assert.Assert(t, u.Username() == testUsername)
	assert.Assert(t, u.TwoFactorToken() == testTwoFactorToken)

	var s = sdk.GetServerSettings(settings, testServer)
	assert.Assert(t, s != nil)
	assert.Assert(t, s.Server() == testServer)
	assert.Assert(t, s.ServerKeyId() == testServerKeyId)
	assert.Assert(t, string(s.DeviceId()) == testDeviceId)
}


func TestSqliteVaultStorage(t *testing.T) {
	_ = flag.Lookup("stderrthreshold").Value.Set("WARNING")
	var err error
	var db sqldb.Database
	db, err = sqlite.OpenSqliteDatabase("file::memory:?cache=shared")
	assert.Assert(t, err == nil, err)
	var storage sdk.IVaultStorage
	storage, err = sqldb.NewMultitenantStorage(db, testUsername, "TEST")
	assert.Assert(t, err == nil, err)
	storage.Clear()

	var vault sdk.Vault
	vault, _ = NewMockVault(storage)
	_ = vault.SyncDown()
	assert.Assert(t, vault.RecordCount() == 3)
	assert.Assert(t, vault.SharedFolderCount() == 1)
	assert.Assert(t, vault.TeamCount() == 1)
}