package auth

import (
  "encoding/json"
  "testing"

  "gotest.tools/assert"
)

type inMemoryJsonStorage struct {
  data []byte
}
func (j *inMemoryJsonStorage) LoadJson() ([]byte, error) {
  return j.data, nil
}
func (j *inMemoryJsonStorage) StoreJson(data []byte) error {
  j.data = data
  return nil
}

const (
  testUsername = "test@company.com"
  testSsoProvider = "SSO Provider"
  testPassword = "password"
  testServer = "mock.keepersecurity.com"
  testServerKeyId = 3
  testDeviceToken = "device token"
)

func TestNewJsonConfiguration(t *testing.T) {
  var jsonLoader = new(inMemoryJsonStorage)
  var jsonStorage = NewJsonConfigurationStorage(jsonLoader)
  jsonStorage.SetLastLogin(testUsername)
  jsonStorage.SetLastServer(testServer)

  var serverConf = NewServerConfiguration(testServer)
  serverConf.ServerKeyId_ = testServerKeyId
  jsonStorage.Servers().Put(serverConf)

  var userConf = NewUserConfiguration(testUsername)
  userConf.Server_ = testServer
  userConf.Password_ = testPassword
  userConf.SsoProvider_ = testSsoProvider
  userConf.LastDevice_ = NewUserDeviceConfiguration(testDeviceToken)
  jsonStorage.Users().Put(userConf)

  jsonStorage.Flush()

  var err error
  var m = make(map[string]interface{})
  err = json.Unmarshal(jsonLoader.data, &m)
  assert.Assert(t, err == nil, err)
  assert.Assert(t, m["last_server"] == testServer)
  assert.Assert(t, m["last_login"] == testUsername)
  var scs, _ = m["servers"].([]interface{})
  assert.Assert(t, scs != nil)
  assert.Assert(t, len(scs) == 1)
  var sc, _ = scs[0].(map[string]interface{})
  assert.Assert(t, sc["server"] == testServer)
  assert.Assert(t, sc["server_key_id"].(float64) == testServerKeyId, sc["server_key_id"], testServerKeyId)

  var ucs, _ = m["users"].([]interface{})
  assert.Assert(t, ucs != nil)
  assert.Assert(t, len(ucs) == 1)
  var uc, _ = ucs[0].(map[string]interface{})
  assert.Assert(t, uc["user"] == testUsername)
  assert.Assert(t, uc["server"] == testServer)
  assert.Assert(t, uc["sso_provider"] == testSsoProvider)


}

