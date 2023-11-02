package auth_impl

import (
	"bytes"
	"crypto/ecdh"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"gotest.tools/assert"
	"strings"
	"testing"
)

var (
	userName                      = "user@company.com"
	userPassword                  = "password"
	serverName                    = "company.com"
	deviceToken                   = api.GenerateUid()
	privateKey   *ecdh.PrivateKey = nil
	cloneCode                     = api.GenerateUid()
)

func init() {
	var err error
	privateKey, _, err = api.GenerateEcKey()
	if err != nil {
		panic(err)
	}
}

func createDefaultConfiguration() *auth.KeeperConfiguration {
	config := auth.NewKeeperConfiguration()
	config.SetLastServer(serverName)
	config.SetLastLogin(userName)
	uc := auth.NewUserConfiguration(userName)
	uc.SetPassword(userPassword)
	uc.SetServer(serverName)
	uc.SetLastDevice(auth.NewUserDeviceConfiguration(api.Base64UrlEncode(deviceToken)))
	config.Users().Put(uc)
	sc := auth.NewServerConfiguration(serverName)
	sc.SetServerKeyId(2)
	config.Servers().Put(sc)
	dc := auth.NewDeviceConfiguration(api.Base64UrlEncode(deviceToken), api.UnloadEcPrivateKey(privateKey))
	dsc := auth.NewDeviceServerConfiguration(serverName)
	dsc.SetCloneCode(api.Base64UrlEncode(cloneCode))
	dc.ServerInfo().Put(dsc)
	config.Devices().Put(dc)
	return config
}

func compareConfigurations(t *testing.T, conf1 auth.IKeeperConfiguration, conf2 auth.IKeeperConfiguration) {
	assert.Assert(t, conf1 != nil)
	assert.Assert(t, conf2 != nil)
	assert.Assert(t, strings.Compare(conf1.LastLogin(), conf2.LastLogin()) == 0, "LastLogin")
	assert.Assert(t, strings.Compare(conf1.LastServer(), conf2.LastServer()) == 0, "LastServer")
	var ids = make(map[string]bool)
	conf1.Users().List(func(uc auth.IUserConfiguration) bool {
		ids[uc.Id()] = true
		return true
	})
	var ok bool
	conf2.Users().List(func(uc auth.IUserConfiguration) bool {
		userId := uc.Id()
		_, ok = ids[userId]
		assert.Assert(t, ok, "User "+userId+" is missing")
		delete(ids, userId)
		return true
	})
	assert.Assert(t, len(ids) == 0, "Users do not match")
	conf1.Users().List(func(uc1 auth.IUserConfiguration) bool {
		var uc2 = conf2.Users().Get(uc1.Id())
		assert.Assert(t, uc2 != nil)
		assert.Assert(t, uc1.Username() == uc2.Username())
		assert.Assert(t, uc1.Password() == uc2.Password())
		assert.Assert(t, uc1.Server() == uc2.Server())
		ld1 := uc1.LastDevice()
		ld2 := uc2.LastDevice()
		if ld1 != nil || ld2 != nil {
			assert.Assert(t, ld1 != nil)
			assert.Assert(t, ld2 != nil)
			assert.Assert(t, ld1.DeviceToken() == ld2.DeviceToken())
		}
		return true
	})

	ids = make(map[string]bool)
	conf1.Devices().List(func(dc auth.IDeviceConfiguration) bool {
		ids[dc.Id()] = true
		return true
	})
	conf2.Devices().List(func(dc auth.IDeviceConfiguration) bool {
		deviceId := dc.Id()
		_, ok = ids[deviceId]
		assert.Assert(t, ok, "Device "+deviceId+" is missing")
		delete(ids, deviceId)
		return true
	})
	assert.Assert(t, len(ids) == 0, "Devices do not match")
	conf1.Devices().List(func(dc1 auth.IDeviceConfiguration) bool {
		dc2 := conf2.Devices().Get(dc1.Id())
		assert.Assert(t, dc2 != nil)
		assert.Assert(t, dc1.DeviceToken() == dc2.DeviceToken())
		assert.Assert(t, bytes.Compare(dc1.DeviceKey(), dc2.DeviceKey()) == 0)
		dc1.ServerInfo().List(func(dsc1 auth.IDeviceServerConfiguration) bool {
			dsc2 := dc2.ServerInfo().Get(dsc1.Id())
			assert.Assert(t, dsc2 != nil)
			assert.Assert(t, dsc1.Server() == dsc2.Server())
			assert.Assert(t, dsc1.CloneCode() == dsc2.CloneCode())
			return true
		})
		return true
	})

	ids = make(map[string]bool)
	conf1.Servers().List(func(sc auth.IServerConfiguration) bool {
		ids[sc.Id()] = true
		return true
	})
	conf2.Servers().List(func(sc auth.IServerConfiguration) bool {
		server := sc.Id()
		_, ok = ids[server]
		assert.Assert(t, ok, "Server "+server+" is missing")
		delete(ids, server)
		return true
	})
	assert.Assert(t, len(ids) == 0, "Servers do not match")
	conf1.Servers().List(func(sc1 auth.IServerConfiguration) bool {
		sc2 := conf2.Servers().Get(sc1.Id())
		assert.Assert(t, sc2 != nil)
		assert.Assert(t, sc1.Server() == sc2.Server())
		assert.Assert(t, sc1.ServerKeyId() == sc2.ServerKeyId())
		return true
	})
}

func TestConfigurationCopy(t *testing.T) {
	var config = createDefaultConfiguration()
	var configCopy = auth.CloneKeeperConfiguration(config)
	compareConfigurations(t, config, configCopy)
}

type jsonInMemoryLoader struct {
	data []byte
}

func (jl *jsonInMemoryLoader) LoadJson() (data []byte, err error) {
	return jl.data, nil
}
func (jl *jsonInMemoryLoader) StoreJson(data []byte) (err error) {
	jl.data = data
	return nil
}

func TestJson(t *testing.T) {
	var config = createDefaultConfiguration()
	var loader = &jsonInMemoryLoader{}
	var jsonStorage = NewJsonConfigurationStorage(loader)
	var err = jsonStorage.Put(config)
	assert.NilError(t, err)
	var jc auth.IKeeperConfiguration
	jc, err = jsonStorage.Get()
	assert.NilError(t, err)
	compareConfigurations(t, config, jc)
}
