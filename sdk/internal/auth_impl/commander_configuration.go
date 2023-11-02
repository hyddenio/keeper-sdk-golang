package auth_impl

import (
	"crypto/ecdh"
	"encoding/json"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/auth"
	"os"
)

var (
	_ auth.IConfigurationStorage = &commanderConfiguration{}
)

type commanderConfiguration struct {
	filePath string
}

func getAsString(m map[string]interface{}, key string) (s string) {
	var ok bool
	var intf interface{}
	if intf, ok = m[key]; ok {
		s, ok = intf.(string)
	}
	return
}
func (cc *commanderConfiguration) Get() (conf auth.IKeeperConfiguration, err error) {
	var data []byte
	if _, err = os.Stat(cc.filePath); err == nil {
		if data, err = os.ReadFile(cc.filePath); err == nil {
			var m map[string]interface{}
			if err = json.Unmarshal(data, &m); err == nil {
				conf = auth.NewKeeperConfiguration()
				var server = getAsString(m, "server")
				var deviceToken = getAsString(m, "device_token")
				if len(deviceToken) > 0 {
					var pk = getAsString(m, "private_key")
					if len(pk) > 0 {
						var pri *ecdh.PrivateKey
						if pri, err = api.LoadEcPrivateKey(api.Base64UrlDecode(pk)); err != nil {
							return
						}
						var dc = auth.NewDeviceConfiguration(deviceToken, api.UnloadEcPrivateKey(pri))
						if len(server) > 0 {
							var dsc = auth.NewDeviceServerConfiguration(server)
							dsc.SetCloneCode(getAsString(m, "clone_code"))
							dc.ServerInfo().Put(dsc)
						}
						conf.Devices().Put(dc)
					}
				}
				if len(server) > 0 {
					conf.SetLastServer(server)
					var sc = auth.NewServerConfiguration(server)
					conf.Servers().Put(sc)
				}
				var user = getAsString(m, "user")
				if len(user) > 0 {
					conf.SetLastLogin(user)
					var uc = auth.NewUserConfiguration(user)
					if len(deviceToken) > 0 {
						var udc = auth.NewUserDeviceConfiguration(deviceToken)
						uc.SetLastDevice(udc)
					}
					conf.Users().Put(uc)
				}
			}
		}
	}
	return
}

func (cc *commanderConfiguration) Put(conf auth.IKeeperConfiguration) (err error) {
	var m = make(map[string]interface{})
	var data []byte
	if _, err = os.Stat(cc.filePath); err == nil {
		if data, err = os.ReadFile(cc.filePath); err == nil {
			_ = json.Unmarshal(data, &m)
		}
	}
	var user = conf.LastLogin()
	var server = conf.LastServer()
	if len(server) > 0 {
		m["server"] = server
	}
	if len(user) > 0 {
		m["user"] = user
		var uc = conf.Users().Get(user)
		if uc != nil {
			var ld = uc.LastDevice()
			if ld != nil {
				var deviceToken = ld.DeviceToken()
				if len(deviceToken) > 0 {
					var dc = conf.Devices().Get(deviceToken)
					if dc != nil {
						m["device_token"] = dc.DeviceToken()
						var priv = dc.DeviceKey()
						if len(priv) > 0 {
							m["private_key"] = api.Base64UrlEncode(priv)
						}
						if len(server) > 0 {
							var si = dc.ServerInfo().Get(server)
							if si != nil {
								m["clone_code"] = si.CloneCode()
							}
						}
					}
				}
			}
		}
	}
	if data, err = json.MarshalIndent(m, "", "  "); err == nil {
		err = os.WriteFile(cc.filePath, data, 0755)
	}
	return
}

func NewCommanderConfiguration(filename string) auth.IConfigurationStorage {
	if filename == "" {
		filename = "config.json"
	}
	return &commanderConfiguration{
		filePath: api.GetKeeperFileFullPath(filename),
	}
}
