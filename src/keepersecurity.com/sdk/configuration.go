package sdk

import (
	"encoding/json"
	"github.com/golang/glog"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type IUserSettings interface {
	Username() string
	Password() string
	TwoFactorToken() string
}

type IServerSettings interface {
	Server() string
	DeviceId() []byte
	ServerKeyId() int32
}

type ISettings interface {
	LastUsername() string
	LastServer() string
	Users(func (IUserSettings) bool)
	Servers(func (IServerSettings) bool)
	GetUserSettings(string) IUserSettings
	GetServerSettings(string) IServerSettings
}

type ISettingsStorage interface {
	GetSettings() ISettings
	PutSettings(ISettings)
}

type UserSettings struct {
	username string
	password string
	twoFactorToken string
}

func NewUserSettings(username string) *UserSettings {
	result := new(UserSettings)
	result.username = AdjustUsername(username)
	return result
}

func (user *UserSettings) Username() string {
	return user.username
}

func (user *UserSettings) Password() string {
	return user.password
}

func (user *UserSettings) TwoFactorToken() string {
	return user.twoFactorToken
}

func (user *UserSettings) SetTwoFactorToken(token string) {
	user.twoFactorToken = token
}

type ServerSettings struct {
	server string
	deviceId []byte
	serverKeyId int32
}

func NewServerSettings(server string) *ServerSettings {
	result := new(ServerSettings)
	result.server = AdjustServername(server)
	return result
}

func (server *ServerSettings) Server() string {
	return server.server
}

func (server *ServerSettings) DeviceId() []byte {
	return server.deviceId
}

func (server *ServerSettings) ServerKeyId() int32 {
	return server.serverKeyId
}

func (server *ServerSettings) SetDeviceId(deviceId []byte)  {
	server.deviceId = deviceId
}

func (server *ServerSettings) SetServerKeyId(serverKeyId int32) {
	server.serverKeyId = serverKeyId
}

type Settings struct {
	lastUsername string
	lastServer string
	users []*UserSettings
	servers []*ServerSettings
}
func NewSettings(settings ISettings) *Settings {
	result := new(Settings)
	result.MergeSettings(settings)
	return result
}

func (settings *Settings) MergeSettings(other ISettings) {
	if other != nil {
		settings.lastUsername = other.LastUsername()
		settings.lastServer = other.LastServer()
		other.Users(func(user IUserSettings) bool {
			settings.MergeUserSettings(user)
			return true
		})
		other.Servers(func(server IServerSettings) bool {
			settings.MergeServerSettings(server)
			return true
		})
	}
}

func (settings *Settings) MergeUserSettings(user IUserSettings) {
	if user != nil {
		username := AdjustUsername(user.Username())
		var uc *UserSettings = nil
		if settings.users != nil {
			for _, e := range settings.users {
				if e.username == username {
					uc = e
					break
				}
			}
		} else {
			settings.users = make([]*UserSettings, 0)
		}
		if uc == nil {
			uc = NewUserSettings(user.Username())
		}
		uc.password = user.Password()
		uc.twoFactorToken = user.TwoFactorToken()
		settings.users = append(settings.users, uc)
	}
}

func (settings *Settings) MergeServerSettings(server IServerSettings) {
	if server != nil {
		servername := AdjustServername(server.Server())
		var sc *ServerSettings = nil
		if settings.servers != nil {
			for _, e := range settings.servers {
				if e.server == servername {
					sc = e
					break
				}
			}
		} else {
			settings.servers = make([]*ServerSettings, 0)
		}
		if sc == nil {
			sc = NewServerSettings(servername)
		}
		sc.SetDeviceId(server.DeviceId())
		sc.SetServerKeyId(server.ServerKeyId())
		settings.servers = append(settings.servers, sc)
	}
}

func (settings *Settings) LastUsername() string {
	return settings.lastUsername
}
func (settings *Settings) LastServer() string {
	return settings.lastServer
}
func (settings *Settings) Users(fn func (IUserSettings) bool) {
	if settings.users != nil {
		for _, e := range settings.users {
			if e != nil {
				if !fn(e) {
					break
				}
			}
		}
	}
}
func (settings *Settings) Servers(fn func (IServerSettings) bool) {
	if settings.servers != nil {
		for _, e := range settings.servers {
			if e != nil {
				if !fn(e) {
					break
				}
			}
		}
	}
}

func (settings *Settings) SetLastUsername(lastUsername string)  {
	settings.lastUsername = lastUsername
}
func (settings *Settings) SetLastServer(lastServer string) {
	settings.lastServer = lastServer
}
func (settings *Settings) GetUserSettings(username string) IUserSettings {
	if settings.users != nil {
		username = AdjustUsername(username)
		for _, e := range settings.users {
			if e.username == username {
				return e
			}
		}
	}
	return nil
}
func (settings *Settings) GetServerSettings(server string) IServerSettings {
	if settings.servers != nil {
		for _, e := range settings.servers {
			server = AdjustServername(server)
			if e.server == server {
				return e
			}
		}
	}
	return nil
}

type SettingsStorage struct {
	settings *Settings
}

func NewSettingsStorage(settings ISettings) *SettingsStorage {
	result := new(SettingsStorage)
	result.settings = NewSettings(settings)
	return result
}

func (storage *SettingsStorage) GetSettings() ISettings {
	return NewSettings(storage.settings)
}

func (storage *SettingsStorage) PutSettings(settings ISettings)  {
	storage.settings.lastUsername = settings.LastUsername()
	storage.settings.lastServer = settings.LastServer()
	userCache := make(map[string] *UserSettings)
	for _, e := range storage.settings.users {
		userCache[e.username] = e
	}
	settings.Users(func (us IUserSettings) bool {
		username := AdjustUsername(us.Username())
		userSettings := userCache[username]
		if userSettings == nil {
			userSettings = NewUserSettings(username)
			storage.settings.users = append(storage.settings.users, userSettings)
		}
		userSettings.twoFactorToken = us.TwoFactorToken()
		return true
	})

	serverCache := make(map[string]*ServerSettings)
	for _, e := range storage.settings.servers {
		serverCache[e.server] = e
	}
	settings.Servers(func (ss IServerSettings) bool {
		servername := AdjustServername(ss.Server())
		serverSettings := serverCache[servername]
		if serverSettings == nil {
			serverSettings = NewServerSettings(servername)
			storage.settings.servers = append(storage.settings.servers, serverSettings)
		}
		serverSettings.deviceId = ss.DeviceId()
		serverSettings.serverKeyId = ss.ServerKeyId()
		return true
	})
}

func AdjustUsername(username string) string {
	return strings.ToLower(username)
}

func AdjustServername(servername string) string {
	servername = strings.ToLower(servername)
	uri, err := url.ParseRequestURI(servername)
	if err != nil {
		uri, err = url.ParseRequestURI("https://" + servername)
	}
	if err == nil {
		return uri.Host
	}
	return servername
}

type JsonSettingsStorage struct {
	filename string
}

func NewJsonSettingsStorage(filename string) *JsonSettingsStorage {
	result := new(JsonSettingsStorage)
	info, err := os.Stat(filename)
	if err == nil {
		if !info.IsDir() {
			fullFilePath, err := filepath.Abs(filename)
			if err == nil {
				result.filename = fullFilePath
				return result
			}
		}
	}
	settingsFilePath, err := os.UserHomeDir()
	if err != nil {
		result.filename = filename
		return result
	}
	settingsFilePath = path.Join(settingsFilePath, ".keeper")
	info, err = os.Stat(settingsFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.MkdirAll(settingsFilePath, os.ModePerm)
		}
	}
	result.filename = path.Join(settingsFilePath, filename)
	return result
}
func (storage *JsonSettingsStorage) GetSettings() ISettings {
	result := NewSettings(nil)
	_, err := os.Stat(storage.filename)
	if err == nil {
		jdata, err := ioutil.ReadFile(storage.filename)
		if err == nil {
			var data map[string]interface{}
			err = json.Unmarshal(jdata, &data)
			var s string
			var i int
			var ar []interface{}
			var obj map[string]interface{}
			if err == nil {
				if val, ok := data["last_login"]; ok {
					if s, ok = val.(string); ok {
						result.SetLastUsername(s)
					}
				}
				if val, ok := data["last_server"]; ok {
					if s, ok = val.(string); ok {
						result.SetLastServer(s)
					}
				}
				if val, ok := data["users"]; ok {
					result.users = make([]*UserSettings, 0)
					if ar, ok = val.([]interface{}); ok {
						for _, val := range ar {
							if obj, ok = val.(map[string]interface{}); !ok {
								continue
							}
							if val, ok = obj["user"]; ok {
								if s, ok = val.(string); ok {
									user := NewUserSettings(s)
									result.users = append(result.users, user)
									if val, ok = obj["password"]; ok {
										if s, ok = val.(string); ok {
											user.password = s
										}
									}
									if val, ok = obj["mfa_token"]; ok {
										if s, ok = val.(string); ok {
											user.twoFactorToken = s
										}
									}
								}
							}
						}
					}
				}
				if val, ok := data["servers"]; ok {
					result.servers = make([]*ServerSettings, 0)
					if ar, ok = val.([]interface{}); ok {
						for _, val := range ar {
							if obj, ok = val.(map[string]interface{}); !ok {
								continue
							}
							if val, ok = obj["server"]; ok {
								if s, ok = val.(string); ok {
									server := NewServerSettings(s)
									result.servers = append(result.servers, server)
									if val, ok = obj["device_id"]; ok {
										if s, ok = val.(string); ok {
											server.deviceId = Base64UrlDecode(s)
										}
									}
									if val, ok = obj["server_key_id"]; ok {
										if i, ok = val.(int); ok {
											server.serverKeyId = int32(i)
										} else {
											glog.Warningf("JSON settings. Integer expected. Got %v", val)
										}
									}
								}
							}
						}
					}
				}
			} else {
				glog.Warningf("Cannot parse JSON settings file. Error: %v", err)
			}
		} else {
			glog.Warningf("Cannot read JSON settings file. Error: %v", err)
		}
	}

	return result
}

func (storage *JsonSettingsStorage) PutSettings(settings ISettings) {
	if _, ok := settings.(ISettings); !ok {
		return
	}
	var data map[string]interface{}
	_, err := os.Stat(storage.filename)
	if err == nil {
		jdata, err := ioutil.ReadFile(storage.filename)
		if err == nil {
			err = json.Unmarshal(jdata, &data)
			if err != nil {
				glog.Warningln("Parse JSON Settings error:", err)
			}
		} else {
			glog.Warningln("Read JSON Settings error:", err)
		}
	}
	if data == nil {
		data = make(map[string]interface{})
	}
	var s string
	var val interface{}
	var ok bool
	if s = settings.LastUsername(); s != "" {
		data["last_login"] = s
	}
	if s = settings.LastServer(); s != "" {
		data["last_server"] = s
	}
	var list []map[string]interface{}
	if val, ok = data["users"]; ok {
		if list, ok = val.([]map[string]interface{}); !ok {
			list = make([]map[string]interface{}, 0)
			data["users"] = list
		}
	} else {
		list = make([]map[string]interface{}, 0)
		data["users"] = list
	}
	cache := make(map[string]map[string]interface{})
	for _, val = range list {
		if entry, ok := val.(map[string]interface{}); ok {
			if val, ok = entry["user"]; ok {
				if s, ok = val.(string); ok {
					cache[AdjustUsername(s)] = entry
				}
			}
		}
	}
	settings.Users(func (user IUserSettings) bool {
		if _, ok := user.(IUserSettings); ok {
			s := AdjustUsername(user.Username())
			var entry map[string]interface{}
			if entry, ok = cache[s]; !ok {
				entry = make( map[string]interface{})
				entry["user"] = s
				cache[s] = entry
				list = append(list, entry)
			}
			if s = user.TwoFactorToken(); s != "" {
				entry["mfa_token"] = s
			}
		}
		return true
	})

	if val, ok = data["servers"]; ok {
		if list, ok = val.([]map[string]interface{}); !ok {
			list = make([]map[string]interface{}, 0)
			data["servers"] = list
		}
	} else {
		list = make([]map[string]interface{}, 0)
		data["servers"] = list
	}
	cache = make(map[string]map[string]interface{})
	for _, val = range list {
		if entry, ok := val.(map[string]interface{}); ok {
			if val, ok = entry["server"]; ok {
				if s, ok = val.(string); ok {
					cache[AdjustServername(s)] = entry
				}
			}
		}
	}
	settings.Servers(func (server IServerSettings) bool {
		if _, ok := server.(IServerSettings); ok {
			s := AdjustServername(server.Server())
			var entry map[string]interface{}
			if entry, ok = cache[s]; !ok {
				entry = make( map[string]interface{})
				entry["server"] = s
				cache[s] = entry
				list = append(list, entry)
			}
			if b := server.DeviceId(); b != nil {
				entry["device_id"] = Base64UrlEncode(b)
			}
			entry["server_key_id"] = server.ServerKeyId()
		}
		return true
	})

	jdata, err := json.MarshalIndent(data, "", "  ")
	if err == nil {
		err = ioutil.WriteFile(storage.filename, jdata, 0644)
		if err != nil {
			glog.Warningln("Write JSON settings to file error.", err)
		}
	} else {
		glog.Warningln("Dump JSON settings error.", err)
	}
}
