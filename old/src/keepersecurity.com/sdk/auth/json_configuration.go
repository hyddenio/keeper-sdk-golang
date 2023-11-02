package auth

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"
)

type IJsonConfigurationLoader interface {
	LoadJson() ([]byte, error)
	StoreJson([]byte) error
}

type deviceServer struct {
	Server_    string `json:"server"`
	CloneCode_ string `json:"clone_code"`
}

func (ds *deviceServer) Id() string {
	return strings.ToLower(ds.Server_)
}
func (ds *deviceServer) Server() string {
	return ds.Server_
}
func (ds *deviceServer) CloneCode() string {
	return ds.CloneCode_
}

type device struct {
	DeviceToken_ string          `json:"device_token"`
	PrivateKey_  string          `json:"private_key"`
	ServerInfo_  []*deviceServer `json:"server_info"`
	Secured_     *bool           `json:"secured"`
	serverInfo   *deviceServerCollectionWrapper
}

func (d *device) Id() string {
	return strings.ToLower(d.DeviceToken_)
}
func (d *device) DeviceKey() []byte {
	if len(d.PrivateKey_) == 0 {
		return nil
	}
	return Base64UrlDecode(d.PrivateKey_)
}

type server struct {
	Server_      string `json:"server"`
	ServerKeyID_ int32  `json:"server_key_id"`
}

func (s *server) Id() string {
	return strings.ToLower(s.Server_)
}
func (s *server) Server() string {
	return s.Server_
}
func (s *server) ServerKeyId() int32 {
	return s.ServerKeyID_
}

type userDevice struct {
	DeviceToken_ string `json:"device_token"`
}

func (ud *userDevice) DeviceToken() string {
	return ud.DeviceToken_
}

type user struct {
	User_         string      `json:"user"`
	UserPassword_ string      `json:"password"`
	Server_       string      `json:"server"`
	SsoProvider_  string      `json:"sso_provider"`
	LastDevice_   *userDevice `json:"last_device"`
	Secured_      *bool       `json:"secured"`
}

func (u *user) Id() string {
	return strings.ToLower(u.User_)
}
func (u *user) Username() string {
	return u.User_
}
func (u *user) Password() string {
	return u.UserPassword_
}
func (u *user) Server() string {
	return u.Server_
}
func (u *user) SsoProvider() string {
	return u.SsoProvider_
}
func (u *user) LastDevice() IUserDeviceConfiguration {
	return u.LastDevice_
}

type jsonConfiguration struct {
	LastLogin_  string    `json:"last_login"`
	LastServer_ string    `json:"last_server"`
	Devices_    []*device `json:"devices"`
	Servers_    []*server `json:"servers"`
	Users_      []*user   `json:"users"`
	Security_   string    `json:"security"`
}

type jsonConfigurationFileLoader struct {
	filePath string
}

func getFileFullPath(filename string) string {
	var fileFullPath string

	info, err := os.Stat(filename)
	if err == nil {
		if !info.IsDir() {
			if fileFullPath, err = filepath.Abs(filename); err == nil {
				return fileFullPath
			}
		}
	}
	if path.IsAbs(filename) {
		return filename
	}

	if fileFullPath, err = os.UserHomeDir(); err != nil {
		glog.Warningln("JSON Configuration file loader: User folder: ", err)
		return filename
	}

	fileFullPath = path.Join(fileFullPath, ".keeper")
	if info, err = os.Stat(fileFullPath); err != nil {
		if os.IsNotExist(err) {
			if err = os.MkdirAll(fileFullPath, os.ModePerm); err != nil {
				glog.Warningln("JSON Configuration file loader: Create Keeper folder: ", err)
			}
		}
	}
	fileFullPath = path.Join(fileFullPath, filename)
	return fileFullPath
}

func NewJsonConfigurationFileLoader(filename string) IJsonConfigurationLoader {
	if filename == "" {
		filename = "config.json"
	}
	return &jsonConfigurationFileLoader{
		filePath: getFileFullPath(filename),
	}
}
func (fl *jsonConfigurationFileLoader) LoadJson() (data []byte, err error) {
	if _, err = os.Stat(fl.filePath); err == nil {
		data, err = ioutil.ReadFile(fl.filePath)
	}
	return
}

func (fl *jsonConfigurationFileLoader) StoreJson(data []byte) (err error) {
	if err = ioutil.WriteFile(fl.filePath, data, 0755); err != nil {
		glog.Warningln("Write JSON configuration to file error.", err)
	}
	return
}

type jsonConfigurationStorage struct {
	configuration *jsonConfiguration
	loader        IJsonConfigurationLoader

	users   *userCollectionWrapper
	servers *serverCollectionWrapper
	devices *deviceCollectionWrapper

	configurationProtection IConfigurationProtectionFactory

	readTimeoutMillis  int
	writeTimeoutMillis int
	lastAccess         int64
	saveAfter          int64
}

func NewJsonConfigurationStorage(loader IJsonConfigurationLoader) IExternalConfigurationStorage {
	return &jsonConfigurationStorage{
		loader:             loader,
		readTimeoutMillis:  10000,
		writeTimeoutMillis: 2000,
	}
}
func NewJsonConfigurationFile(filePath string) IConfigurationStorage {
	return NewJsonConfigurationStorage(NewJsonConfigurationFileLoader(filePath))
}

func (j *jsonConfigurationStorage) getConfiguration() *jsonConfiguration {
	var now = time.Now().Unix()
	if j.saveAfter == 0 && now-j.lastAccess > int64(j.readTimeoutMillis) {
		j.configuration = nil
	}
	if j.configuration == nil {
		var config = &jsonConfiguration{}
		var err error
		var data []byte
		if data, err = j.loader.LoadJson(); data != nil && err == nil {
			if err = json.Unmarshal(data, config); err == nil {
				if config.Security_ != "" && j.configurationProtection != nil {
					var protection = j.configurationProtection.Resolve(config.Security_)
					if protection != nil {
						var decrypted string
						for _, u := range config.Users_ {
							if u.Secured_ == nil || !*u.Secured_ {
								continue
							}
							if u.UserPassword_ != "" {
								if decrypted, err = protection.Clarify(u.UserPassword_); err == nil {
									u.UserPassword_ = decrypted
								} else {
									glog.Warningln("JSON configuration decryption error.", err)
								}
							}
						}
						for _, d := range config.Devices_ {
							if d.Secured_ == nil || !*d.Secured_ {
								continue
							}
							if d.PrivateKey_ != "" {
								if decrypted, err = protection.Clarify(d.PrivateKey_); err == nil {
									d.PrivateKey_ = decrypted
								} else {
									glog.Warningln("JSON configuration decryption error.", err)
								}
							}
							for _, s := range d.ServerInfo_ {
								if s.CloneCode_ != "" {
									if decrypted, err = protection.Clarify(s.CloneCode_); err == nil {
										s.CloneCode_ = decrypted
									} else {
										glog.Warningln("JSON configuration decryption error.", err)
									}
								}
							}
						}
					}
				}
			} else {
				glog.Warningln("JSON configuration parse error.", err)
			}
		}

		j.configuration = config
	}
	j.lastAccess = now
	return j.configuration
}

func (j *jsonConfigurationStorage) modified() {
	var now = time.Now().Unix()
	j.lastAccess = now
	if j.saveAfter == 0 {
		j.saveAfter = now + int64(j.writeTimeoutMillis) - 100
		go func() {
			time.Sleep(time.Duration(j.writeTimeoutMillis) * time.Millisecond)
			var after = time.Now().Unix()
			if j.saveAfter != 0 && after > j.saveAfter {
				j.Flush()
			}
		}()
	} else if j.saveAfter < now {
		j.Flush()
	}
}

func (j *jsonConfigurationStorage) SecurityAlgorithm() string {
	conf := j.getConfiguration()
	return conf.Security_
}
func (j *jsonConfigurationStorage) SetSecurityAlgorithm(algorithm string) {
	conf := j.getConfiguration()
	conf.Security_ = algorithm
	j.modified()
}

func (j *jsonConfigurationStorage) ConfigurationProtection() IConfigurationProtectionFactory {
	return j.configurationProtection
}
func (j *jsonConfigurationStorage) SetConfigurationProtection(protection IConfigurationProtectionFactory) {
	j.configurationProtection = protection
}

func (j *jsonConfigurationStorage) Flush() {
	if j.configuration != nil {
		var err error
		var data []byte
		if data, err = json.Marshal(j.configuration); err == nil {
			clone := new(jsonConfiguration)
			if err = json.Unmarshal(data, clone); err == nil {
				var protection IConfigurationProtection = nil
				if clone.Security_ != "" && j.configurationProtection != nil {
					protection = j.configurationProtection.Resolve(clone.Security_)
				}
				var t = true
				var encrypted string
				for _, u := range clone.Users_ {
					u.Secured_ = nil
					if protection != nil && u.UserPassword_ != "" {
						if encrypted, err = protection.Obscure(u.UserPassword_); err == nil {
							u.Secured_ = &t
							u.UserPassword_ = encrypted
						}
					}
				}
				for _, d := range clone.Devices_ {
					d.Secured_ = nil
					if protection != nil {
						d.Secured_ = &t
						if encrypted, err = protection.Obscure(d.PrivateKey_); err == nil {
							d.PrivateKey_ = encrypted
						}
						for _, s := range d.ServerInfo_ {
							if encrypted, err = protection.Obscure(s.CloneCode_); err == nil {
								s.CloneCode_ = encrypted
							}
						}
					}
				}
				if data, err = json.Marshal(clone); err == nil {
					if err = j.loader.StoreJson(data); err == nil {
						j.saveAfter = 0
					}
				}
			}
		}
		if err != nil {
			glog.Warningln("JSON configuration Flush error.", err)
		}
	}
}

func (j *jsonConfigurationStorage) LastLogin() string {
	conf := j.getConfiguration()
	return conf.LastLogin_
}
func (j *jsonConfigurationStorage) SetLastLogin(lastLogin string) {
	conf := j.getConfiguration()
	conf.LastLogin_ = lastLogin
	j.modified()
}
func (j *jsonConfigurationStorage) LastServer() string {
	conf := j.getConfiguration()
	return conf.LastServer_
}
func (j *jsonConfigurationStorage) SetLastServer(lastServer string) {
	conf := j.getConfiguration()
	conf.LastServer_ = lastServer
	j.modified()
}

func (j *jsonConfigurationStorage) Users() IUserCollection {
	if j.users == nil {
		j.users = &userCollectionWrapper{
			sliceCollectionWrapper{
				onGet: func() []IConfigurationId {
					elems := j.getConfiguration().Users_
					s := make([]IConfigurationId, len(elems))
					for i, e := range elems {
						s[i] = e
					}
					return s
				},
				onSet: func(elems []IConfigurationId) {
					s := make([]*user, 0, len(elems))
					for i := 0; i < len(elems); i++ {
						if u, ok := elems[i].(*user); ok {
							s = append(s, u)
						}
					}
					j.getConfiguration().Users_ = s
				},
				onModified: j.modified,
				onClone: func(current IConfigurationId, elem IConfigurationId) IConfigurationId {
					var uc IUserConfiguration
					var ok bool
					if uc, ok = elem.(IUserConfiguration); !ok {
						return nil
					}

					var u *user
					if current != nil {
						u, _ = current.(*user)
					}
					if u == nil {
						u = &user{
							User_: elem.Id(),
						}
					}
					u.Server_ = uc.Server()
					u.SsoProvider_ = uc.SsoProvider()
					var ld IUserDeviceConfiguration = uc.LastDevice()
					if ld != nil {
						u.LastDevice_ = &userDevice{
							DeviceToken_: ld.DeviceToken(),
						}
					}
					return u
				},
			},
		}
	}
	return j.users
}

type userCollectionWrapper struct {
	sliceCollectionWrapper
}

func (u *userCollectionWrapper) Get(id string) (user IUserConfiguration) {
	var idConf = u.get(strings.ToLower(id))
	if idConf == nil {
		return nil
	}
	user, _ = idConf.(IUserConfiguration)
	return
}
func (u *userCollectionWrapper) Put(elem IUserConfiguration) {
	u.put(elem)
}
func (u *userCollectionWrapper) Delete(id string) {
	u.delete(strings.ToLower(id))
}
func (u *userCollectionWrapper) List(cb func(IUserConfiguration) bool) {
	u.list(func(idc IConfigurationId) bool {
		return cb(idc.(IUserConfiguration))
	})
}

func (j *jsonConfigurationStorage) Servers() IServerCollection {
	if j.servers == nil {
		j.servers = &serverCollectionWrapper{
			sliceCollectionWrapper{
				onGet: func() []IConfigurationId {
					elems := j.getConfiguration().Servers_
					s := make([]IConfigurationId, len(elems))
					for i, e := range elems {
						s[i] = e
					}
					return s
				},
				onSet: func(elems []IConfigurationId) {
					s := make([]*server, 0, len(elems))
					for i := 0; i < len(elems); i++ {
						if e, ok := elems[i].(*server); ok {
							s = append(s, e)
						}
					}
					j.getConfiguration().Servers_ = s
				},
				onModified: j.modified,
				onClone: func(current IConfigurationId, elem IConfigurationId) IConfigurationId {
					var sc IServerConfiguration
					var ok bool
					if sc, ok = elem.(IServerConfiguration); !ok {
						return nil
					}

					var s *server
					if current != nil {
						s, _ = current.(*server)
					}
					if s == nil {
						s = &server{
							Server_: elem.Id(),
						}
					}
					s.ServerKeyID_ = sc.ServerKeyId()
					return s
				},
			},
		}
	}
	return j.servers
}

type serverCollectionWrapper struct {
	sliceCollectionWrapper
}

func (s *serverCollectionWrapper) Get(id string) (server IServerConfiguration) {
	var idConf = s.get(strings.ToLower(id))
	if idConf == nil {
		return nil
	}
	server, _ = idConf.(IServerConfiguration)
	return
}
func (s *serverCollectionWrapper) Put(elem IServerConfiguration) {
	s.put(elem)
}
func (s *serverCollectionWrapper) Delete(id string) {
	s.delete(strings.ToLower(id))
}
func (s *serverCollectionWrapper) List(cb func(IServerConfiguration) bool) {
	s.list(func(idc IConfigurationId) bool {
		return cb(idc.(IServerConfiguration))
	})
}

func (j *jsonConfigurationStorage) Devices() IDeviceCollection {
	if j.devices == nil {
		j.devices = &deviceCollectionWrapper{
			sliceCollectionWrapper{
				onGet: func() []IConfigurationId {
					elems := j.getConfiguration().Devices_
					s := make([]IConfigurationId, len(elems))
					for i, e := range elems {
						s[i] = e
					}
					return s
				},
				onSet: func(elems []IConfigurationId) {
					s := make([]*device, 0, len(elems))
					for i := 0; i < len(elems); i++ {
						if u, ok := elems[i].(*device); ok {
							s = append(s, u)
						}
					}
					j.getConfiguration().Devices_ = s
				},
				onModified: j.modified,
				onClone: func(current IConfigurationId, elem IConfigurationId) IConfigurationId {
					var dc IDeviceConfiguration
					var ok bool
					if dc, ok = elem.(IDeviceConfiguration); !ok {
						return nil
					}

					var d *device
					if current != nil {
						d, _ = current.(*device)
					}
					if d == nil {
						d = &device{
							DeviceToken_: elem.Id(),
						}
					}
					d.PrivateKey_ = Base64UrlEncode(dc.DeviceKey())
					si := dc.ServerInfo()
					d.ServerInfo_ = nil
					if si != nil {
						si.List(func(ss IDeviceServerConfiguration) bool {
							d.ServerInfo().Put(ss)
							return true
						})
					}
					return d
				},
			},
		}
	}
	return j.devices
}

type deviceCollectionWrapper struct {
	sliceCollectionWrapper
}

func (d *deviceCollectionWrapper) Get(id string) (device IDeviceConfiguration) {
	var idConf = d.get(id)
	if idConf == nil {
		return nil
	}
	device, _ = idConf.(IDeviceConfiguration)
	return
}
func (d *deviceCollectionWrapper) Put(elem IDeviceConfiguration) {
	d.put(elem)
}
func (d *deviceCollectionWrapper) Delete(id string) {
	d.delete(id)
}
func (d *deviceCollectionWrapper) List(cb func(IDeviceConfiguration) bool) {
	d.list(func(idc IConfigurationId) bool {
		return cb(idc.(IDeviceConfiguration))
	})
}

type deviceServerCollectionWrapper struct {
	sliceCollectionWrapper
}

func (ds *deviceServerCollectionWrapper) Get(id string) IDeviceServerConfiguration {
	return ds.get(strings.ToLower(id)).(IDeviceServerConfiguration)
}
func (ds *deviceServerCollectionWrapper) Put(elem IDeviceServerConfiguration) {
	ds.put(elem)
}
func (ds *deviceServerCollectionWrapper) Delete(id string) {
	ds.delete(strings.ToLower(id))
}
func (u *deviceServerCollectionWrapper) List(cb func(IDeviceServerConfiguration) bool) {
	u.list(func(idc IConfigurationId) bool {
		return cb(idc.(IDeviceServerConfiguration))
	})
}

func (d *device) ServerInfo() IDeviceServerCollection {
	if d.serverInfo == nil {
		d.serverInfo = &deviceServerCollectionWrapper{
			sliceCollectionWrapper{
				onGet: func() []IConfigurationId {
					elems := d.ServerInfo_
					s := make([]IConfigurationId, len(elems))
					for i, e := range elems {
						s[i] = e
					}
					return s
				},
				onSet: func(elems []IConfigurationId) {
					s := make([]*deviceServer, 0, len(elems))
					for i := 0; i < len(elems); i++ {
						if u, ok := elems[i].(*deviceServer); ok {
							s = append(s, u)
						}
					}
					d.ServerInfo_ = s
				},
				onModified: nil,
				onClone: func(current IConfigurationId, elem IConfigurationId) IConfigurationId {
					var dsc IDeviceServerConfiguration
					var ok bool
					if dsc, ok = elem.(IDeviceServerConfiguration); !ok {
						return nil
					}

					var ds *deviceServer
					if current != nil {
						ds, _ = current.(*deviceServer)
					}
					if ds == nil {
						ds = &deviceServer{
							Server_: elem.Id(),
						}
					}
					ds.CloneCode_ = dsc.CloneCode()
					return ds
				},
			},
		}
	}

	return d.serverInfo
}

type sliceCollectionWrapper struct {
	onGet      func() []IConfigurationId
	onSet      func([]IConfigurationId)
	onModified func()
	onClone    func(IConfigurationId, IConfigurationId) IConfigurationId
}

func (w *sliceCollectionWrapper) get(id string) IConfigurationId {
	slice := w.onGet()
	for _, e := range slice {
		if e.Id() == id {
			return e
		}
	}
	return nil
}

func (w *sliceCollectionWrapper) put(elem IConfigurationId) {
	id := elem.Id()
	slice := w.onGet()
	var added bool = false
	for i, e := range slice {
		if iid, ok := e.(IConfigurationId); ok {
			if iid.Id() == id {
				slice[i] = w.onClone(iid, elem)
				added = true
				break
			}
		}
	}
	if !added {
		slice = append(slice, w.onClone(nil, elem))
	}
	w.onSet(slice)
	if w.onModified != nil {
		w.onModified()
	}
}

func (w *sliceCollectionWrapper) delete(id string) {
	slice := w.onGet()
	var length int = len(slice)
	for i, e := range slice {
		if iid, ok := e.(IConfigurationId); ok {
			if iid.Id() == id {
				if i+1 < length {
					slice[i] = slice[length-1]
				}
				slice = slice[0 : length-1]
			}
		}
	}
	if len(slice) < length {
		w.onSet(slice)
		if w.onModified != nil {
			w.onModified()
		}
	}
}

func (w *sliceCollectionWrapper) list(cb func(IConfigurationId) bool) {
	slice := w.onGet()
	for _, e := range slice {
		if iid, ok := e.(IConfigurationId); ok {
			if !cb(iid) {
				return
			}
		}
	}
}
