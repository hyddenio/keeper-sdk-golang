package sqldb

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/golang/glog"
	"keepersecurity.com/sdk"
	"reflect"
	"strings"
)

type sqlSettings struct {
	Environment_  string               `sdk:"environment,master"`
	LastUsername_ sql.NullString       `sdk:"last_login,64"`
	LastServer_   sql.NullString       `sdk:"last_server,64"`
	Users_        []*sqlSettingsUser   `sdk:"users"`
	Servers_      []*sqlSettingsServer `sdk:"servers"`
}
func (s *sqlSettings) LastUsername() (user string) {
	if s.LastUsername_.Valid {
		user = s.LastUsername_.String
	}
	return
}
func (s *sqlSettings) LastServer() (server string) {
	if s.LastServer_.Valid {
		server = s.LastServer_.String
	}
	return
}
func (s *sqlSettings) Users(callback func (sdk.IUserSettings) bool) {
	for _, u := range s.Users_ {
		if !callback(u) {
			break
		}
	}
}
func (s *sqlSettings) Servers(callback func (sdk.IServerSettings) bool) {
	for _, s := range s.Servers_ {
		if !callback(s) {
			break
		}
	}
}

func (s *sqlSettings) Initialize(settings sdk.ISettings) {
	s.LastUsername_ = sql.NullString{String: settings.LastUsername(), Valid:true}
	s.LastServer_ = sql.NullString{String: settings.LastServer(), Valid:true}
	s.Users_ = make([]*sqlSettingsUser, 0)
	settings.Users(func (uu sdk.IUserSettings) bool {
		var user = new(sqlSettingsUser)
		user.Initialize(uu)
		s.Users_ = append(s.Users_, user)
		return true
	})
	s.Servers_ = make([]*sqlSettingsServer, 0)
	settings.Servers(func (ss sdk.IServerSettings) bool {
		var server = new(sqlSettingsServer)
		server.Initialize(ss)
		s.Servers_ = append(s.Servers_, server)
		return true
	})
}
func (s *sqlSettings) Init(source interface{}) (err error) {
	if settings, ok := source.(sdk.ISettings); ok {
		s.Initialize(settings)
	} else {
		err = errors.New(fmt.Sprintf("type %s does not implement ISettings", reflect.TypeOf(source).Name()))
	}
	return
}

type sqlSettingsUser struct {
	Environment_    string         `sdk:"environment,master"`
	Username_       string         `sdk:"username,detail"`
	Password_       sql.NullString `sdk:"password,64,read-only"`
	TwoFactorToken_ sql.NullString `sdk:"two_factor_token,64"`
}
func (u *sqlSettingsUser) Uid() string {
	return u.Environment_
}
func (u *sqlSettingsUser) Username() string {
	return u.Username_
}
func (u *sqlSettingsUser) Password() (password string) {
	if u.Password_.Valid {
		password = u.Password_.String
	}
	return
}
func (u *sqlSettingsUser) TwoFactorToken() (token string) {
	if u.TwoFactorToken_.Valid {
		token = u.TwoFactorToken_.String
	}
	return
}
func (u *sqlSettingsUser) Initialize(userSettings sdk.IUserSettings) {
	u.Username_ = userSettings.Username()
	u.Password_ = sql.NullString{String: userSettings.Password(), Valid: true}
	u.TwoFactorToken_ = sql.NullString{String: userSettings.TwoFactorToken(), Valid: true}
}

type sqlSettingsServer struct {
	Environment_ string        `sdk:"environment,master"`
	Server_      string        `sdk:"server,detail"`
	DeviceToken_ []byte        `sdk:"device_token,128"`
	ServerKeyId_ sql.NullInt32 `sdk:"server_key_id"`
}
func (s *sqlSettingsServer) Server() string {
	return s.Server_
}
func (s *sqlSettingsServer) DeviceId() []byte {
	return s.DeviceToken_
}
func (s *sqlSettingsServer) ServerKeyId() (keyId int32) {
	if s.ServerKeyId_.Valid {
		keyId = s.ServerKeyId_.Int32
	}
	return
}
func (s *sqlSettingsServer) Initialize(serverSettings sdk.IServerSettings) {
	s.Server_ = serverSettings.Server()
	s.DeviceToken_ = serverSettings.DeviceId()
	s.ServerKeyId_ = sql.NullInt32{Int32: serverSettings.ServerKeyId(), Valid: true}
}

type sqlSettingsStorage struct {
	KeyValueStorage
	environment string
}

func (sss *sqlSettingsStorage) GetSettings() (settings sdk.ISettings) {
	var err error
	var value interface{}
	if value, err = sss.Get(sss.environment); err == nil && value != nil {
		var ok bool
		if settings, ok = value.(sdk.ISettings); !ok {
			var vType = reflect.TypeOf(value)
			if vType.Kind() == reflect.Ptr {
				vType = vType.Elem()
			}
			err = errors.New(fmt.Sprintf("type %s does not implement interface ISettings", vType.Name()))
		}
	}
	if err != nil {
		glog.Warning("SQL settings: GET: ", err)
	}
	if settings == nil {
		settings = sdk.NewSettings(nil)
	}
	return
}
func (sss *sqlSettingsStorage) PutSettings(settings sdk.ISettings) {
	var err = sss.Put(sss.environment, settings)
	if err != nil {
		glog.Warning("SQL settings: PUT: ", err)
	}
}

func NewSqlSettingsStorage (db Database) (settingsStorage sdk.ISettingsStorage, err error) {
	return NewSqlSettingsStorageForEnvironment(db, "PROD")
}
func NewSqlSettingsStorageForEnvironment (db Database, environment string) (settingsStorage sdk.ISettingsStorage, err error) {
	var keyStorage KeyValueStorage
	if keyStorage, err = NewKeyValueStorage(db, reflect.TypeOf((*sqlSettings)(nil)), "settings"); err == nil {
		settingsStorage = &sqlSettingsStorage{
			KeyValueStorage: keyStorage,
			environment:     strings.ToUpper(environment),
		}
	}
	return
}