package enterprise

import (
	"errors"
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/sdk/sqlite"
	"github.com/keeper-security/keeper-sdk-golang/sdk/storage"
	"reflect"
)

type EnterpriseSettings struct {
	ContinuationToken []byte `db:"continuation_token"`
}

type EnterpriseEntityData struct {
	Type int64  `db:"type"`
	Key  string `db:"key"`
	Data []byte `db:"data"`
}

func NewSqliteEnterpriseStorage(getConnection func() *sqlx.DB, enterpriseId int64) (storage IEnterpriseStorage, err error) {
	var db = getConnection()

	const ownerColumnName = "enterprise_id"
	var settingsType = reflect.TypeOf((*EnterpriseSettings)(nil))
	var settingsSchema sqlite.ITableSchema
	settingsSchema, err = sqlite.LoadTableSchema(settingsType, nil, nil, ownerColumnName, sqlite.SqlDataType_Integer)
	if err != nil {
		return
	}

	var dataType = reflect.TypeOf((*EnterpriseEntityData)(nil))
	var dataSchema sqlite.ITableSchema
	var indexes = make(map[string][]string)
	indexes["ObjectKey"] = []string{"key"}
	dataSchema, err = sqlite.LoadTableSchema(dataType, []string{"type", "key"}, indexes, ownerColumnName, sqlite.SqlDataType_Integer)
	if err != nil {
		return
	}

	var queries []string
	if queries, err = sqlite.VerifyDatabase(db, []sqlite.ITableSchema{settingsSchema, dataSchema}, true); err != nil {
		return
	}
	if len(queries) > 0 {
		err = errors.New("failed to modify database schema")
		return
	}

	var es = &enterpriseStorage{}
	es.settingStorage, err = sqlite.NewSqliteRecordStorage[*EnterpriseSettings](getConnection, settingsSchema, enterpriseId)
	if err != nil {
		return
	}
	es.dataStorage, err = sqlite.NewSqliteLinkStorage[*EnterpriseEntityData, int64, string](getConnection, dataSchema, enterpriseId)
	if err != nil {
		return
	}
	storage = es
	return
}

type enterpriseStorage struct {
	settingStorage storage.IRecordStorage[*EnterpriseSettings]
	dataStorage    storage.ILinkStorage[*EnterpriseEntityData, int64, string]
	putCache       []*EnterpriseEntityData
	deleteCache    []storage.IUidLink[int64, string]
}

func (es *enterpriseStorage) ContinuationToken() (token []byte, err error) {
	var settings *EnterpriseSettings
	if settings, err = es.settingStorage.Load(); err == nil {
		if settings != nil {
			token = settings.ContinuationToken
		}
	}
	return
}

func (es *enterpriseStorage) SetContinuationToken(token []byte) (err error) {
	var settings *EnterpriseSettings
	if settings, err = es.settingStorage.Load(); err == nil {
		if settings == nil {
			settings = &EnterpriseSettings{}
		}
		settings.ContinuationToken = token
		err = es.settingStorage.Store(settings)
	}
	return
}

func (es *enterpriseStorage) GetEntities(cb func(int32, []byte) bool) (err error) {
	err = es.dataStorage.GetAll(func(data *EnterpriseEntityData) bool {
		return cb(int32(data.Type), data.Data)
	})
	return
}

func (es *enterpriseStorage) Flush() (err error) {
	if len(es.deleteCache) > 0 {
		err = es.dataStorage.DeleteLinks(es.deleteCache)
		es.deleteCache = nil
	}
	if len(es.putCache) > 0 {
		err = es.dataStorage.PutLinks(es.putCache)
		es.putCache = nil
	}
	return
}

func (es *enterpriseStorage) PutEntity(dataType int32, dataKey string, data []byte) (err error) {
	es.putCache = append(es.putCache, &EnterpriseEntityData{
		Type: int64(dataType),
		Key:  dataKey,
		Data: data,
	})
	if len(es.putCache) >= 1000 {
		err = es.Flush()
	}
	return
}

func (es *enterpriseStorage) DeleteEntity(dataType int32, dataKey string) (err error) {
	es.deleteCache = append(es.deleteCache, storage.NewUidLink(int64(dataType), dataKey))
	if len(es.deleteCache) >= 1000 {
		err = es.Flush()
	}
	return
}

func (es *enterpriseStorage) Clear() {
	_ = es.settingStorage.Delete()
	_ = es.dataStorage.Clear()
}
