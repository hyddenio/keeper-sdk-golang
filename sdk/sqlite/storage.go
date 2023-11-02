package sqlite

import (
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/keeper-security/keeper-sdk-golang/sdk/api"
	"github.com/keeper-security/keeper-sdk-golang/sdk/storage"
)

type Key interface {
	string | int64 | []byte
}

type sqliteEntityStorage[T storage.IUid] struct {
	*sqliteStorage[T]
}

func NewSqliteEntityStorage[T storage.IUid](
	getConnection func() *sqlx.DB, schema ITableSchema, ownerValue interface{}) (sto storage.IEntityStorage[T], err error) {
	if len(schema.PrimaryKey()) != 1 {
		err = api.NewKeeperError(fmt.Sprintf(
			"SqliteEntityStorage (%s): Primary key to have one column.", schema.TableName()))
	}
	sto = &sqliteEntityStorage[T]{
		&sqliteStorage[T]{
			getConnection: getConnection,
			schema:        schema,
			ownerValue:    ownerValue,
		},
	}
	return
}
func (ses *sqliteEntityStorage[T]) GetEntity(uid string) (entity T, err error) {
	var returned = false
	err = ses.sqliteStorage.SelectFilter(ses.schema.PrimaryKey(), [][]interface{}{{uid}}, func(T) bool {
		if returned {
			err = api.NewKeeperError(fmt.Sprintf("Get Entity: more than a one record for UID %v", uid))
		} else {
			returned = true
		}
		return true
	})
	return
}

func (ses *sqliteEntityStorage[T]) GetAll(cb func(T) bool) (err error) {
	var entity T
	err = ses.sqliteStorage.SelectAll(func(e T) bool {
		if !cb(entity) {
			return false
		}
		return true
	})
	return
}

func (ses *sqliteEntityStorage[T]) PutEntities(entities []T) (err error) {
	return ses.Put(entities)
}

func (ses *sqliteEntityStorage[T]) DeleteUids(uids []string) error {
	var values = make([][]interface{}, len(uids))
	for i, e := range uids {
		values[i] = []interface{}{e}
	}
	return ses.DeleteFilter(ses.schema.PrimaryKey(), values)
}

type sqliteLinkStorage[T storage.IUidLink] struct {
	*sqliteStorage[T]
}

func NewSqliteLinkStorage[KS Key, KO Key, T storage.IUidLink](
	getConnection func() *sqlx.DB, schema ITableSchema,
	ownerValue interface{}) (sto storage.ILinkStorage[T], err error) {
	if len(schema.PrimaryKey()) != 2 {
		err = api.NewKeeperError(fmt.Sprintf(
			"SqliteLinkStorage (%s): Primary key to have two columns.", schema.TableName()))
	}
	var objectColumn = schema.PrimaryKey()[1]
	var objectIndexName string
	if schema.Indexes() != nil {
		for k, v := range schema.Indexes() {
			if v[0] == objectColumn {
				objectIndexName = k
				break
			}
		}
	}
	if len(objectIndexName) == 0 {
		err = api.NewKeeperError(fmt.Sprintf(
			"SqliteLinkStorage: ObjectUID column \"%s\"is not indexed in the table \"%s\".",
			objectColumn, schema.TableName()))
	}

	sto = &sqliteLinkStorage[T]{
		&sqliteStorage[T]{
			getConnection: getConnection,
			schema:        schema,
			ownerValue:    ownerValue,
		},
	}
	return
}

func (sls *sqliteLinkStorage[T]) PutLinks(links []T) (err error) {
	return sls.Put(links)
}
func (sls *sqliteLinkStorage[T]) DeleteLinks(links []storage.IUidLink) (err error) {
	var values = make([][]interface{}, len(links))
	for i, e := range links {
		values[i] = []interface{}{e.SubjectUid(), e.ObjectUid()}
	}
	return sls.DeleteFilter(sls.schema.PrimaryKey(), values)
}
func (sls *sqliteLinkStorage[T]) DeleteLinksForObjects(objects []string) (err error) {
	var values = make([][]interface{}, len(objects))
	for i, e := range objects {
		values[i] = []interface{}{e}
	}
	return sls.DeleteFilter([]string{sls.schema.PrimaryKey()[1]}, values)
}
func (sls *sqliteLinkStorage[T]) DeleteLinksForSubjects(subjects []string) (err error) {
	var values = make([][]interface{}, len(subjects))
	for i, e := range subjects {
		values[i] = []interface{}{e}
	}
	return sls.DeleteFilter([]string{sls.schema.PrimaryKey()[0]}, values)
}
func (sls *sqliteLinkStorage[T]) GetLinksForObjects(objects []string, cb func(link T) bool) (err error) {
	var values = make([][]interface{}, len(objects))
	for i, e := range objects {
		values[i] = []interface{}{e}
	}
	return sls.SelectFilter([]string{sls.schema.PrimaryKey()[1]}, values, cb)
}
func (sls *sqliteLinkStorage[T]) GetLinksForSubjects(subjects []string, cb func(T) bool) (err error) {
	var values = make([][]interface{}, len(subjects))
	for i, e := range subjects {
		values[i] = []interface{}{e}
	}
	return sls.SelectFilter([]string{sls.schema.PrimaryKey()[0]}, values, cb)
}
func (sls *sqliteLinkStorage[T]) GetAll(cb func(T) bool) (err error) {
	return sls.SelectAll(cb)
}
